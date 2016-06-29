---------------------------------
--- @file synCookie.lua
--- @brief TCP SYN cookie implementation.
--- Includes:
--- - calculate and verify a cookie
--- - functions to build and verify each part of the cookie
---------------------------------

local ffi		= require "ffi"
local log		= require "log"
local memory	= require "memory"
local proto		= require "proto/proto"
local hashMap	= require "hashMap"
local dpdk		= require "dpdk" -- for getTime
require "utils"

local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift
local time = time

---------------------------------------------------
-- Terminology
---------------------------------------------------

-- left: outside, internet, clients, potential attackers, whatever
-- right: "protected" side, connection to server(s), only filtered traffic comes here

local mod = {}

mod.LEFT_TO_RIGHT = true
mod.RIGHT_TO_LEFT = false


-------------------------------------------------------------------------------------------
---- Timestamp
-------------------------------------------------------------------------------------------

-- one cycle is 64 seconds (6 bit right shift of timestamp)
local timestampValidCycles = 2

local function getTimestamp()
	local t = dpdk.getTime()
	--log:debug('Time: ' .. t .. ' ' .. toBinary(t))
	-- 64 seconds resolution
	t = rshift(t, 6)
	--log:debug('Time: ' .. t .. ' ' .. toBinary(t))
	-- 5 bits
	t = t % 32
	--log:debug('Time: ' .. t .. ' ' .. toBinary(t))
	return t
end

local function verifyTimestamp(t)
	return t + timestampValidCycles >= getTimestamp()
end


-------------------------------------------------------------------------------------------
---- Option extracting
-------------------------------------------------------------------------------------------

local function extractOptions(pkt)
	-- get MSS and WSOPT options
	local offset = pkt.tcp:getDataOffset() - 5 -- options length in 32 bits (deduct 5 for standard tcp header length)
	local mss = nil
	local upper = 0
	--local upper2 = 0
	local lower = 0
	--local lower2 = 0

	local wsopt = nil
	local sack = false
	--local tsval = false
	local opt = 0
	local i = 0
	while i < offset * 4 do
		opt = pkt.payload.uint8[i]
		if opt == 2 then -- MSS option type
			-- alignment is not guaranteed, build uint16 from uint8s
			upper = pkt.payload.uint8[i + 2]
			lower = pkt.payload.uint8[i + 3]
			mss = lshift(upper, 8) + lower
			i = i + 4
		elseif opt == 3 then
			wsopt = pkt.payload.uint8[i + 2]
			i = i + 3
		elseif opt == 4 then
			sack = true
			i = i + 2
		--elseif opt == 8 then
			--upper = pkt.payload.uint8[i + 2]
			--upper2 = pkt.payload.uint8[i + 3]
			--lower = pkt.payload.uint8[i + 4]
			--upper2 = pkt.payload.uint8[i + 5]
			--tsval = lshift(upper, 48) + lshift(upper2, 32) + lshift(lower, 16) + lower2 
			--
			--upper = pkt.payload.uint8[i + 6]
			--upper2 = pkt.payload.uint8[i + 7]
			--lower = pkt.payload.uint8[i + 8]
			--upper2 = pkt.payload.uint8[i + 9]
			--ecr = lshift(upper, 48) + lshift(upper2, 32) + lshift(lower, 16) + lower2 
		--	tsval = true
		--	i = i + 10
		elseif opt == 0 then
			-- signals end
			break
		elseif opt == 1 then
			-- nop padding
			i = i + 1
		else
			-- other options
			i = i + pkt.payload.uint8[i + 1] -- increment by option length
		end
	end
	return mss, wsopt, sack
end

-------------------------------------------------------------------------------------------
---- TCP Options
-------------------------------------------------------------------------------------------

-- MSS encodings
local MSS = { }
MSS[1] = 1460
MSS[2] = 1360
MSS[3] = 1260
MSS[4] = 1160
MSS[5] = 960
MSS[6] = 760
MSS[7] = 536
MSS[8] = nil -- not set

-- always round down to next MSS value
local function encodeMss(mss)
	-- 3 bits, allows for 8 different MSS
	if not mss then
		return 7 -- not set
	end
	for i = 1, 7 do
		if mss >= MSS[i] then
			return i - 1 -- convert to 0-7
		end
	end
	return 6 -- below minimum (weird, but set minimum?!)
end

local function decodeMss(idx)
	return MSS[idx + 1] or 536
end

-- we can encode values 0 - 14 (everything above is 14)
-- value 15 means no option set
local function encodeWsopt(wsopt)
	if not wsopt then
		return 15
	end
	if wsopt > 14 then
		return 14
	end
	return wsopt
end

local function decodeWsopt(wsopt)
	if wsopt == 15 then
		return nil
	end
	return wsopt
end

-------------------------------------------------------------------------------------------
---- Hash
-------------------------------------------------------------------------------------------

local function hash(int)
	-- TODO implement something with real crypto later on
	return int
end

local function getHash(ipSrc, ipDst, portSrc, portDst, ts)
	local sum = 0
	sum = sum + ipSrc + ipDst + portSrc + portDst + ts
	return band(hash(sum), 0x000fffff) -- 20 bits
end

local function verifyHash(oldHash, ipSrc, ipDst, portSrc, portDst, ts)
	local newHash = getHash(ipSrc, ipDst, portSrc, portDst, ts)
	-- log:debug('Old hash:       ' .. toBinary(oldHash))
	-- log:debug('New hash:       ' .. toBinary(newHash))
	return oldHash == newHash
end


-------------------------------------------------------------------------------------------
---- Cookie crafting
-------------------------------------------------------------------------------------------

local function calculateCookie(pkt)
	--------------------------------------
	---- LAYOUT Original
	---- ts 5 - mss 3 - hash 24
	---- LAYOUT with wsopt
	---- ts 5 - mss 3 - wsopt 4 - hash 20
	--------------------------------------

	local tsOrig = getTimestamp()
	--log:debug('Time: ' .. ts .. ' ' .. toBinary(ts))
	local ts = lshift(tsOrig, 27)
	--log:debug('Time: ' .. ts .. ' ' .. toBinary(ts))

	-- extra options we support
	local mss, wsopt, sack = extractOptions(pkt)
	mss = encodeMss(mss)
	mss = lshift(mss, 24)

	wsopt = encodeWsopt(wsopt)
	wsopt = lshift(wsopt, 20)
	
	-- TODO encode sack 1 bit, tsval can be checked at ack again

	-- hash
	local hash = getHash(
		pkt.ip4:getSrc(), 
		pkt.ip4:getDst(), 
		pkt.tcp:getSrc(),
		pkt.tcp:getDst(),
		tsOrig
	)
	--log:debug('Created TS:     ' .. toBinary(ts))
	--log:debug('Created MSS:    ' .. toBinary(mss))
	--log:debug('Created WSOPT:  ' .. toBinary(wsopt))
	--log:debug('Created hash:   ' .. toBinary(hash))
	local cookie = ts + mss + wsopt + hash
	--log:debug('Created cookie: ' .. toBinary(cookie))
	return cookie, tsval, ecr
end

function mod.verifyCookie(pkt)
	local cookie = pkt.tcp:getAckNumber()
	--log:debug('Got ACK:        ' .. toBinary(cookie))
	cookie = cookie - 1
	--log:debug('Cookie:         ' .. toBinary(cookie))

	-- check timestamp first
	local ts = rshift(cookie, 27)
	--log:debug('TS:           ' .. toBinary(ts))
	if not verifyTimestamp(ts) then
		log:warn('Received cookie with invalid timestamp')
		return false
	end

	-- check hash
	local hash = band(cookie, 0x000fffff)
	-- log:debug('Hash:           ' .. toBinary(hash))
	if not verifyHash(
			hash, 
			pkt.ip4:getSrc(), 
			pkt.ip4:getDst(), 
			pkt.tcp:getSrc(), 
			pkt.tcp:getDst(), 
			ts
	) then
		log:warn('Received cookie with invalid hash')
		return false
	else
		-- finally decode options and return it
		--log:debug('Received legitimate cookie')
		local mss = decodeMss(band(rshift(cookie, 24), 0x7))
		local wsopt = decodeWsopt(band(rshift(cookie, 20), 0xf))
		--log:debug('wsopt:          ' .. toBinary(wsopt))
		--log:debug("dec " .. wsopt)
		return mss, wsopt
	end
end


-------------------------------------------------------------------------------------------
---- Packet modification and crafting for cookie strategy
-------------------------------------------------------------------------------------------

-- simply resend the complete packet, but adapt seq/ack number
function mod.sequenceNumberTranslation(diff, rxBuf, txBuf, rxPkt, txPkt, leftToRight)
	--log:debug('Performing Sequence Number Translation ' .. (leftToRight and 'from left ' or 'from right '))
	
	local size = rxBuf:getSize() 	
	
	-- copy content
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	txBuf:setSize(size)

	-- translate numbers, depends on direction
	if leftToRight then
		txPkt.tcp:setAckNumber(rxPkt.tcp:getAckNumber() + diff)
	else
		txPkt.tcp:setSeqNumber(rxPkt.tcp:getSeqNumber() - diff)
	end

	
	-- calculate TCP checksum
	-- IP header does not change, hence, do not recalculate IP checksum
	--if leftToRight then
		--log:debug('Calc checksum ' .. (leftToRight and 'from left ' or 'from right '))
		txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	--end
end

function mod.createSynToServer(txBuf, rxBuf, mss, wsopt)
	-- set size of tx packet
	local size = 54 --rxBuf:getSize()
	
	-- copy data
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	
	-- adjust some members: sequency number, flags, checksum, length fields
	local txPkt = txBuf:getTcp4Packet()
	-- reduce seq num by 1 as during handshake it will be increased by 1 (in SYN/ACK)
	-- this way, it does not have to be translated at all
	txPkt.tcp:setSeqNumber(txPkt.tcp:getSeqNumber() - 1)
	txPkt.tcp:setWindow(29200)
	txPkt.tcp:setFlags(0)
	txPkt.tcp:setSyn()


	-- MSS option
	local offset = 0
	if mss then
		txPkt.payload.uint8[0] = 2 -- MSS option type
		txPkt.payload.uint8[1] = 4 -- MSS option length (4 bytes)
		txPkt.payload.uint16[1] = hton16(mss) -- MSS option
		offset = offset + 4
	end
	-- window scale option
	if wsopt then
		txPkt.payload.uint8[offset] = 3 -- WSOPT option type
		txPkt.payload.uint8[offset + 1] = 3 -- WSOPT option length (3 bytes)
		txPkt.payload.uint8[offset + 2] = wsopt -- WSOPT option
		offset = offset + 3
	end
	
	if false then -- sack then
		txPkt.payload.uint8[offset] = 4 -- sack option type
		txPkt.payload.uint8[offset + 1] = 2 -- sack option length (2 bytes)
		offset = offset + 2
	end

	if true then -- ts then
		txPkt.payload.uint8[offset] = 8 -- ts option type
		txPkt.payload.uint8[offset + 1] = 10 -- ts option length (2 bytes)
		txPkt.payload.uint8[offset + 2] = 0 -- ts option tsval
		txPkt.payload.uint8[offset + 3] = 0 -- ts option tsval
		txPkt.payload.uint8[offset + 4] = 0 -- ts option tsval
		txPkt.payload.uint8[offset + 5] = 0 -- ts option tsval
		txPkt.payload.uint8[offset + 6] = 0 -- ts option ecr
		txPkt.payload.uint8[offset + 7] = 0 -- ts option ecr
		txPkt.payload.uint8[offset + 8] = 0 -- ts option ecr
		txPkt.payload.uint8[offset + 9] = 0 -- ts option ecr
		offset = offset + 10
	end

	local pad = 4 - (offset % 4)
	if pad > 0 then
		txPkt.payload.uint8[offset + pad - 1] = 0 -- eop
		for i = pad - 2, 0, -1 do
			txPkt.payload.uint8[offset + i] = 1 -- padding
		end
	end
	offset = offset + pad
	size = size + offset
	local dataOffset = 5 + (offset / 4)

	txPkt.tcp:setDataOffset(dataOffset)
	txPkt:setLength(size)
	if size < 60 then
		size = 60
	end
	txBuf:setSize(size)

	-- calculate checksums
	txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	txPkt.ip4:calculateChecksum()
end

function mod.createAckToServer(txBuf, rxBuf, rxPkt)
	-- set size of tx packet
	local size = 60 --rxBuf:getSize()
	txBuf:setSize(size)
	
	-- copy data TODO directly use rx buffer
	--log:debug('copy data')
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	
	-- send packet back with seq, ack + 1
	local txPkt = txBuf:getTcp4Packet()

	-- mac addresses (FIXME does not work with KNI)
	-- I can put any addresses in here (NULL, BROADCASTR, ...), 
	-- but as soon as I use the right ones it doesn't work any longer
	--local tmp = rxPkt.eth:getSrc()
	--txPkt.eth:setSrc(rxPkt.eth:getDst())
	--txPkt.eth:setDst(tmp)

	
	-- ip addresses
	local tmp = rxPkt.ip4:getSrc()
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	txPkt.ip4:setDst(tmp)

	-- tcp ports
	tmp = rxPkt.tcp:getSrc()
	txPkt.tcp:setSrc(rxPkt.tcp:getDst())
	txPkt.tcp:setDst(tmp)

	txPkt.tcp:setSeqNumber(rxPkt.tcp:getAckNumber())
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)
	txPkt.tcp:unsetSyn()
	txPkt.tcp:setAck()
	txPkt.tcp:setDataOffset(5)
	txPkt.tcp:setWindow(229)
	txPkt.payload.uint32[0] = 0
	txPkt.payload.uint16[2] = 0
	
	txPkt:setLength(54)

	-- calculate checksums
	txPkt.ip4:calculateChecksum()
	txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
end

function mod.createSynAckToClient(txBuf, rxPkt)
	local txPkt = txBuf:getTcp4Packet()
	local cookie, tsval, ecr = calculateCookie(rxPkt)

	-- TODO set directly without set/get, should be a bit faster
	-- MAC addresses
	txPkt.eth:setDst(rxPkt.eth:getSrc())
	txPkt.eth:setSrc(rxPkt.eth:getDst())

	-- IP addresses
	txPkt.ip4:setDst(rxPkt.ip4:getSrc())
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	
	-- TCP
	txPkt.tcp.src = rxPkt.tcp.dst
	txPkt.tcp.dst = rxPkt.tcp.src
	
	txPkt.tcp:setSeqNumber(cookie)
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)

	txBuf:setSize(txPkt.ip4:getLength() + 14)
end


-------------------------------------------------------------------------------------------
---- Packet mempools and buf arrays
-------------------------------------------------------------------------------------------

-- TODO config options
local SERVER_MSS = 1460
local SERVER_WSOPT = 7

function mod.getSynAckBufs()
	local lTXSynAckMem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet()
		pkt:fill{
			ethSrc="90:e2:ba:98:88:e9",
			ethDst="90:e2:ba:98:58:79",
			ip4Src="192.168.1.1",
			ip4Dst="192.168.1.201",
			ip4Flags=2, -- set DF
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpAck=1,
			tcpSyn=1,
			tcpWindow=29200,
		}
	
		-- MSS option
		local offset = 0
		if true then --mss then
			pkt.payload.uint8[0] = 2 -- MSS option type
			pkt.payload.uint8[1] = 4 -- MSS option length (4 bytes)
			pkt.payload.uint16[1] = hton16(SERVER_MSS) -- MSS option
			offset = offset + 4
		end
		-- window scale option
		if true then --wsopt then
			pkt.payload.uint8[offset] = 3 -- WSOPT option type
			pkt.payload.uint8[offset + 1] = 3 -- WSOPT option length (3 bytes)
			pkt.payload.uint8[offset + 2] = SERVER_WSOPT -- WSOPT option
			offset = offset + 3
		end
		
		if false then -- sack then
			pkt.payload.uint8[offset] = 4 -- sack option type
			pkt.payload.uint8[offset + 1] = 2 -- sack option length (2 bytes)
			offset = offset + 2
		end
	
		if true then -- ts option
			pkt.payload.uint8[offset] = 8 -- ts option type
			pkt.payload.uint8[offset + 1] = 10 -- ts option length (2 bytes)
			pkt.payload.uint8[offset + 2] = 0 -- ts option tsval
			pkt.payload.uint8[offset + 3] = 0 -- ts option tsval
			pkt.payload.uint8[offset + 4] = 0 -- ts option tsval
			pkt.payload.uint8[offset + 5] = 0 -- ts option tsval
			pkt.payload.uint8[offset + 6] = 0--band(rshift(tsval, 48), 0xff) -- ts option ecr
			pkt.payload.uint8[offset + 7] = 0--band(rshift(tsval, 32), 0xff) -- ts option ecr
			pkt.payload.uint8[offset + 8] = 0--band(rshift(tsval, 16), 0xff) -- ts option ecr
			pkt.payload.uint8[offset + 9] = 0--band(		  tsval		, 0xff) -- ts option ecr
			offset = offset + 10
		end

		local pad = 4 - (offset % 4)
		if pad > 0 then
			pkt.payload.uint8[offset + pad - 1] = 0 -- eop
			for i = pad - 2, 0, -1 do
				pkt.payload.uint8[offset + i] = 1 -- padding
			end
		end
		offset = offset + pad
		local size = 54 + offset
		local dataOffset = 5 + (offset / 4)
	
		pkt.tcp:setDataOffset(dataOffset)
		pkt:setLength(size)
	end)
	return lTXSynAckMem:bufArray()
end
	
function mod.getForwardBufs()
	local lTXForwardMem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpSyn=1,
			pktLength=60,
		}
	end)
	return lTXForwardMem:bufArray()
end

return mod
