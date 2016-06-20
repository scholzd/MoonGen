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
--local ntoh16, hton16 = ntoh16, hton16
local time = time

---------------------------------------------------
-- Terminology
---------------------------------------------------

-- left: outside, internet, clients, potential attackers, whatever
-- right: "protected" side, connection to server(s), only filtered traffic comes here

local mod = {}

mod.LEFT_TO_RIGHT = true
mod.RIGHT_TO_LEFT = false

----------------------------------------------------
-- check packet type
----------------------------------------------------

local function isAck(pkt)
	return pkt.tcp:getAck() == 1
end

local function isRst(pkt)
	return pkt.tcp:getRst() == 1
end

local function isFin(pkt)
	return pkt.tcp:getFin() == 1
end


-------------------------------------------------------------------------------------------
---- Cookie
-------------------------------------------------------------------------------------------

-- one cycle is 64 seconds (6 bit right shift of timestamp)
local timestampValidCycles = 2

-- MSS encodings
local MSS = { 
	mss1=1460, 
	mss2=1000,
}


-------------------------------------------------------------------------------------------
---- Timestamp
-------------------------------------------------------------------------------------------

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
---- MSS
-------------------------------------------------------------------------------------------

local function encodeMss()
	-- 3 bits, allows for 8 different MSS
	mss = 1 -- encoding see MSS
	-- log:debug('MSS: ' .. mss .. ' ' .. toBinary(mss))
	return mss
end

local function decodeMss(idx)
	return MSS['mss' .. tostring(idx)] or -1
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
	return band(hash(sum), 0x00ffffff)
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
	local tsOrig = getTimestamp()
	--log:debug('Time: ' .. ts .. ' ' .. toBinary(ts))
	local ts = lshift(tsOrig, 27)
	--log:debug('Time: ' .. ts .. ' ' .. toBinary(ts))

	local mss = encodeMss()
	mss = lshift(mss, 24)

	local hash = getHash(
		pkt.ip4:getSrc(), 
		pkt.ip4:getDst(), 
		pkt.tcp:getSrc(),
		pkt.tcp:getDst(),
		tsOrig
	)
	--log:debug('Created TS:     ' .. toBinary(ts))
	--log:debug('Created MSS:    ' .. toBinary(mss))
	--log:debug('Created hash:   ' .. toBinary(hash))
	local cookie = ts + mss + hash
	--log:debug('Created cookie: ' .. toBinary(cookie))
	return cookie, mss
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
	local hash = band(cookie, 0x00ffffff)
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
		-- finally decode MSS and return it
		--log:debug('Received legitimate cookie')
		return decodeMss(band(rshift(cookie, 24), 0x3))
	end
end


---------------------------------------------------------------------------------------------
------ State keeping
---------------------------------------------------------------------------------------------
--
--
---- infringement things (TODO move at some point)
--function mod.isVerifiedReset(pkt)
--	local idx = getIdx(pkt, LEFT_TO_RIGHT)
--	if verifiedConnections[idx] then
--		return true
--	else
--		verifiedConnections[idx] = true
--		return false
--	end
--end
--
---- same as reset
--function mod.isVerifiedIgnore(pkt)
--	local idx = getIdx(pkt, LEFT_TO_RIGHT)
--	if verifiedConnections[idx] then
--		return true
--	else
--		verifiedConnections[idx] = true
--		return false
--	end
--end
--
--function mod.setVerifiedSequence(pkt)
--	local idx = getIdx(pkt, LEFT_TO_RIGHT)
--	verifiedConnections[idx] = true
--end
--
--function mod.isVerifiedSequence(pkt)
--	local idx = getIdx(pkt, LEFT_TO_RIGHT)
--	if verifiedConnections[idx] then
--		return true
--	else
--		return false
--	end
--end

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

function mod.createSynToServer(txBuf, rxBuf)
	-- set size of tx packet
	local size = rxBuf:getSize()
	txBuf:setSize(size)
	
	-- copy data
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	
	-- adjust some members: sequency number, flags, checksum, length fields
	local txPkt = txBuf:getTcp4Packet()
	-- reduce seq num by 1 as during handshake it will be increased by 1 (in SYN/ACK)
	-- this way, it does not have to be translated at all
	txPkt.tcp:setSeqNumber(txPkt.tcp:getSeqNumber() - 1)
	txPkt.tcp:setSyn()
	txPkt.tcp:unsetAck()

	txPkt:setLength(size)

	-- calculate checksums
	txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	txPkt.ip4:calculateChecksum()

end

function mod.createAckToServer(txBuf, rxBuf, rxPkt)
	-- set size of tx packet
	local size = rxBuf:getSize()
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
	
	txPkt:setLength(size)

	-- calculate checksums
	txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	txPkt.ip4:calculateChecksum()
end

function mod.createSynAckToClient(txPkt, rxPkt)
	local cookie, mss = calculateCookie(rxPkt)
	
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
	txPkt.tcp:setWindow(mss)
end


-------------------------------------------------------------------------------------------
---- Packet mempools and buf arrays
-------------------------------------------------------------------------------------------

function mod.getSynAckBufs()
	local lTXSynAckMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
			ethSrc="90:e2:ba:98:88:e9",
			ethDst="90:e2:ba:98:58:79",
			ip4Src="192.168.1.1",
			ip4Dst="192.168.1.201",
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpAck=1,
			tcpSyn=1,
			tcpWindow=50,
			pktLength=60,
		}
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
