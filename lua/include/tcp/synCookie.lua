---------------------------------
--- @file synCookie.lua
--- @brief TCP SYN cookie implementation.
--- Includes:
--- - calculate and verify a cookie
--- - functions to build and verify each part of the cookie
---------------------------------

local ffi 	= require "ffi"
local log	= require "log"
local memory = require "memory"
local proto = require "proto/proto"
require "utils"

local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift


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

-- one cycle is 64 64 seconds (6 bit right shoft of timestamp)
local timestampValidCycles = 1

-- MSS encodings
local MSS = { 
	mss1=50, 
	mss2=55,
}


-------------------------------------------------------------------------------------------
---- Timestamp
-------------------------------------------------------------------------------------------

local function getTimestamp()
	local t = time()
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

local function getHash(...)
	local args = {...}
	local sum = 0
	for k, v in pairs(args) do
		-- log:debug(k .. ':            ' .. toBinary(tonumber(v)))
		sum = sum + tonumber(v)
	end
	-- log:debug('sum:            ' .. toBinary(sum))
	return band(hash(sum), 0x00ffffff)
end

local function verifyHash(oldHash, ...)
	local newHash = getHash(...)
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
	ts = lshift(tsOrig, 27)
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
		--log:warn('Received cookie with invalid timestamp')
		return false
	end

	-- check hash
	local hash = band(cookie, 0x00ffffff)
	-- log:debug('Hash:           ' .. toBinary(hash))
	if not verifyHash(hash, pkt.ip4:getSrc(), pkt.ip4:getDst(), pkt.tcp:getSrc(), pkt.tcp:getDst(), ts) then
		--log:warn('Received cookie with invalid hash')
		return false
	else
		-- finally decode MSS and return it
		--log:debug('Received legitimate cookie')
		return decodeMss(band(rshift(cookie, 24), 0x3))
	end
end

-------------------------------------------------------------------------------------------
---- State keeping
-------------------------------------------------------------------------------------------

-- TODO add some form of timestamp and garbage collection on timeout
-- eg if not refreshed, remove after 60 seconds(2bits, every 30 seconds unset one, if both unset remove)
local verifiedConnections = {}

function mod.getIdx(pkt, leftToRight)
	if leftToRight then
		return pkt.ip4:getSrc() .. ':' .. pkt.tcp:getSrc() .. '-' .. pkt.ip4:getDst() .. ':' .. pkt.tcp:getDst()
	else
		return pkt.ip4:getDst() .. ':' .. pkt.tcp:getDst() .. '-' .. pkt.ip4:getSrc() .. ':' .. pkt.tcp:getSrc()
	end
end

local getIdx = mod.getIdx

function mod.setLeftVerified(pkt)
	local idx = getIdx(pkt, mod.LEFT_TO_RIGHT)
	local con = verifiedConnections[idx]
	if con then
		-- connection is already left verified, 
		-- hence, this packet and the syn we send next is duplicated
		-- option A: drop it
		-- 		disadvantage: original syn might have gotten lost (server busy, ...)
		-- option B (chosen): send again
		-- 		we assume the Ack number has not changed (which it obviously shouldn't)
		--		if it has changed, something is wrong
		--		hence, we assume the first Ack number to be the correct one
		return
	end
	con = {}
	con['lAck'] = pkt.tcp:getAckNumber()
	verifiedConnections[idx] = con
end

function mod.setRightVerified(pkt)
	local idx = getIdx(pkt, mod.RIGHT_TO_LEFT)
	local con = verifiedConnections[idx]
	if not con or not con['lAck'] then
		-- not left verified,
		-- happens if a connection is deleted 
		-- but right still has some packets in flight
		--log:debug('Not left verified, something is wrong')
		return false
	end
	con['diff'] = pkt.tcp:getSeqNumber() - con['lAck'] + 1
	con['lAck'] = nil
	return true
end

function mod.setFin(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]
	if not con then
		-- FIN for not verified connection
		-- means conenction was already deleted
		-- and this packet can be ignored
		--log:debug('FIN for not verified connection ' .. (leftToRight and 'from left ' or 'from right ') .. idx)
		return
	end
	--log:debug('one way FIN ' .. (leftToRight and 'from left' or 'from right'))
	if leftToRight then
		con['lFin'] = true --con['lFin'] .. '-' .. getPkts(con)
	else
		con['rFin'] = true -- con['rFin'] .. '-' .. getPkts(con)
	end
	-- to identify the final ACK of the connection store the Sequence number
	if con['lFin'] and con['rFin'] then 
		con['FinSeqNumber'] = pkt.tcp:getSeqNumber()
	end
end

function mod.setRst(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]
	if not con then
		-- RST for not verified connection
		-- means conenction was already deleted
		-- and this packet can be ignored
		--log:debug('RST for not verified connection ' .. (leftToRight and 'from left ' or 'from right ') .. idx)
		return
	end
	--log:debug('one way RST ' .. (leftToRight and 'from left' or 'from right'))
	if leftToRight then
		con['lRst'] = true --con['lRst'] .. '-' .. getPkts(con)
	else
		con['rRst'] = true --con['rRst'] .. '-' .. getPkts(con)
	end
end

local function unsetVerified(idx)
	--log:warn('Deleting connection ' .. idx)
	-- disabled as it has huge performance impact :( (3k reqs/s)
	verifiedConnections[idx] = nil
end

local function checkUnsetVerified(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]
	-- RST: in any case, delete connection
	if con['lRst'] or con['rRst'] then 
		unsetVerified(idx)
	-- FIN: only if both parties sent a FIN
	-- 		+ it has to be an ACK for the last sequence number
	elseif con['lFin'] and con['rFin'] then 
		-- check for ack and the number matches
		if isAck(pkt) and con['FinSeqNumber'] + 1 == pkt.tcp:getAckNumber() then
				unsetVerified(idx)
		end
		-- otherwise it was an old packet or wrong direction
		-- no action in that case
	end
end

-- TODO update timstamp
function mod.isVerified(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]

	-- a connection is verified if it is in both directions
	-- in that case, the diff is calculated
	if con and con['diff'] then
		return con
	end
	return false
end

function mod.printVerifiedConnections()
	log:debug('********************')
	log:debug('Verified Connections')
	local numRst = 0
	local num = 0
	for k, v in pairs(verifiedConnections) do
		num = num + 1
		local str = ''
		if type(v) == 'table' then
		for ik, iv in pairs(v) do
			str = str .. ', ' .. tostring(ik) .. '=' .. tostring(iv)
			if ik == 'lRst' or ik == 'rRst' then
				numRst = numRst + 1
			end
		end
		else
		str = tostring(v)
		end
		log:debug(tostring(k) .. ' -> ' .. str)
	end
	log:debug('Numer of resets: ' .. numRst .. '/' .. num)
	log:debug('********************')
end

-- infringement things (TODO move at some point)
function mod.isVerifiedReset(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	if verifiedConnections[idx] then
		return true
	else
		verifiedConnections[idx] = true
		return false
	end
end

-- same as reset
function mod.isVerifiedIgnore(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	if verifiedConnections[idx] then
		return true
	else
		verifiedConnections[idx] = true
		return false
	end
end

function mod.setVerifiedSequence(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	verifiedConnections[idx] = true
end

function mod.isVerifiedSequence(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	if verifiedConnections[idx] then
		return true
	else
		return false
	end
end

-------------------------------------------------------------------------------------------
---- Packet modification and crafting for cookie strategy
-------------------------------------------------------------------------------------------

-- simply resend the complete packet, but adapt seq/ack number
function mod.sequenceNumberTranslation(rxBuf, txBuf, rxPkt, txPkt, leftToRight)
	--log:debug('Performing Sequence Number Translation ' .. (leftToRight and 'from left ' or 'from right '))
	
	-- I recall this delivered the wrong size once
	-- however, it is significantly faster (4-5k reqs/s!!)
	local size = rxBuf:getSize() 	
	
	-- copy content
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	txBuf:setSize(size)

	-- translate numbers, depends on direction
	local diff = mod.isVerified(rxPkt, leftToRight)
	if not diff then
		-- packet is not verified, hence, we can't translate it
		-- happens after deleting connections or before second handshake is finished
		--log:error('translation without diff, something is horribly wrong ' .. getIdx(rxPkt, leftToRight))
		--rxBuf:dump()
		return
	end
	if leftToRight then
		txPkt.tcp:setAckNumber(rxPkt.tcp:getAckNumber() + diff['diff'])
	else
		txPkt.tcp:setSeqNumber(rxPkt.tcp:getSeqNumber() - diff['diff'])
	end

	
	-- calculate TCP checksum
	-- IP header does not change, hence, do not recalculate IP checksum
	-- only for KNI we can't offload it
	if leftToRight then
		--log:debug('Calc checksum ' .. (leftToRight and 'from left ' or 'from right '))
		txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	else
		--txPkt.tcp:setChecksum(0)
	end

	-- check whether connection should be deleted
	checkUnsetVerified(rxPkt, leftToRight)
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
	txPkt.tcp:setDst(rxPkt.tcp:getSrc())
	txPkt.tcp:setSrc(rxPkt.tcp:getDst())
	
	txPkt.tcp:setSeqNumber(cookie)
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)
	txPkt.tcp:setWindow(mss)
end

-- bufs
function mod.getSynAckBufs()
	local lTXSynAckMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
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
