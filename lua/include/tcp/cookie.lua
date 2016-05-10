---------------------------------
--- @file cookie.lua
--- @brief TCP SYN cookie implementation.
--- Includes:
--- - calculate and verify a cookie
--- - functions to build and verify each part of the cookie
---------------------------------

local log	= require "log"
local ffi	= require "ffi"
require "utils"

local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift

local mod = {}

-------------------------------------------------------------------------------------------
---- Parameters
-------------------------------------------------------------------------------------------

-- one cycle is 64 64 seconds (6 bit right shoft of timestamp)
local timestampValidCycles = 1

-- mss encodings
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
---- Cookie
-------------------------------------------------------------------------------------------

function mod.calculateCookie(pkt)
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
---------------------------------------------------------------------------------------------

local stateTable = {}
mod.stateTable = stateTable
stateTable.__index = stateTable

function mod.createStateTable()
	return setmetatable({ num = 0 }, stateTable)
end

-- TODO add some form of timestamp and garbage collection on timeout
-- eg if not refreshed, remove after 60 seconds(2bits, every 30 seconds unset one, if both unset remove)
--mod.verifiedConnections = { num = 0 }

function mod.getIdx(pkt, leftToRight)
	if leftToRight then
		return pkt.ip4:getSrcString() .. ':' .. pkt.tcp:getSrc() .. '-' .. pkt.ip4:getDstString() .. ':' .. pkt.tcp:getDst()
	else
		return pkt.ip4:getDstString() .. ':' .. pkt.tcp:getDst() .. '-' .. pkt.ip4:getSrcString() .. ':' .. pkt.tcp:getSrc()
	end
end

function stateTable:setLeftVerified(pkt)
	local idx = mod.getIdx(pkt, LEFT_TO_RIGHT)
	local con = self.idx
	if con then
		-- connection is left verified, 
		-- hence, this syn is duplicated and can be dropped
		--log:debug('Already left verified')
		return false
	end
	con = {}
	con['lAck'] = pkt.tcp:getAckNumber()
	con['lPkts'] = 0
	con['rPkts'] = 0
	con['lFin'] = ''
	con['rFin'] = ''
	con['lRst'] = ''
	con['rRst'] = ''
	con['numPkts'] = 0
	self['num'] = self['num'] + 1
	self[idx] = con
	return true
end

function stateTable:setRightVerified(pkt)
	local idx = mod.getIdx(pkt, RIGHT_TO_LEFT)
	local con = self[idx]
	if not con then
		-- not left verified,
		-- happens if a connection is deleted 
		-- but right still has some packets in flight
		--log:debug('Not left verified, something is wrong')
		return false
	end
	con['rSeq'] = pkt.tcp:getSeqNumber()
	con['diff'] = con['rSeq'] - con['lAck'] + 1
	return true
end

local function incPkts(con)
	con['numPkts'] = con['numPkts'] + 1
end

local function getPkts(con)
	return con['numPkts']
end

function stateTable:setFin(pkt, leftToRight)
	local idx = mod.getIdx(pkt, leftToRight)
	local con = self[idx]
	if not con then
		-- FIN for not verified connection
		-- means conenction was already deleted
		-- and this packet can be ignored
		--log:debug('FIN for not verified connection ' .. (leftToRight and 'from left ' or 'from right ') .. idx)
		return
	end
	--log:debug('one way FIN ' .. (leftToRight and 'from left' or 'from right'))
	if leftToRight then
		con['lFin'] = con['lFin'] .. '-' .. getPkts(con)
	else
		con['rFin'] = con['rFin'] .. '-' .. getPkts(con)
	end
	-- to identify the final ACK of the connection store the Sequence number
	if con['lFin'] and con['rFin'] then 
		con['FinSeqNumber'] = pkt.tcp:getSeqNumber()
	end
end

function stateTable:setRst(pkt, leftToRight)
	local idx = mod.getIdx(pkt, leftToRight)
	local con = self[idx]
	if not con then
		-- RST for not verified connection
		-- means conenction was already deleted
		-- and this packet can be ignored
		--log:debug('RST for not verified connection ' .. (leftToRight and 'from left ' or 'from right ') .. idx)
		return
	end
	--log:debug('one way RST ' .. (leftToRight and 'from left' or 'from right'))
	if leftToRight then
		con['lRst'] = con['lRst'] .. '-' .. getPkts(con)
	else
		con['rRst'] = con['rRst'] .. '-' .. getPkts(con)
	end
end

function stateTable:checkUnsetVerified(pkt, leftToRight)
	local idx = mod.getIdx(pkt, leftToRight)
	local con = self[idx]
	-- RST: in any case, delete connection
	if con['lRst'] ~= '' then 
		self:unsetVerified(pkt, leftToRight)
	elseif con['rRst'] ~= '' then 
		self:unsetVerified(pkt, leftToRight)
	-- FIN: only if both parties sent a FIN
	-- 		+ it has to be an ACK for the last sequence number
	elseif con['lFin'] ~= '' and con['rFin'] ~= '' then 
		-- check for ack and the number matches
		if isAck(pkt) and con['FinSeqNumber'] + 1 == pkt.tcp:getAckNumber() then
				self:unsetVerified(pkt, leftToRight)
		end
		-- otherwise it was an old packet or wrong direction
		-- no action in that case
	end
end

function stateTable:unsetVerified(pkt, leftToRight)
	local idx = mod.getIdx(pkt, leftToRight)
	--log:warn('Deleting connection ' .. idx)
	-- disabled as it has huge performance impact :( (3k reqs/s)
	--verifiedConnections[idx] = nil
end

-- TODO update timstamp
function stateTable:isVerified(pkt, leftToRight)
	local idx = mod.getIdx(pkt, leftToRight)
	local con = self[idx]

	-- a connection is verified if it is in both directions
	-- in that case, the diff is calculated
	if con and con['diff'] then
		if leftToRight then
			con['lPkts'] = con['lPkts'] + 1
		else
			con['rPkts'] = con['rPkts'] + 1
		end
		incPkts(con)
		return con
	end
	return false
end

function stateTable:printVerifiedConnections()
	log:debug('********************')
	log:debug('Verified Connections')
	for k, v in pairs(self) do
		local str = ''
		if type(v) == 'table' then
		for ik, iv in pairs(v) do
			str = str .. ', ' .. tostring(ik) .. '=' .. tostring(iv)
		end
		else
		str = tostring(v)
		end
		log:debug(tostring(k) .. ' -> ' .. str)
	end
	log:debug('********************')
end


-------------------------------------------------------------------------------------------
---- Sequence Number Translation
-------------------------------------------------------------------------------------------

-- simply resend the complete packet, but adapt seq/ack number
function stateTable:sequenceNumberTranslation(rxBuf, txBuf, rxPkt, txPkt, leftToRight)
	--log:debug('Performing Sequence Number Translation ' .. (leftToRight and 'from left ' or 'from right '))
	
	-- calculate packet size
	-- must not be smaller than 60
	--local size = rxPkt.ip4:getLength() + 14
	--size = size < 60 and 60 or size
	
	-- I recall this delivered the wrong size once
	-- however, it is significantly faster (4-5k reqs/s!!)
	local size = rxBuf:getSize() 	
	
	-- copy content
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	txBuf:setSize(size)

	-- translate numbers, depends on direction
	local diff = self:isVerified(rxPkt, leftToRight)
	if not diff then
		-- packet is not verified, hence, we can't translate it
		-- happens after deleting connections or before second handshake is finished
		--log:error('translation without diff, something is horribly wrong ' .. getIdx(rxPkt, leftToRight))
		--rxBuf:dump()
		return
	end
	if leftToRight then
		txPkt.tcp:setSeqNumber(rxPkt.tcp:getSeqNumber())
		txPkt.tcp:setAckNumber(rxPkt.tcp:getAckNumber() + diff['diff'])
	else
		txPkt.tcp:setSeqNumber(rxPkt.tcp:getSeqNumber() - diff['diff'])
		txPkt.tcp:setAckNumber(rxPkt.tcp:getAckNumber())
	end

	-- calculate TCP checksum
	txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	-- IP header does not change, hence, do not recalculate IP checksum

	-- check whether connection should be deleted
	self:checkUnsetVerified(rxPkt, leftToRight)
end


return mod
