---------------------------------
--- @file cookie.lua
--- @brief TCP SYN cookie implementation.
--- Includes:
--- - calculate and verify a cookie
--- - functions to build and verify each part of the cookie
---------------------------------

local log	= require "log"
require "utils"

local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift


-------------------------------------------------------------------------------------------
---- Parameters
-------------------------------------------------------------------------------------------

-- one cycle is 64 64 seconds (6 bit right shoft of timestamp)
local timestampValidCycles = 1

-- MSS encodings
local MSS = { 
	mss1=50, 
	mss2=55,
}


-------------------------------------------------------------------------------------------
---- Cookie
-------------------------------------------------------------------------------------------

function calculateCookie(pkt)
	local ts_orig = getTimestamp()
	--log:debug('Time: ' .. ts .. ' ' .. toBinary(ts))
	ts = lshift(ts_orig, 27)
	--log:debug('Time: ' .. ts .. ' ' .. toBinary(ts))

	local mss = encodeMss()
	mss = lshift(mss, 24)

	local hash = getHash(
		pkt.ip4:getSrc(), 
		pkt.ip4:getDst(), 
		pkt.tcp:getSrc(),
		pkt.tcp:getDst(),
		ts_orig
	)
	--log:debug('Created TS:     ' .. toBinary(ts))
	--log:debug('Created MSS:    ' .. toBinary(mss))
	--log:debug('Created hash:   ' .. toBinary(hash))
	local cookie = ts + mss + hash
	--log:debug('Created cookie: ' .. toBinary(cookie))
	return cookie, mss
end

function verifyCookie(pkt)
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
---- Timestamp
-------------------------------------------------------------------------------------------

function getTimestamp()
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

function verifyTimestamp(t)
	return t + timestampValidCycles >= getTimestamp()
end


-------------------------------------------------------------------------------------------
---- MSS
-------------------------------------------------------------------------------------------

function encodeMss()
	-- 3 bits, allows for 8 different MSS
	mss = 1 -- encoding see MSS
	-- log:debug('MSS: ' .. mss .. ' ' .. toBinary(mss))
	return mss
end

function decodeMss(idx)
	return MSS['mss' .. tostring(idx)] or -1
end


-------------------------------------------------------------------------------------------
---- Hash
-------------------------------------------------------------------------------------------

function getHash(...)
	local args = {...}
	local sum = 0
	for k, v in pairs(args) do
		-- log:debug(k .. ':            ' .. toBinary(tonumber(v)))
		sum = sum + tonumber(v)
	end
	-- log:debug('sum:            ' .. toBinary(sum))
	return band(hash(sum), 0x00ffffff)
end

function verifyHash(oldHash, ...)
	local newHash = getHash(...)
	-- log:debug('Old hash:       ' .. toBinary(oldHash))
	-- log:debug('New hash:       ' .. toBinary(newHash))
	return oldHash == newHash
end

function hash(int)
	-- TODO implement something with real crypto later on
	return int
end
