---------------------------------
--- @file synAuthentication.lua
--- @brief TCP SYN flood mitigation via SYN authentication
--- Includes:
--- - wrong Ack number on initial SYN
---------------------------------

local ffi 	= require "ffi"
local log	= require "log"
local memory = require "memory"
local proto = require "proto/proto"
local cookie = require "tcp/synCookie"
require "utils"

local mod = {}

-------------------------------------------------------------------------------------------
---- Packet modification and crafting for SYN authentication
-------------------------------------------------------------------------------------------

function mod.forwardTraffic(txBuf, rxBuf)
	cookie.forwardTraffic(txBuf, rxBuf)
end

function mod.createResponseAuth(txBuf, rxPkt)
	--log:debug('crafting seq vio')
	local txPkt = txBuf:getTcp4Packet()
	
	txPkt.eth:setSrc(rxPkt.eth:getDst())
	txPkt.eth:setDst(rxPkt.eth:getSrc())

	-- IP addresses
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	txPkt.ip4:setDst(rxPkt.ip4:getSrc())
	
	-- TCP
	txPkt.tcp:setSrc(rxPkt.tcp:getDst())
	txPkt.tcp:setDst(rxPkt.tcp:getSrc())

	-- set violating ack number
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() - 1) -- violation => AckNumber != SeqNumber + 1
end


function mod.getBufs()
	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=42, -- randomly chosen
			tcpAckNumber=0,  -- set depending on RX
			tcpSyn=1,
			tcpAck=1,
			pktLength=60,
		}
	end)
	return mem:bufArray()
end

ffi.cdef [[
	struct bit_map_auth_map {};
	struct bit_map_auth_map * mg_bit_map_auth_create();
	
	bool mg_bit_map_auth_update(struct bit_map_auth_map *m, uint32_t k);
	void mg_bit_map_auth_find_update(struct bit_map_auth_map *m, uint32_t k);
	void mg_bit_map_auth_set(struct bit_map_auth_map *m, uint32_t k);
	bool mg_bit_map_auth_get(struct bit_map_auth_map *m, uint32_t k);
]]


local LEFT_TO_RIGHT = true
local RIGHT_TO_LEFT = false

----------------------------------------------------------------------------------------------------------------------------
----
----------------------------------------------------------------------------------------------------------------------------

local bitMapAuth = {}
bitMapAuth.__index = bitMapAuth

function mod.createBitMapAuth()
	log:info("Creating a bit map for TCP SYN Authentication strategy")
	return setmetatable({
		map = ffi.C.mg_bit_map_auth_create()
	}, bitMapAuth)
end

function bitMapAuth:update(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	return ffi.C.mg_bit_map_auth_update(self.map, k)
end

function bitMapAuth:set(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	ffi.C.mg_bit_map_auth_set(self.map, k)
end

function bitMapAuth:get(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	return ffi.C.mg_bit_map_auth_get(self.map, k)
end

function bitMapAuth:findUpdate(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	ffi.C.mg_bit_map_auth_find_update(self.map, k)
end

function bitMapAuth:updateWhitelisted(pkt)
	self:findUpdate(pkt, leftToRight)
end

function bitMapAuth:isWhitelisted(pkt)
	return self:get(pkt, leftToRight)
end

function bitMapAuth:setWhitelisted(pkt)
	return self:set(pkt, leftToRight)
end

return mod
