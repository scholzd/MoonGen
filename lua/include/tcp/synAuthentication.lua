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

local SERVER_IP = parseIP4Address("192.168.1.1")
local CLIENT_MAC = parseMacAddress("90:e2:ba:98:58:78")
local SERVER_MAC = parseMacAddress("90:e2:ba:98:88:e8")
local PROXY_MAC  = parseMacAddress("90:e2:ba:98:88:e9") 

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
	
	bool mg_bit_map_auth_update(struct bit_map_auth_map *m, uint32_t k, bool rst);
]]


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

local function getKey(pkt)
	local mac = pkt.eth.src
	if mac == CLIENT_MAC then
		return pkt.ip4:getSrc()
	else
		return pkt.ip4:getDst()
	end
end

function bitMapAuth:isWhitelisted(pkt)
	local k = getKey(pkt)
	return ffi.C.mg_bit_map_auth_update(self.map, k, pkt.tcp:getRst())
end

return mod
