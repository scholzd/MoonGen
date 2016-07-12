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

return mod
