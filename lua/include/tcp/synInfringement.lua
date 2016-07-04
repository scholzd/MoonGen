---------------------------------
--- @file synInfringement.lua
--- @brief TCP SYN flood mitigation via protocol infringement responses
--- Includes:
--- - ignore initial SYN
--- - reset on initial SYN
--- - wrong Ack number on initial SYN
---------------------------------

local ffi 	= require "ffi"
local log	= require "log"
local memory = require "memory"
local proto = require "proto/proto"
require "utils"

local mod = {}

-------------------------------------------------------------------------------------------
---- Packet modification and crafting for protocol violation strategies
-------------------------------------------------------------------------------------------

function mod.forwardTraffic(txBuf, rxBuf)
	-- set size of tx packet
	local size = rxBuf:getSize()
	txBuf:setSize(size)
	
	-- copy data 
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
end

function mod.createResponseIgnore(txBuf, rxPkt)
	-- yep, nothing
end

function mod.createResponseReset(txBuf, rxPkt)
	--log:debug('Crafting rst')
	local txPkt = txBuf:getTcp4Packet()
	
	txPkt.eth:setSrc(rxPkt.eth:getDst())
	txPkt.eth:setDst(rxPkt.eth:getSrc())

	-- IP addresses
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	txPkt.ip4:setDst(rxPkt.ip4:getSrc())
	
	-- TCP
	txPkt.tcp:setSrc(rxPkt.tcp:getDst())
	txPkt.tcp:setDst(rxPkt.tcp:getSrc())

	
	-- alternative approach: reuse rx buffer (saves alloc and free, but more members to set)
	-- TODO check whats better under load
	-- MAC addresses
	--local tmp = lRXPkt.eth:getSrc()
	--lRXPkt.eth:setSrc(lRXPkt.eth:getDst())
	--lRXPkt.eth:setDst(tmp)

	---- IP addresses
	--tmp = lRXPkt.ip4:getSrc()
	--lRXPkt.ip4:setSrc(lRXPkt.ip4:getDst())
	--lRXPkt.ip4:setDst(tmp)
	--
	---- TCP
	--tmp = lRXPkt.tcp:getSrc()
	--lRXPkt.tcp:setSrc(lRXPkt.tcp:getDst())
	--lRXPkt.tcp:setDst(tmp)
	--
	--lRXPkt.tcp:unsetSyn()
	--lRXPkt.tcp:setRst()
end 

function mod.createResponseSequence(txBuf, rxPkt)
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
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() - 2) -- violation => AckNumber != SeqNumber + 1

	-- alternative approach: reuse rx buffer (saves alloc and free, but more members to set)
	-- TODO check whats better under load
	-- reuse RX buffer
	-- MAC addresses
	--local tmp = lRXPkt.eth:getSrc()
	--lRXPkt.eth:setSrc(lRXPkt.eth:getDst())
	--lRXPkt.eth:setDst(tmp)

	---- IP addresses
	--tmp = lRXPkt.ip4:getSrc()
	--lRXPkt.ip4:setSrc(lRXPkt.ip4:getDst())
	--lRXPkt.ip4:setDst(tmp)
	--
	---- TCP
	--tmp = lRXPkt.tcp:getSrc()
	--lRXPkt.tcp:setSrc(lRXPkt.tcp:getDst())
	--lRXPkt.tcp:setDst(tmp)
	--
	--lRXPkt.tcp:setAckNumber(lRXPkt.tcp:getSeqNumber() - 1) -- violation => AckNumber != SeqNumber + 1
	--lRXPkt.tcp:setSeqNumber(42)
	--lRXPkt.tcp:setAck()
end


--bufs

function mod.getRstBufs()
	local lTXRstMem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpRst=1,
			pktLength=60,
		}
	end)
	return lTXRstMem:bufArray()
end
	
function mod.getSeqBufs()
	local lTXSeqMem = memory.createMemPool(function(buf)
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
	return lTXSeqMem:bufArray()
end

return mod
