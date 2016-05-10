local mg		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log		= require "log"
local profile	= require "jit.profile"
local kni 		= require "kni"
local ffi		= require "ffi"
local dpdkc 	= require "dpdkc"
local proto		= require "proto/proto"

-- tcp SYN defense strategies
local cookie	= require "tcp/cookie"

-- utility
local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift


---------------------------------------------------
-- Usage
---------------------------------------------------
-- TODO config for interfaces etc

function master(rxPort, txPort)
	if not txPort or not rxPort then
		log:info("Usage: rxPort txPort")
		return
	end
	txPort = tonumber(txPort)
	rxPort = tonumber(rxPort)
	
	local lRXDev = device.config{ port = rxPort, txQueues=2 }
	local lTXDev = device.config{ port = txPort }
	lRXDev:wait()
	lTXDev:wait()
	mg.launchLua("tcpProxySlave", lRXDev, lTXDev)
	
	mg.waitForSlaves()
end


---------------------------------------------------
-- Terminology
---------------------------------------------------

-- left: outside, internet, clients, potential attackers, whatever
-- right: "protected" side, connection to server(s), only filtered traffic comes here


---------------------------------------------------
-- Constants
---------------------------------------------------

LEFT_TO_RIGHT = true
RIGHT_TO_LEFT = false


-----------------------------------------------------
-- debug utility 
-----------------------------------------------------

-- print table of string -> string
function sT(t)
	local str = ''
	for k, v in pairs(t) do
		str = str .. ', ' .. k .. ' -> ' .. v
	end
	return str
end


-----------------------------------------------------
-- profiling
-----------------------------------------------------

local profile_stats = {}

function profile_callback(thread, samples, vmstate)
	local dump = profile.dumpstack(thread, "l (f) << ", 1)
	--printf("profile cb: " .. dump)
	if(profile_stats[dump]) then
		profile_stats[dump] = profile_stats[dump] + 1
	else
		profile_stats[dump] = 1
	end
end


----------------------------------------------------
-- check packet type
----------------------------------------------------

function isIP4(pkt)
	return pkt.eth:getType() == proto.eth.TYPE_IP 
end

function isTcp4(pkt)
	return isIP4(pkt) and pkt.ip4:getProtocol() == proto.ip4.PROTO_TCP
end

function isSyn(pkt)
	return pkt.tcp:getSyn() == 1
end

function isAck(pkt)
	return pkt.tcp:getAck() == 1
end

function isRst(pkt)
	return pkt.tcp:getRst() == 1
end

function isFin(pkt)
	return pkt.tcp:getFin() == 1
end

function printChecks(pkt)
	print('Is IP4 ' .. tostring(isIP4(pkt)))
	print('Is TCP ' .. tostring(isTcp4(pkt)))
	print('Is SYN ' .. tostring(isSyn(pkt)))
	print('Is ACK ' .. tostring(isAck(pkt)))
end


---------------------------------------------------
-- slave
---------------------------------------------------

function tcpProxySlave(lRXDev, lTXDev)
	log:setLevel("DEBUG")
	
	-------------------------------------------------------------
	-- right/virtual interface
	-------------------------------------------------------------
	-- Create KNI device
	log:info('Initialize KNI')
	kni.init(4)
	log:info('Creating virtual device')
	local virtualDevMemPool = memory.createMemPool{n=8192}
	local virtualDev = kni.createKNI(0, lRXDev, virtualDevMemPool, "vEth0")
	log:info('Ifconfig virtual device')
	virtualDev:setIP("192.168.1.1", 24)

	log:info('ARP entry for client') -- TODO use ARP task
	io.popen("/usr/sbin/arp -s 192.168.1.101 90:e2:ba:98:58:78")

	-- not sure but without this it doesn't work
	for i = 0, 100 do
    	virtualDev:handleRequest()	
		mg.sleepMillisIdle(1)
	end

	-- TX buffers for right to right
	local rTXMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
		}
	end)
	local rTXBufs = rTXMem:bufArray(1)
	
	-- RX buffers for right
	local rRXMem = memory.createMemPool()	
	local rRXBufs = rRXMem:bufArray()


	-------------------------------------------------------------
	-- left/physical interface
	-------------------------------------------------------------
	-- RX buffers for left
	local lRXQueue = lRXDev:getRxQueue(0)
	local lRXMem = memory.createMemPool()	
	local lRXBufs = lRXMem:bufArray()
	lRXStats = stats:newDevRxCounter(lRXDev, "plain")

	-- TX buffers for left to left
	local lTXQueue = lTXDev:getTxQueue(0)
	local lTXMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
		}
	end)
	local lTXBufs = lTXMem:bufArray()
	lTXStats = stats:newDevTxCounter(lTXDev, "plain")

	-- TX buffers for right to left
	local lTX2Queue = lTXDev:getTxQueue(1)
	local lTX2Mem = memory.createMemPool()
	local lTX2Bufs = lTX2Mem:bufArray(1)
	

	-------------------------------------------------------------
	-- profiling
	-------------------------------------------------------------
	profile.start("l", profile_callback)

	local stateTable = cookie.createStateTable()

	-- main event loop
	log:info('Starting TCP Proxy')
	while mg.running() do
		------------------------------------------------------------------------------ poll right interface
		--log:debug('Polling right (virtual) Dev')
		rx = virtualDev:rxBurst(rRXBufs, 63)
		for i = 1, rx do
			local translate = false
			
			local rRXPkt = rRXBufs[i]:getTcp4Packet()
			if not isTcp4(rRXPkt) then
				--log:info('Ignoring rRX packet from server that is not TCP')
			else
				---------------------------------------------------------------------- process TCP
				---------------------------------------------------------------------- SYN/ACK from server, finally establish connection
				if isSyn(rRXPkt) and isAck(rRXPkt) then
					--log:debug('Received SYN/ACK from server, sending ACK back')
					stateTable:setRightVerified(rRXPkt)
					
					-- send ACK to server
					rTXBufs:alloc(70)
					local rTXBuf = rTXBufs[1]

					-- set size of tx packet
					local size = rRXBufs[i]:getSize()
					rTXBuf:setSize(size)
					
					-- copy data TODO directly use rx buffer
					--log:debug('copy data')
					ffi.copy(rTXBuf:getData(), rRXBufs[i]:getData(), size)
					
					-- send packet back with seq, ack + 1
					local rTXPkt = rTXBuf:getTcp4Packet()
					local tmp = rRXPkt.ip4:getSrc()
					rTXPkt.ip4:setSrc(rRXPkt.ip4:getDst())
					rTXPkt.ip4:setDst(tmp)
					tmp = rRXPkt.tcp:getSrc()
					rTXPkt.tcp:setSrc(rRXPkt.tcp:getDst())
					rTXPkt.tcp:setDst(tmp)
					rTXPkt.tcp:setSeqNumber(rRXPkt.tcp:getAckNumber())
					rTXPkt.tcp:setAckNumber(rRXPkt.tcp:getSeqNumber() + 1)
					rTXPkt.tcp:unsetSyn()
					rTXPkt.tcp:setAck()
					rTXPkt:setLength(size)

					-- calculate checksums
					rTXPkt.tcp:calculateChecksum(rTXBuf:getData(), size, true)
					rTXPkt.ip4:calculateChecksum()
					
					-- done, sending
					--log:debug('Sending rTXBuf via KNI')
					virtualDev:txSingle(rTXBuf)
				----------------------------------------------------------------------- any verified packet from server
				elseif stateTable:isVerified(rRXPkt, RIGHT_TO_LEFT) then
					-- anything else must be from a verified connection, translate and send via physical nic
					--log:info('Packet of verified connection from server, translate and forward')
					local idx = cookie.getIdx(rRXPkt, RIGHT_TO_LEFT)
					if isRst(rRXPkt) then -- TODO move to bottom
						--log:debug('Got RST packet from right ' .. idx)
						stateTable:setRst(rRXPkt, RIGHT_TO_LEFT)
					elseif isFin(rRXPkt) then
						--log:debug('Got FIN packet from right ' .. idx)
						stateTable:setFin(rRXPkt, RIGHT_TO_LEFT)
					end
					translate = true
				------------------------------------------------------------------------ not verified connection from server
				else
					--log:debug('Packet of not verified connection from right')
				end
			end
			if translate then
				--log:info('Translating from right to left')
			
				lTX2Bufs:alloc(70)
				local lTXBuf = lTX2Bufs[1]
				local lTXPkt = lTXBuf:getTcp4Packet()

				stateTable:sequenceNumberTranslation(rRXBufs[i], lTXBuf, rRXPkt, lTXPkt, RIGHT_TO_LEFT)
				lTX2Queue:send(lTX2Bufs)
			end
		end
		
		--log:debug('free rRX')
		rRXBufs:freeAll()

		------------------------------------------------------------------- polling from right interface done

		------------------------------------------------------------------- polling from left interface
		rx = lRXQueue:tryRecv(lRXBufs, 1)

		if rx > 0 then
			lTXBufs:allocN(60, rx)
		end
		for i = 1, rx do
			local translate = false
			
			local lRXPkt = lRXBufs[i]:getTcp4Packet()
			if not isTcp4(lRXPkt) then
				--log:info('Ignoring packet that is not TCP from left')
			--------------------------------------------------------------- processing TCP
			else
				------------------------------------------------------------ SYN -> defense mechanism
				if isSyn(lRXPkt) then
					--log:info('Received SYN from left')
					-- strategy cookie

					local cookie, mss = cookie.calculateCookie(lRXPkt)
				
					-- build tx pkt
					local lTXPkt = lTXBufs[i]:getTcp4Packet()
					-- MAC addresses
					lTXPkt.eth:setDst(lRXPkt.eth:getSrc())
					lTXPkt.eth:setSrc(lRXPkt.eth:getDst())

					-- IP addresses
					lTXPkt.ip4:setDst(lRXPkt.ip4:getSrc())
					lTXPkt.ip4:setSrc(lRXPkt.ip4:getDst())
					
					-- TCP
					lTXPkt.tcp:setDst(lRXPkt.tcp:getSrc())
					lTXPkt.tcp:setSrc(lRXPkt.tcp:getDst())
					
					lTXPkt.tcp:setAck()
					lTXPkt.tcp:setSyn()
					lTXPkt.tcp:setSeqNumber(cookie)
					lTXPkt.tcp:setAckNumber(lRXPkt.tcp:getSeqNumber() + 1)
					lTXPkt.tcp:setWindow(mss)

					-- length
					lTXBufs[i]:setSize(lRXBufs[i]:getSize())
				-------------------------------------------------------------------------------------------------------- verified -> translate and forward
				-- check with verified connections
				-- if already verified in both directions, immediately forward, otherwise check cookie
				elseif stateTable:isVerified(lRXPkt, LEFT_TO_RIGHT) then 
					--log:info('Received packet of verified connection from left, translating and forwarding')
					local idx = cookie.getIdx(lRXPkt, LEFT_TO_RIGHT)
					if isRst(lRXPkt) then -- TODO move to bottom
						--log:debug('Got RST packet from left ' .. idx)
						stateTable:setRst(lRXPkt, LEFT_TO_RIGHT)
						translate = true
					elseif isFin(lRXPkt) then
						--log:debug('Got FIN packet from left ' .. idx)
						stateTable:setFin(lRXPkt, LEFT_TO_RIGHT)
						translate = true
					end
					translate = true
				------------------------------------------------------------------------------------------------------- not verified, but is ack -> verify cookie
				elseif isAck(lRXPkt) then
					local ack = lRXPkt.tcp:getAckNumber()
					local mss = cookie.verifyCookie(lRXPkt)
					if mss then
						--log:info('Received valid cookie from left, starting handshake with server')
						
						if stateTable:setLeftVerified(lRXPkt) then
							-- connection is left verified, start handshake with right
							rTXBufs:alloc(70)
							local rTXBuf = rTXBufs[1]

							-- set size of tx packet
							local size = lRXBufs[i]:getSize()
							rTXBuf:setSize(size)
							
							-- copy data TODO directly use rx buffer
							ffi.copy(rTXBuf:getData(), lRXBufs[i]:getData(), size)
							
							-- adjust some members: sequency number, flags, checksum, length fields
							local rTXPkt = rTXBuf:getTcp4Packet()
							-- reduce seq num by 1 as during handshake it will be increased by 1 (in SYN/ACK)
							-- this way, it does not have to be translated at all
							rTXPkt.tcp:setSeqNumber(rTXPkt.tcp:getSeqNumber() - 1)
							rTXPkt.tcp:setSyn()
							rTXPkt.tcp:unsetAck()
							rTXPkt:setLength(size)

							-- calculate checksums
							rTXPkt.tcp:calculateChecksum(rTXBuf:getData(), size, true)
							rTXPkt.ip4:calculateChecksum()
							
							-- done, sending
							--log:debug('Sending vTXBuf via KNI')
							virtualDev:txSingle(rTXBuf)
						else
							-- was already left verified -> stall
							-- should not happen as it is checked above already
							--log:debug('Already left verified, discarding')
						end
					else
						log:warn('Wrong cookie, dropping packet ' .. cookie.getIdx(lRXPkt, LEFT_TO_RIGHT))
						-- drop, and done
						-- most likely simply the timestamp timed out
						-- but it might also be a DoS attack that tried to guess the cookie
					end
				----------------------------------------------------------------------------------------------- unverified, but not syn/ack -> ignore
				else
					-- not syn, unverified packets -> belongs to already deleted connection -> drop
					--log:error('unhandled packet ' .. tostring(isVerified(lRXPkt, LEFT_TO_RIGHT)))
				end
			end
			if translate then
				--log:info('Translating from left to right')
				rTXBufs:alloc(70)
				local rTXBuf = rTXBufs[1]

				local rTXPkt = rTXBufs[1]:getTcp4Packet()
				stateTable:sequenceNumberTranslation(lRXBufs[i], rTXBufs[1], lRXPkt, rTXPkt, LEFT_TO_RIGHT)
				virtualDev:txSingle(rTXBuf)
			end
		end
		if rx > 0 then	
			--offload checksums to NIC
			lTXBufs:offloadTcpChecksums()
	
			lTXQueue:send(lTXBufs)
		end
		lRXBufs:free(rx)


		----------------------------- all actions by polling left interface done (also all buffers sent or cleared)

		lRXStats:update()
		lTXStats:update()
	end
	stateTable:printVerifiedConnections()

	log:info('Releasing KNI device')
	virtualDev:release()
	
	log:info('Closing KNI')
	kni.close()
	
	lRXStats:finalize()
	lTXStats:finalize()

	profile.stop()

	print("Profiler results:")

	for i,v in pairs(profile_stats) do
		print( v .. " ::: " .. i)
	end

	log:info('Slave done')
end
