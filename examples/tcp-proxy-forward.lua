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
	
	local rxDev = device.config{ port = rxPort, txQueues=2 }
	local txDev = device.config{ port = txPort }
	rxDev:wait()
	txDev:wait()
	mg.launchLua("tcpProxySlave", rxDev, txDev)
	
	mg.waitForSlaves()
end


-----------------------------------------------------
-- profiling TODO move to util or new profiling.lua
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

function isIP4(pkt)
	return pkt.eth:getType() == proto.eth.TYPE_IP 
end

function isTcp(pkt)
	return isIP4(pkt) and pkt.ip4:getProtocol() == proto.ip4.PROTO_TCP
end

---------------------------------------------------
-- slave
---------------------------------------------------

function tcpProxySlave(rxDev, txDev)
	log:setLevel("DEBUG")
	
	-- virutal KNI
	log:info('Init KNI')
	kni.init(4)
	log:info('Creating virtual Dev')
	local virtualDevMemPool = memory.createMemPool{n=8192}
	local virtualDev = kni.createKNI(0, rxDev, virtualDevMemPool, "vEth1")
	log:info('Ifconfig virtual Dev')
	io.popen("/sbin/ifconfig " .. "vEth1" .. " " .. "192.168.1.1" .. "/" .. "24")
	for i = 0, 100 do
    	virtualDev:handleRequest()	
		mg.sleepMillisIdle(1)
	end
	log:info('ARP virtual Dev')
	io.popen("/usr/sbin/arp -s 192.168.1.101 90:e2:ba:98:58:78")

	for i = 0, 100 do
    	virtualDev:handleRequest()	
		mg.sleepMillisIdle(1)
	end

	-- v rx
	local vRXMem = memory.createMemPool()	
	local vRXBufs = vRXMem:bufArray()


	-- physical interfaces
	-- rx Dev
	local rxQueue = rxDev:getRxQueue(0)
	local rxMem = memory.createMemPool()	
	local rxBufs = rxMem:bufArray()
	rxStats = stats:newDevRxCounter(rxDev, "plain")
	
	-- tx queue
	local txQueue = txDev:getTxQueue(0)
	txStats = stats:newDevTxCounter(txDev, "plain")

	-- profiling
	profile.start("l", profile_callback)

	-- main event loop
	log:info('Starting TCP Proxy')
	while mg.running() do		
		local rx = rxQueue:tryRecv(rxBufs, 1)
		for i = 1, rx do
			local pkt = rxBufs[i]:getTcp4Packet()
			if isTcp(pkt) then
				pkt.tcp:setChecksum()
				pkt.ip4:setChecksum()
				pkt.tcp:calculateChecksum(rxBufs[i]:getData(), pkt.ip4:getLength() + 14, true)
				pkt.ip4:calculateChecksum()
			end
		end
		virtualDev:txBurst(rxBufs, rx)
		
		local rx = virtualDev:rxBurst(vRXBufs, 63)
		for i = 1, rx do
			local pkt = vRXBufs[i]:getTcp4Packet()
			if isTcp(pkt) then
				--log:info('Before')
				--pkt.tcp:setChecksum()
				--pkt.ip4:setChecksum()
				--vRXBufs[i]:dump()
				local b = pkt.tcp:getChecksum()
				pkt.tcp:calculateChecksum(vRXBufs[i]:getData(), pkt.ip4:getLength() + 14, true)
				--pkt.ip4:calculateChecksum()
				local a = pkt.tcp:getChecksum()
				if not (a == b) then
					log:debug('Not equal checksums ' .. string.format('%x', a) .. ' ' .. string.format('%x', b))
					vRXBufs[i]:dump()
				end
				if pkt.tcp:getRst() == 1 then
					log:debug('Is RST')
				end
				if pkt.tcp:getFin() == 1 then
					--log:debug('Is FIN')
				end
				--vRXBufs[i]:offloadTcpChecksum(true, nil, nil)
				--log:info('After')

				--vRXBufs[i]:dump()

			end
		end
		--vRXBufs:offloadTcpChecksums(true, nil, nil, rx)
		txQueue:sendN(vRXBufs, rx)
		--vRXBufs:freeAll()

		rxStats:update()
		txStats:update()
	end
	log:info('Releasing KNI device')
	virtualDev:release()
	
	log:info('Closing KNI')
	kni.close()
	
	rxStats:finalize()
	txStats:finalize()

	profile.stop()

	print("Profiler results:")

	for i,v in pairs(profile_stats) do
		print( v .. " ::: " .. i)
	end

	---- this is just for testing garbage collection
	--collectgarbage("collect")
	log:info('Slave done')
end
