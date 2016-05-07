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


---------------------------------------------------
-- Usage
---------------------------------------------------

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


---------------------------------------------------
-- Terminology
---------------------------------------------------

-- left: outside, internet, clients, potential attackers, whatever
-- right: "protected" side, connection to server(s), only filtered traffic comes here


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


-----------------------------------------------------
-- utility 
-----------------------------------------------------

function isIP4(pkt)
	return pkt.eth:getType() == proto.eth.TYPE_IP 
end

function isTcp(pkt)
	return isIP4(pkt) and pkt.ip4:getProtocol() == proto.ip4.PROTO_TCP
end


---------------------------------------------------
-- slave
---------------------------------------------------

function tcpProxySlave(lRXDev, lTXDev)
	--log:setLevel("DEBUG")
	
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

	-- right side (virtual device) buffers
	local rRXMem = memory.createMemPool()	
	local rRXBufs = rRXMem:bufArray()


	-- physical interfaces
	-- rx Dev
	local lRXQueue = lRXDev:getRxQueue(0)
	local lRXMem = memory.createMemPool()	
	local lRXBufs = lRXMem:bufArray()
	lRXStats = stats:newDevRxCounter(lRXDev, "plain")
	
	-- tx queue
	local lTXQueue = lTXDev:getTxQueue(0)
	lTXStats = stats:newDevTxCounter(lTXDev, "plain")

	-- profiling
	profile.start("l", profile_callback)

	-- main event loop
	log:info('Starting TCP Proxy')
	while mg.running() do		
		-- poll left interface
		local rx = lRXQueue:tryRecv(lRXBufs, 1)
		virtualDev:txBurst(lRXBufs, rx)
		
		-- poll right interface
		local rx = virtualDev:rxBurst(rRXBufs, 63)
		rRXBufs:resize(rx)
		lTXQueue:send(rRXBufs)

		lRXStats:update()
		lTXStats:update()
	end
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
