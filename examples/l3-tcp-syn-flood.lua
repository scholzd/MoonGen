local mg		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log 		= require "log"

function master(txPorts, rxPorts, minIp, numIps, rate)
	if not txPorts or not rxPorts then
		log:info("usage: txPort1[,txPort2[,...]] rxPort1[,rxPort2[,...]] [minIP numIPs rate]")
		return
	end
	txPorts = tostring(txPorts)
	rxPorts = tostring(rxPorts)
	minIp = minIp or "10.0.0.1"
	numIps = numIps or 100
	rate = rate or 0
	for currentTxPort in txPorts:gmatch("(%d+),?") do
		currentTxPort = tonumber(currentTxPort) 
		local txDev = device.config{ port = currentTxPort }
		txDev:wait()
		txDev:getTxQueue(0):setRate(rate)
		mg.launchLua("loadSlave", currentTxPort, 0, minIp, numIps)
	end
	for currentRxPort in rxPorts:gmatch("(%d+),?") do
		currentRxPort = tonumber(currentRxPort) 
		local rxDev = device.config{ port = currentRxPort }
		rxDev:wait()
		mg.launchLua("counterSlave", rxDev)
	end
	mg.waitForSlaves()
end

function counterSlave(dev)
	local bufs = memory.bufArray()
	rxStats = stats:newDevRxCounter(dev, "plain")

	while mg.running(1000) do
		local rx = dev:getRxQueue(0):recv(bufs)
		if rx > 0 then
			for buf in bufs do
				buf:dump()
			end
			bufs:freeAll()
		end
		rxStats:update()
	end
	rxStats:finalize()
end

function loadSlave(port, queue, minA, numIPs)
	--- parse and check ip addresses
	local minIP, ipv4 = parseIPAddress(minA)
	if minIP then
		log:info("Detected an %s address.", minIP and "IPv4" or "IPv6")
	else
		log:fatal("Invalid minIP: %s", minA)
	end

	-- min TCP packet size for IPv6 is 74 bytes (+ CRC)
	local packetLen = ipv4 and 60 or 74
	
	-- continue normally
	local queue = device.get(port):getTxQueue(queue)
	local mem = memory.createMemPool(function(buf)
		buf:getTcpPacket(ipv4):fill{ 
			ethSrc="90:e2:ba:98:58:78", ethDst="90:e2:ba:98:88:e8",
			ip4Dst="192.168.1.1", 
			ip6Dst="fd06::1",
			tcpSyn=1,
			tcpSeqNumber=1,
			tcpWindow=10,
			pktLength=packetLen }
	end)

	local bufs = mem:bufArray(128)
	local counter = 0
	local c = 0

	local txStats = stats:newDevTxCounter(queue, "plain")
	while mg.running() do
		-- fill packets and set their size 
		bufs:alloc(packetLen)
		for i, buf in ipairs(bufs) do 			
			local pkt = buf:getTcpPacket(ipv4)
			
			--increment IP
			if ipv4 then
				pkt.ip4.src:set(minIP)
				pkt.ip4.src:add(counter)
			else
				pkt.ip6.src:set(minIP)
				pkt.ip6.src:add(counter)
			end
			counter = incAndWrap(counter, numIPs)

			-- dump first 3 packets
			if c < 3 then
				buf:dump()
				c = c + 1
			end
		end 
		--offload checksums to NIC
		bufs:offloadTcpChecksums(ipv4)
		
		queue:send(bufs)
		txStats:update()
	end
	txStats:finalize()
end
