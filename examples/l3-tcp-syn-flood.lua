local mg		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log 		= require "log"

function master(txPorts, rxPorts, rate)
	if not txPorts or not rxPorts then
		log:info("usage: txPort1[,txPort2[,...]] rxPort1[,rxPort2[,...]] [rate]")
		return
	end
	txPorts = tostring(txPorts)
	rxPorts = tostring(rxPorts)
	rate = rate or 0
	for currentTxPort in txPorts:gmatch("(%d+),?") do
		currentTxPort = tonumber(currentTxPort) 
		local txDev = device.config{ port = currentTxPort }
		txDev:wait()
		txDev:getTxQueue(0):setRate(rate)
		mg.launchLua("loadSlave", currentTxPort, 0)
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
			bufs:freeAll()
		end
		rxStats:update()
	end
	rxStats:finalize()
end

function loadSlave(port, queue)
	local minIP = parseIP4Address("11.0.0.0")
	local maxIP = parseIP4Address("11.0.0.0")--26.255.255.255")
	local minPort = 1024
	local maxPort = 49151

	local packetLen = 60
	
	-- continue normally
	local queue = device.get(port):getTxQueue(queue)
	local mem = memory.createMemPool(function(buf)
		buf:getTcpPacket(ipv4):fill{ 
			ethSrc="90:e2:ba:98:58:79", ethDst="90:e2:ba:98:88:e9",
			ip4Dst="192.168.1.1", 
			tcpDst=80,
			tcpSyn=1,
			tcpSeqNumber=1,
			pktLength=packetLen }
	end)

	local bufs = mem:bufArray(128)
	local c = 0

	local txStats = stats:newDevTxCounter(queue, "plain")
	while mg.running() do
		-- fill packets and set their size 
		bufs:alloc(packetLen)
		for i, buf in ipairs(bufs) do 			
			local pkt = buf:getTcpPacket(ipv4)
			pkt.ip4.src:set(math.random(minIP, maxIP))
			pkt.tcp:setSrcPort(math.random(minPort, maxPort))		

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
