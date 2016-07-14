local dpdk		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log 		= require "log"

function master(txPorts, minIp, numIps, rate)
	if not txPorts then
		log:info("usage: txPort1[,txPort2[,...]] [minIP numIPs rate]")
		return
	end
	txPorts = tostring(txPorts)
	minIp = minIp or "10.0.0.1"
	numIps = numIps or 100
	rate = rate or 0
	for currentTxPort in txPorts:gmatch("(%d+),?") do
		currentTxPort = tonumber(currentTxPort) 
		local txDev = device.config{ port = currentTxPort }
		txDev:wait()
		txDev:getTxQueue(0):setRate(rate)
		dpdk.launchLua("loadSlave", currentTxPort, 0, minIp, numIps)
	end
	dpdk.waitForSlaves()
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
			ethDst="90:e2:ba:98:58:78",
			ethSrc="90:e2:ba:98:88:e9",
			ip4Dst="192.168.1.101", 
			ip4Src="192.168.1.1",
			tcpSrc="12345",
			tcpDst="80",
			tcpSyn=1,
			tcpAck=1,
			tcpSeqNumber=1431,
			tcpAckNumber=19089,
			tcpWindow=10,
			pktLength=54 }
	end)

	local bufs = mem:bufArray(3)
	local counter = 0
	local c = 0

	local txStats = stats:newDevTxCounter(queue, "plain")
	while dpdk.running() do
		-- fill packets and set their size 
		bufs:alloc(packetLen)
		for i, buf in ipairs(bufs) do 			
			-- dump first 3 packets
			if c < 3 then
				buf:dump()
				c = c + 1
			end
		end 
		--offload checksums to NIC
		bufs:offloadTcpChecksums(ipv4)
		
		queue:send(bufs)
		exit()
		txStats:update()
	end
	txStats:finalize()
end
