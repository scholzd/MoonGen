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
	local maxIP = parseIP4Address("126.255.255.255")
	local minPort = 1024
	local maxPort = 49151

	local packetLen = 74
	
	-- continue normally
	local queue = device.get(port):getTxQueue(queue)
	local mem = memory.createMemPool(function(buf)
		local pkt = buf:getTcpPacket(ipv4)
		pkt:fill{ 
			ethSrc="90:e2:ba:98:58:79", ethDst="90:e2:ba:98:88:e9",
			ip4Dst="192.168.1.1", 
			ip4Flags=2, 
			tcpDst=80,
			tcpSyn=1,
			tcpSeqNumber=1,
			tcpWindow=29200,
			pktLength=packetLen }
		-- tcp options
        local offset = 0
        -- MSS option
        pkt.payload.uint8[0] = 2 -- MSS option type
        pkt.payload.uint8[1] = 4 -- MSS option length (4 bytes)
        pkt.payload.uint16[1] = hton16(1460) -- MSS option
        offset = offset + 4

        -- ts option
        pkt.payload.uint8[offset] = 8 -- ts option type
        pkt.payload.uint8[offset + 1] = 10 -- ts option length (2 bytes)
        pkt.payload.uint8[offset + 2] = 500 -- ts option tsval
        pkt.payload.uint8[offset + 3] = 400 -- ts option tsval
        pkt.payload.uint8[offset + 4] = 900 -- ts option tsval
        pkt.payload.uint8[offset + 5] = 700 -- ts option tsval
        pkt.payload.uint8[offset + 6] = 0 -- ts option ecr
        pkt.payload.uint8[offset + 7] = 0 -- ts option ecr
        pkt.payload.uint8[offset + 8] = 0 -- ts option ecr
        pkt.payload.uint8[offset + 9] = 0 -- ts option ecr
        offset = offset + 10

        -- window scale option
        pkt.payload.uint8[offset] = 3 -- WSOPT option type
        pkt.payload.uint8[offset + 1] = 3 -- WSOPT option length (3 bytes)
        pkt.payload.uint8[offset + 2] = 7 -- WSOPT option
        offset = offset + 3

        -- determine if and how much padding is needed
        local pad = 4 - (offset % 4)
        if pad == 4 then
            pad = 0
        end
        if pad > 0 then
            pkt.payload.uint8[offset + pad - 1] = 0 -- eop
            for i = pad - 2, 0, -1 do
                pkt.payload.uint8[offset + i] = 1 -- padding
            end
        end
        -- calculate size and dataOffset values
        offset = offset + pad
        local size = 54 + offset -- minimum sized ip4/tcp packet with tcp options
        local dataOffset = 5 + (offset / 4)

        pkt.tcp:setDataOffset(dataOffset)
        pkt:setLength(size)
        if size < 60 then
            size = 60
        end
        buf:setSize(size)

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
