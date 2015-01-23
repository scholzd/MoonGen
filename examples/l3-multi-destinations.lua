local dpdk	= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local ts	= require "timestamping"
local dpdkc	= require "dpdkc"
local filter	= require "filter"
local utils 	= require "utils"
local headers	= require "headers"
local packet	= require "packet"

local ffi	= require "ffi"

function master(...)
	--parse args
	local txPort = tonumber((select(1, ...)))
	local minIP = select(2, ...)
	local numIPs = tonumber((select(3, ...)))
	local rate = tonumber(select(4, ...))
	
	if not txPort or not minIP or not numIPs or not rate then
		printf("usage: txPort minIP numIPs rate")
		return
	end

	local rxMempool = memory.createMemPool()
	local txDev = device.config(txPort, rxMempool, 2, 2)
	txDev:wait()
	txDev:getTxQueue(0):setRate(rate)
	dpdk.launchLua("loadSlave", txPort, 0, minIP, numIPs)
	dpdk.waitForSlaves()
end

function loadSlave(port, queue, minA, numIPs)
	--- parse and check ip addresses
	-- min UDP packet size for IPv6 is 66 bytes
	-- 4 bytes subtracted as the CRC gets appended by the NIC
	local packetLen = 66 - 4
	local ipv4 = true
	local minIP

	-- first check if its an ipv4 address
	minIP = parseIP4Address(minA)

	if minIP == nil then
		printf("Address is not IPv4, checking for IPv6...")
		ipv4 = false
	end

	-- if not an ipv4 address, check if its ipv6
	if not ipv4 then
		minIP = parseIP6Address(minA)
		
		if minIP == nil then
			printf("Address is not IPv6, stopping now.")
			return
		end
	end

	--continue normally
	local queue = device.get(port):getTxQueue(queue)
	local mem = memory.createMemPool(function(buf)
		local pkt
		if ipv4 then
			pkt = buf:getUDPPacket()
		else 
			pkt = buf:getUDP6Packet()
		end

		pkt:fill{ ethSrc="90:e2:ba:2c:cb:02", ethDst="90:e2:ba:35:b5:81", 
--				  ipSrc="192.168.1.1", 
--				  ip6Src="fd06:0000:0000:0001::1",
				  ipDst="10.0.0.2",
				  ip6Dst="fd06::2",
				  pktLength=packetLen }
	end)

	local lastPrint = dpdk.getTime()
	local totalSent = 0
	local lastTotal = 0
	local lastSent = 0
	local bufs = mem:bufArray(128)
	local counter = 0
	local c = 0

	print("Start sending...")
	while dpdk.running() do
		-- fill packets and set their size 
		bufs:fill(packetLen)
		for i, buf in ipairs(bufs) do 			
			local pkt
			if ipv4 then
				pkt = buf:getUDPPacket()
			else
				pkt = buf:getUDP6Packet()
			end
			
			--increment IP
			pkt.ip.src:set(minIP)
			pkt.ip.src:add(counter)
			if numIPs <= 32 then
				counter = (counter + 1) % numIPs
			else 
				counter = counter == numIPs and 0 or counter + 1
			end

			-- dump first 3 packets
			if c < 3 then
				buf:dump()
				c = c + 1
			end
		end 
		--offload checksums to NIC
		bufs:offloadUdpChecksums(ipv4)
		
		totalSent = totalSent + queue:send(bufs)
		local time = dpdk.getTime()
		if time - lastPrint > 0.1 then 	--counter frequency
			local mpps = (totalSent - lastTotal) / (time - lastPrint) / 10^6
			printf("%.5f %d", time - lastPrint, totalSent - lastTotal)	-- packet_counter-like output
			--printf("Sent %d packets, current rate %.2f Mpps, %.2f MBit/s, %.2f MBit/s wire rate", totalSent, mpps, mpps * 64 * 8, mpps * 84 * 8)
			lastTotal = totalSent
			lastPrint = time
		end
	end
	printf("Sent %d packets", totalSent)
end


