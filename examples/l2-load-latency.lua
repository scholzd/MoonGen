local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local ts     = require "timestamping"
local stats  = require "stats"
local hist   = require "histogram"

local BASE_MAC	= parseMacAddress("11:12:13:14:15:16", true)

local function getRstFile(...)
	local args = { ... }
	for i, v in ipairs(args) do
		result, count = string.gsub(v, "%-%-result%=", "")
		if (count == 1) then
			return i, result
		end
	end
	return nil, nil
end

function configure(parser)
	parser:description("Generates bidirectional CBR traffic with hardware rate control and measure latencies.")
	parser:argument("dev1", "Device to transmit/receive from."):convert(tonumber)
	parser:argument("dev2", "Device to transmit/receive from."):convert(tonumber)
	parser:option("-r --rate", "Transmit rate in Mbit/s."):default(10000):convert(tonumber)
	parser:option("-f --file", "Filename of the latency histogram."):default("histogram.csv")
	parser:option("-s --size", "Packet size."):default(60):convert(tonumber)
	parser:option("-m --macs", "Number of different MAC addresses."):default(2):convert(tonumber)
end

function master(args)
	local dev1 = device.config({port = args.dev1, rxQueues = 2, txQueues = 2})
	local dev2 = device.config({port = args.dev2, rxQueues = 2, txQueues = 2})
	device.waitForLinks()
	dev1:getTxQueue(0):setRate(args.rate)
	dev2:getTxQueue(0):setRate(args.rate)
	mg.startTask("loadSlave", dev1:getTxQueue(0), args.size, args.macs)
	if dev1 ~= dev2 then
		mg.startTask("loadSlave", dev2:getTxQueue(0), args.size, args.macs)
	end
	mg.startTask("dumpSlave", dev1:getRxQueue(0))
	stats.startStatsTask{dev1, dev2}
	mg.startSharedTask("timerSlave", dev1:getTxQueue(1), dev2:getRxQueue(1), args.file)
	mg.waitForTasks()
end

function loadSlave(queue, size, macs)
	local mem = memory.createMemPool(function(buf)
		buf:getEthernetPacket():fill{
			ethSrc = BASE_MAC,
			ethDst = BASE_MAC,
			ethType = 0x1234
		}
	end)
	local bufs = mem:bufArray()
	local counter = 0
	while mg.running() do
		bufs:alloc(size)
		for i, buf in ipairs(bufs) do 			
			local pkt = buf:getEthernetPacket()
			pkt.eth:setSrc(BASE_MAC + counter)
			pkt.eth:setDst(BASE_MAC + (macs - 1) - counter)

			counter = incAndWrap(counter, macs)
		end

		queue:send(bufs)
	end
end

function timerSlave(txQueue, rxQueue, histfile)
	local timestamper = ts:newTimestamper(txQueue, rxQueue)
	local hist = hist:new()
	mg.sleepMillis(1000) -- ensure that the load task is running
	while mg.running() do
		hist:update(timestamper:measureLatency(function(buf) buf:getEthernetPacket().eth.dst:set(BASE_MAC) end))
	end
	hist:print()
	hist:save(histfile)
end

function dumpSlave(queue)
	local bufs = memory.bufArray()
	local num = 5
	local count = 0
	while mg.running() do
		local rx = queue:tryRecv(bufs, 100)
		for i = 1, rx do
			local buf = bufs[i]
			buf:dump()
			count = count + 1
			if count > num then
				return
			end
		end
		bufs:free(rx)
	end
end

