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

local hashMap 	= require "hashMap"

-- tcp SYN defense strategies
local cookie	= require "tcp/synCookie"
local infr		= require "tcp/synInfringement"

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
	
	log:info('Initialize KNI')
	kni.init(4)
	
	local lRXDev = device.config{ port = rxPort, txQueues=2 }
	local lTXDev = device.config{ port = txPort }
	--lRXDev:wait()
	--lTXDev:wait()
	mg.launchLua("tcpProxySlave", lRXDev, lTXDev)
	
	mg.waitForSlaves()
	
	log:info('Closing KNI')
	kni.close()
end


---------------------------------------------------
-- Constants
---------------------------------------------------

local LEFT_TO_RIGHT = cookie.LEFT_TO_RIGHT
local RIGHT_TO_LEFT = cookie.RIGHT_TO_LEFT


-----------------------------------------------------
-- profiling
-----------------------------------------------------

local profile_stats = {}

local function profile_callback(thread, samples, vmstate)
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


local function isIP4(pkt)
	return pkt.eth:getType() == proto.eth.TYPE_IP 
end

local function isTcp4(pkt)
	return isIP4(pkt) and pkt.ip4:getProtocol() == proto.ip4.PROTO_TCP
end

local function isSyn(pkt)
	return pkt.tcp:getSyn() == 1
end

local function isAck(pkt)
	return pkt.tcp:getAck() == 1
end

local function isRst(pkt)
	return pkt.tcp:getRst() == 1
end

local function isFin(pkt)
	return pkt.tcp:getFin() == 1
end


-------------------------------------------------------------------------------------------
---- Cookie
-------------------------------------------------------------------------------------------

local verifyCookie = cookie.verifyCookie


-------------------------------------------------------------------------------------------
---- State keeping
-------------------------------------------------------------------------------------------

local isVerifiedReset = cookie.isVerifiedReset
local isVerifiedIgnore = cookie.isVerifiedIgnore
local setVerifiedSequence = cookie.setVerifiedSequence
local isVerifiedSequence = cookie.isVerifiedSequence

local printVerifiedConnections = cookie.printVerifiedConnections


-------------------------------------------------------------------------------------------
---- Packet modification and crafting for cookie strategy
-------------------------------------------------------------------------------------------

local sequenceNumberTranslation = cookie.sequenceNumberTranslation
local createSynAckToClient = cookie.createSynAckToClient
local createSynToServer = cookie.createSynToServer
local createAckToServer = cookie.createAckToServer

-------------------------------------------------------------------------------------------
---- Packet modification and crafting for protocol violation strategies
-------------------------------------------------------------------------------------------

local forwardTraffic = infr.forwardTraffic
local createResponseIgnore = infr.createResponseIgnore
local createResponseReset = infr.createResponseReset
local createResponseSequence = infr.createResponseSequence


---------------------------------------------------
-- slave
---------------------------------------------------

local STRAT = {
	cookie 	= 1,
	ignore 	= 2,
	reset	= 3,
	sequence= 4,
}

function tcpProxySlave(lRXDev, lTXDev)
	log:setLevel("DEBUG")
	
	local currentStrat = STRAT['cookie']
	local maxBurstSize = 63

	-------------------------------------------------------------
	-- right/virtual interface
	-------------------------------------------------------------
	-- Create KNI device
	log:info('Creating virtual device')
	local virtualDevMemPool = memory.createMemPool{ n=8192 }
	local virtualDev = kni.createKni(0, lRXDev, virtualDevMemPool, "vEth0")
	log:info('Ifconfig virtual device')
	virtualDev:setIP("192.168.1.1", 24)

	log:info('ARP entry for client') -- TODO use ARP task
	io.popen("/usr/sbin/arp -s 192.168.1.101 90:e2:ba:98:58:78")

	-- not sure but without this it doesn't work
	for i = 0, 100 do
    	virtualDev:handleRequest()	
		mg.sleepMillisIdle(1)
	end

	log:info('Set default route')
	io.popen("ip r add default via 192.168.1.201")
	log:info('Set ARP for HTTP')
	io.popen("/usr/sbin/arp -s 192.168.1.101 90:e2:ba:98:58:78")
	log:info('Set ARP for DoS')
	io.popen("/usr/sbin/arp -s 192.168.1.201 90:e2:ba:98:58:79")
	
	-- RX buffers for right
	local rRXMem = memory.createMemPool()	
	local rRXBufs = rRXMem:bufArray()
	
	-- TX buffers 
	-- ack to right (on syn/ack from right)
	local numAck = 0
	local rTXAckMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
		}
	end)
	local rTXAckBufs = rTXAckMem:bufArray()
	
	-- right to left forward
	local lTXForwardQueue = lTXDev:getTxQueue(1)
	
	local numForward = 0
	local rTXForwardMem = memory.createMemPool()
	local rTXForwardBufs = rTXForwardMem:bufArray()


	-------------------------------------------------------------
	-- left/physical interface
	-------------------------------------------------------------
	lTXStats = stats:newDevTxCounter(lTXDev, "plain")
	lRXStats = stats:newDevRxCounter(lRXDev, "plain")
	
	-- RX buffers for left
	local lRXQueue = lRXDev:getRxQueue(0)
	local lRXMem = memory.createMemPool()	
	local lRXBufs = lRXMem:bufArray()

	-- TX buffers
	local lTXQueue = lTXDev:getTxQueue(0)

	-- buffer for cookie syn/ack to left
	local numSynAck = 0
	local lTXSynAckBufs = cookie.getSynAckBufs()
	
	-- buffer for cookie forwarding to right
	-- both for syn as well as all translated traffic
	local numForward = 0 
	local lTXForwardBufs = cookie.getForwardBufs()
	
	-- buffer for resets to left
	local numRst = 0
	local lTXRstBufs = infr.getRstBufs()
	
	-- buffer for sequence to left
	local numSeq = 0
	local lTXSeqBufs = infr.getSeqBufs()

	-- buffers for not TCP packets
	-- need to behandled separately as we cant just offload TCP checksums here
	-- its only a few packets anyway, so handle them separately
	local txNotTcpMem = memory.createMemPool()	
	local txNotTcpBufs = txNotTcpMem:bufArray(1)


	-------------------------------------------------------------
	-- Hash table
	-------------------------------------------------------------
	log:info("Creating hash table")


	-------------------------------------------------------------
	-- profiling
	-------------------------------------------------------------


	-------------------------------------------------------------
	-- main event loop
	-------------------------------------------------------------
	log:info('Starting TCP Proxy')
	while mg.running() do
		------------------------------------------------------------------- polling from left interface
		rx = lRXQueue:tryRecv(lRXBufs, 1)
		--log:debug('rx ' .. rx)
		if rx > 0 then
							lTXSynAckBufs:allocN(60, rx)
							--log:debug("alloc'd with i = " .. i)
			numSynAck = 0
		end
		for i = 1, rx do
			local lRXPkt = lRXBufs[i]:getTcp4Packet()
			if not isTcp4(lRXPkt) then
				--log:info('Sending packet that is not TCP from left')
			--------------------------------------------------------------- processing TCP
			else
					------------------------------------------------------------ SYN -> defense mechanism
					if isSyn(lRXPkt) then
						--log:info('Received SYN from left')
						-- strategy cookie

						numSynAck = numSynAck + 1
						local lTXPkt = lTXSynAckBufs[numSynAck]:getTcp4Packet()
						createSynAckToClient(lTXPkt, lRXPkt)
						
						--lTXSynAckBufs[numSynAck]:setSize(lRXBufs[i]:getSize())
						--log:debug(''..lRXBufs[i]:getSize())
					-------------------------------------------------------------------------------------------------------- verified -> translate and forward
					-- check with verified connections
					-- if already verified in both directions, immediately forward, otherwise check cookie
					end
			end
		end
		if rx > 0 then
				if numSynAck > 0 then
					-- send syn ack
					lTXSynAckBufs:offloadTcpChecksums(nil, nil, nil, numSynAck)
			
					lTXQueue:sendN(lTXSynAckBufs, numSynAck)

					lTXSynAckBufs:freeAfter(numSynAck)
				end
			
			-- no rx packets reused --> free
			lRXBufs:free(rx)
		end

		----------------------------- all actions by polling left interface done (also all buffers sent or cleared)

		lRXStats:update()
		lTXStats:update()
	end
	log:debug("*****************\n" .. tostring(sparseMapCookie))

	log:info('Releasing KNI device')
	virtualDev:release()
	
	lRXStats:finalize()
	lTXStats:finalize()

	profile.stop()

	print("Profiler results:")

	for i,v in pairs(profile_stats) do
		print( v .. " ::: " .. i)
	end

	log:info('Slave done')
end
