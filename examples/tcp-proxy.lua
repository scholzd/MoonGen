local mg		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log		= require "log"
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
	local sparseMapCookie = hashMap.createSparseHashMapCookie()


	-------------------------------------------------------------
	-- main event loop
	-------------------------------------------------------------
	log:info('Starting TCP Proxy')
	while mg.running() do
		------------------------------------------------------------------------------ poll right interface
		--log:debug('Polling right (virtual) Dev')
		-- for a real interface use tryRecv
		rx = virtualDev:recv(rRXBufs, 63)
		--log:debug(''..rx)
		if currentStrat == STRAT['cookie'] and rx > 0 then
			-- buffer for translated packets
			-- not cookie strategies forward all rx packets without touching them
			if not (currentStrat == STRAT['cookie']) then
				rTXForwardBufs:allocN(60, rx)
			end
			numForward = 0
			
			numAck = 0
		end
		for i = 1, rx do
			local rRXPkt = rRXBufs[i]:getTcp4Packet()
			if not isTcp4(rRXPkt) then
				--log:info('Sending packet that is not TCP from right')
				txNotTcpBufs:alloc(60)
				forwardTraffic(txNotTcpBufs[1], rRXBufs[i])
				lTXQueue:sendN(txNotTcpBufs, 1)
			else
				---------------------------------------------------------------------- process TCP
				-- handle protocol infiringement strategies
				if not (currentStrat == STRAT['cookie']) then
					-- in all cases, we simply forward whatever we get from right
					--log:debug('doing nothing')
				-- strategie cookie
				else
					---------------------------------------------------------------------- SYN/ACK from server, finally establish connection
					if isSyn(rRXPkt) and isAck(rRXPkt) then
						--log:debug('Received SYN/ACK from server, sending ACK back')
						sparseMapCookie:setRightVerified(rRXPkt)
						
						if numAck == 0 then
							rTXAckBufs:allocN(60, rx - (i - 1))
						end
						
						numAck = numAck + 1
						createAckToServer(rTXAckBufs[numAck], rRXBufs[i], rRXPkt)
					----------------------------------------------------------------------- any verified packet from server
					else
						local diff = sparseMapCookie:isVerified(rRXPkt, RIGHT_TO_LEFT) 
						if diff then
							-- anything else must be from a verified connection, translate and send via physical nic
							--log:info('Packet of verified connection from server, translate and forward')
							if numForward == 0 then
								rTXForwardBufs:allocN(60, rx - (i - 1))
							end
								
							numForward = numForward + 1
							local rTXForwardBuf = rTXForwardBufs[numForward]
							local rTXPkt = rTXForwardBuf:getTcp4Packet()

							sequenceNumberTranslation(diff, rRXBufs[i], rTXForwardBuf, rRXPkt, rTXPkt, RIGHT_TO_LEFT)
						------------------------------------------------------------------------ not verified connection from server
						else
							--log:debug('Packet of not verified connection from right')
						end
					end
				end
			end
		end
		
		if currentStrat == STRAT['cookie'] then
			if rx > 0 then	
				--offload checksums to NIC
				--log:debug('Offloading ' .. rx)
				--lTX2Bufs:offloadTcpChecksums(nil, nil, nil, rx)
				--log:debug('rx ' .. rx .. ' numTX2 ' .. numTX2)
		
				-- forwarded to left
				if numForward > 0 then
					lTXForwardQueue:sendN(rTXForwardBufs, numForward)
					rTXForwardBufs:freeAfter(numForward)
				end

				-- ack to right
				if numAck > 0 then
					virtualDev:sendN(rTXAckBufs, numAck)
					rTXAckBufs:freeAfter(numAck)
				end
			end
			--log:debug('free rRX')
			rRXBufs:freeAll()
		-- protocol infringements: simply send every received packet
		elseif rx > 0 then
			-- send all buffers, untouched
			lTXQueue:sendN(rRXBufs, rx)
		end

		------------------------------------------------------------------- polling from right interface done

		------------------------------------------------------------------- polling from left interface
		rx = lRXQueue:tryRecv(lRXBufs, 1)
		--log:debug('rx ' .. rx)
		if rx > 0 then
			if currentStrat == STRAT['cookie'] then
				numSynAck = 0
			elseif currentStrat == STRAT['ignore'] then
				-- nothing
			elseif currentStrat == STRAT['reset'] then
				lTXRstBufs:allocN(60, rx)
				numRst = 0
			elseif currentStrat == STRAT['sequence'] then
				lTXSeqBufs:allocN(60, rx)
				numSeq = 0
			end

			-- every strategy needs buffers to simply forward packets left to right
			numForward = 0
		end
		for i = 1, rx do
			local lRXPkt = lRXBufs[i]:getTcp4Packet()
			if not isTcp4(lRXPkt) then
				--log:info('Sending packet that is not TCP from left')
				txNotTcpBufs:alloc(60)
				forwardTraffic(txNotTcpBufs[1], lRXBufs[i])
				virtualDev:sendN(txNotTcpBufs, 1)
			--------------------------------------------------------------- processing TCP
			else
				-- here the reaction always depends on the strategy
				if currentStrat == STRAT['ignore'] then
					-- do nothing on unverified SYN
					if isSyn(lRXPkt) and not isVerifiedIgnore(lRXPkt) then
						-- do nothing
						createResponseIgnore()
					else
						-- everything else simply forward
						if numForward == 0 then
							lTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForward = numForward + 1
						forwardTraffic(lTXForwardBufs[numForward], lRXBufs[i])
					end
				elseif currentStrat == STRAT['reset'] then
					-- send RST on unverified SYN
					if isSyn(lRXPkt) and not isVerifiedReset(lRXPkt) then
						-- create and send RST packet
						numRst = numRst + 1
						createResponseReset(lTXRstBufs[numRst], lRXPkt)
					else
						-- everything else simply forward
						if numForward == 0 then
							lTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForward = numForward + 1
						forwardTraffic(lTXForwardBufs[numForward], lRXBufs[i])
					end
				elseif currentStrat == STRAT['sequence'] then
					-- send wrong sequence number on unverified SYN
					if isSyn(lRXPkt) and not isVerifiedSequence(lRXPkt) then
						-- create and send packet with wrong sequence
						numSeq = numSeq + 1
						createResponseSequence(lTXSeqBufs[numSeq], lRXPkt)
					elseif isRst(lRXPkt) and not isVerifiedSequence(lRXPkt) then
						setVerifiedSequence(lRXPkt)
						-- do nothing with RX packet
					else
						-- everything else simply forward
						if numForward == 0 then
							lTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForward = numForward + 1
						forwardTraffic(lTXForwardBufs[numForward], lRXBufs[i])
					end
				elseif currentStrat == STRAT['cookie'] then
					------------------------------------------------------------ SYN -> defense mechanism
					if isSyn(lRXPkt) then
						--log:info('Received SYN from left')
						-- strategy cookie
						if numSynAck == 0 then
							lTXSynAckBufs:allocN(60, rx - (i - 1))
							--log:debug("alloc'd with i = " .. i)
						end
						numSynAck = numSynAck + 1
						local lTXPkt = lTXSynAckBufs[numSynAck]:getTcp4Packet()
						createSynAckToClient(lTXPkt, lRXPkt)
						
						lTXSynAckBufs[numSynAck]:setSize(lRXBufs[i]:getSize())
						--log:debug(''..lRXBufs[i]:getSize())
					-------------------------------------------------------------------------------------------------------- verified -> translate and forward
					-- check with verified connections
					-- if already verified in both directions, immediately forward, otherwise check cookie
					else
						local diff = sparseMapCookie:isVerified(lRXPkt, LEFT_TO_RIGHT) 
						if diff then 
							--log:info('Received packet of verified connection from left, translating and forwarding')
							if numForward == 0 then
								lTXForwardBufs:allocN(60, rx - (i - 1))
							end
							numForward = numForward + 1
							sequenceNumberTranslation(diff, lRXBufs[i], lTXForwardBufs[numForward], lRXPkt, lTXForwardBufs[numForward]:getTcp4Packet(), LEFT_TO_RIGHT)
						------------------------------------------------------------------------------------------------------- not verified, but is ack -> verify cookie
						elseif isAck(lRXPkt) then
							local ack = lRXPkt.tcp:getAckNumber()
							local mss = verifyCookie(lRXPkt)
							if mss then
								--log:info('Received valid cookie from left, starting handshake with server')
								
								sparseMapCookie:setLeftVerified(lRXPkt)
								-- connection is left verified, start handshake with right
								if numForward == 0 then
									lTXForwardBufs:allocN(60, rx - (i - 1))
									--log:debug("alloc'd with i = " .. i)
								end
								numForward = numForward + 1
								createSynToServer(lTXForwardBufs[numForward], lRXBufs[i])
							else
								log:warn('Wrong cookie, dropping packet ')
								-- drop, and done
								-- most likely simply the timestamp timed out
								-- but it might also be a DoS attack that tried to guess the cookie
							end
						----------------------------------------------------------------------------------------------- unverified, but not syn/ack -> ignore
						else
							-- not syn, unverified tcp packets -> belongs to already deleted connection -> drop
							--log:error('unhandled packet ' .. tostring(isVerified(lRXPkt, LEFT_TO_RIGHT)))
						end
					end
				end
			end
		end
		if rx > 0 then
			-- strategy specific responses
			if currentStrat == STRAT['cookie'] then	
				if numSynAck > 0 then
					-- send syn ack
					lTXSynAckBufs:offloadTcpChecksums(nil, nil, nil, numSynAck)
			
					lTXQueue:sendN(lTXSynAckBufs, numSynAck)

					lTXSynAckBufs:freeAfter(numSynAck)
				end
			elseif currentStrat == STRAT['ignore'] then	
				-- send no response nothing
			elseif currentStrat == STRAT['reset'] then	
				-- send rst packets
				lTXRstBufs:offloadTcpChecksums(nil, nil, nil, numRst)
				lTXQueue:sendN(lTXRstBufs, numRst)
			elseif currentStrat == STRAT['sequence'] then	
				-- send packets with wrong ack number
				lTXSeqBufs:offloadTcpChecksums(nil, nil, nil, numSeq)
				lTXQueue:sendN(lTXSeqBufs, numSeq)
			end
			-- all strategies
			-- send forwarded packets and free unused buffers
			if numForward > 0 then
				virtualDev:sendN(lTXForwardBufs, numForward)
				lTXForwardBufs:freeAfter(numForward)
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

	log:info('Slave done')
end
