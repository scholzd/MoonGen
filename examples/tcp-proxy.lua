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

-- tcp SYN defense strategies
local cookie	= require "tcp/cookie"

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
	
	local lRXDev = device.config{ port = rxPort, txQueues=2 }
	local lTXDev = device.config{ port = txPort }
	lRXDev:wait()
	lTXDev:wait()
	mg.launchLua("tcpProxySlave", lRXDev, lTXDev)
	
	mg.waitForSlaves()
end


---------------------------------------------------
-- Terminology
---------------------------------------------------

-- left: outside, internet, clients, potential attackers, whatever
-- right: "protected" side, connection to server(s), only filtered traffic comes here


---------------------------------------------------
-- Constants
---------------------------------------------------

local LEFT_TO_RIGHT = cookie.LEFT_TO_RIGHT
local RIGHT_TO_LEFT = cookie.RIGHT_TO_LEFT


-----------------------------------------------------
-- debug utility 
-----------------------------------------------------

-- print table of string -> string
local function sT(t)
	local str = ''
	for k, v in pairs(t) do
		str = str .. ', ' .. k .. ' -> ' .. v
	end
	return str
end


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

local function printChecks(pkt)
	print('Is IP4 ' .. tostring(isIP4(pkt)))
	print('Is TCP ' .. tostring(isTcp4(pkt)))
	print('Is SYN ' .. tostring(isSyn(pkt)))
	print('Is ACK ' .. tostring(isAck(pkt)))
end


-------------------------------------------------------------------------------------------
---- Cookie
-------------------------------------------------------------------------------------------

local calculateCookie = cookie.calculateCookie

local verifyCookie = cookie.verifyCookie

-------------------------------------------------------------------------------------------
---- State keeping
-------------------------------------------------------------------------------------------

local getIdx = cookie.getIdx

local setLeftVerified = cookie.setLeftVerified

local setRightVerified = cookie.setRightVerified

local setFin = cookie.setFin

local setRst = cookie.setRst

local isVerified = cookie.isVerified

--local isVerifiedReset = infr.isVerifiedReset
--
--local isVerifiedIgnore = infr.isVerifiedIgnore
--
--local setVerifiedSequence = infr.setVerifiedSequence
--
--local isVerifiedSequence = infr.isVerifiedSequence

local printVerifiedConnections = cookie.printVerifiedConnections


-------------------------------------------------------------------------------------------
---- Packet modification and crafting for cookie strategy
-------------------------------------------------------------------------------------------

local sequenceNumberTranslation = cookie.sequenceNumberTranslation

local function createSynToServer(txBuf, rxBuf)
	-- set size of tx packet
	local size = rxBuf:getSize()
	txBuf:setSize(size)
	
	-- copy data
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	
	-- adjust some members: sequency number, flags, checksum, length fields
	local txPkt = txBuf:getTcp4Packet()
	-- reduce seq num by 1 as during handshake it will be increased by 1 (in SYN/ACK)
	-- this way, it does not have to be translated at all
	txPkt.tcp:setSeqNumber(txPkt.tcp:getSeqNumber() - 1)
	txPkt.tcp:setSyn()
	txPkt.tcp:unsetAck()

	txPkt:setLength(size)

	-- calculate checksums
	txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	txPkt.ip4:calculateChecksum()

end

local function createAckToServer(txBuf, rxBuf, rxPkt)
	-- set size of tx packet
	local size = rxBuf:getSize()
	txBuf:setSize(size)
	
	-- copy data TODO directly use rx buffer
	--log:debug('copy data')
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	
	-- send packet back with seq, ack + 1
	local txPkt = txBuf:getTcp4Packet()

	-- mac addresses (FIXME does not work with KNI)
	-- I can put any addresses in here (NULL, BROADCASTR, ...), 
	-- but as soon as I use the right ones it doesn't work any longer
	--local tmp = rxPkt.eth:getSrc()
	--txPkt.eth:setSrc(rxPkt.eth:getDst())
	--txPkt.eth:setDst(tmp)

	
	-- ip addresses
	local tmp = rxPkt.ip4:getSrc()
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	txPkt.ip4:setDst(tmp)

	-- tcp ports
	tmp = rxPkt.tcp:getSrc()
	txPkt.tcp:setSrc(rxPkt.tcp:getDst())
	txPkt.tcp:setDst(tmp)

	txPkt.tcp:setSeqNumber(rxPkt.tcp:getAckNumber())
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)
	txPkt.tcp:unsetSyn()
	txPkt.tcp:setAck()
	
	txPkt:setLength(size)

	-- calculate checksums
	txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	txPkt.ip4:calculateChecksum()
end

local function createSynAckToClient(txPkt, rxPkt)
	local cookie, mss = calculateCookie(rxPkt)
	
	-- MAC addresses
	txPkt.eth:setDst(rxPkt.eth:getSrc())
	txPkt.eth:setSrc(rxPkt.eth:getDst())

	-- IP addresses
	txPkt.ip4:setDst(rxPkt.ip4:getSrc())
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	
	-- TCP
	txPkt.tcp:setDst(rxPkt.tcp:getSrc())
	txPkt.tcp:setSrc(rxPkt.tcp:getDst())
	
	txPkt.tcp:setSeqNumber(cookie)
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)
	txPkt.tcp:setWindow(mss)
end

-------------------------------------------------------------------------------------------
---- Packet modification and crafting for protocol violation strategies
-------------------------------------------------------------------------------------------

local function forwardTraffic(vDev, txBufs, rxBuf)
	--log:debug('alloc txBufs')
	txBufs:alloc(60)
	local txBuf = txBufs[1]
	
	-- set size of tx packet
	local size = rxBuf:getSize()
	txBuf:setSize(size)
	
	-- copy data 
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	vDev:txSingle(txBuf)
	
	-- invalidate rx packet
	rxBuf:setSize(1)
end

local function createResponseIgnore(txBuf, rxPkt)
	-- yep, nothing
end

local function createResponseReset(txBuf, rxPkt)
	--log:debug('Crafting rst')
	local txPkt = txBuf:getTcp4Packet()
	
	txPkt.eth:setSrc(rxPkt.eth:getDst())
	txPkt.eth:setDst(rxPkt.eth:getSrc())

	-- IP addresses
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	txPkt.ip4:setDst(rxPkt.ip4:getSrc())
	
	-- TCP
	txPkt.tcp:setSrc(rxPkt.tcp:getDst())
	txPkt.tcp:setDst(rxPkt.tcp:getSrc())

	
	-- alternative approach: reuse rx buffer (saves alloc and free, but more members to set)
	-- TODO check whats better under load
	-- MAC addresses
	--local tmp = lRXPkt.eth:getSrc()
	--lRXPkt.eth:setSrc(lRXPkt.eth:getDst())
	--lRXPkt.eth:setDst(tmp)

	---- IP addresses
	--tmp = lRXPkt.ip4:getSrc()
	--lRXPkt.ip4:setSrc(lRXPkt.ip4:getDst())
	--lRXPkt.ip4:setDst(tmp)
	--
	---- TCP
	--tmp = lRXPkt.tcp:getSrc()
	--lRXPkt.tcp:setSrc(lRXPkt.tcp:getDst())
	--lRXPkt.tcp:setDst(tmp)
	--
	--lRXPkt.tcp:unsetSyn()
	--lRXPkt.tcp:setRst()
end

local function createResponseSequence(txBuf, rxPkt)
	--log:debug('crafting seq vio')
	local txPkt = txBuf:getTcp4Packet()
	
	txPkt.eth:setSrc(rxPkt.eth:getDst())
	txPkt.eth:setDst(rxPkt.eth:getSrc())

	-- IP addresses
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	txPkt.ip4:setDst(rxPkt.ip4:getSrc())
	
	-- TCP
	txPkt.tcp:setSrc(rxPkt.tcp:getDst())
	txPkt.tcp:setDst(rxPkt.tcp:getSrc())

	-- set violating ack number
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() - 1) -- violation => AckNumber != SeqNumber + 1

	-- alternative approach: reuse rx buffer (saves alloc and free, but more members to set)
	-- TODO check whats better under load
	-- reuse RX buffer
	-- MAC addresses
	--local tmp = lRXPkt.eth:getSrc()
	--lRXPkt.eth:setSrc(lRXPkt.eth:getDst())
	--lRXPkt.eth:setDst(tmp)

	---- IP addresses
	--tmp = lRXPkt.ip4:getSrc()
	--lRXPkt.ip4:setSrc(lRXPkt.ip4:getDst())
	--lRXPkt.ip4:setDst(tmp)
	--
	---- TCP
	--tmp = lRXPkt.tcp:getSrc()
	--lRXPkt.tcp:setSrc(lRXPkt.tcp:getDst())
	--lRXPkt.tcp:setDst(tmp)
	--
	--lRXPkt.tcp:setAckNumber(lRXPkt.tcp:getSeqNumber() - 1) -- violation => AckNumber != SeqNumber + 1
	--lRXPkt.tcp:setSeqNumber(42)
	--lRXPkt.tcp:setAck()
end


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
	log:info('Initialize KNI')
	kni.init(4)
	log:info('Creating virtual device')
	local virtualDevMemPool = memory.createMemPool{ n=8192 }
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
	local lTXMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpAck=1,
			tcpSyn=1,
			tcpWindow=50,
			pktLength=60,
		}
	end)
	local lTXSynAckBufs = lTXMem:bufArray()
	
	-- buffer for cookie forwarding to right
	-- both for syn as well as all translated traffic
	local numForward = 0 
	local lTXForwardMem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpSyn=1,
			pktLength=60,
		}
	end)
	local lTXForwardBufs = lTXForwardMem:bufArray()
	
	-- buffer for resets to left
	local lTXRstMem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=0,
			tcpAckNumber=0,
			tcpRst=1,
			pktLength=60,
		}
	end)
	local lTXRstBufs = lTXRstMem:bufArray()
	
	-- buffer for sequence to left
	local lTXSeqMem = memory.createMemPool(function(buf)
		local pkt = buf:getTcp4Packet():fill{
			ethSrc=proto.eth.NULL,
			ethDst=proto.eth.NULL,
			ip4Src=proto.ip4.NULL,
			ip4Dst=proto.ip4.NULL,
			tcpSrc=0,
			tcpDst=0,
			tcpSeqNumber=42, -- randomly chosen
			tcpAckNumber=0,  -- set depending on RX
			tcpSyn=1,
			tcpAck=1,
			pktLength=60,
		}
	end)
	local lTXSeqBufs = lTXSeqMem:bufArray()
	

	-------------------------------------------------------------
	-- profiling
	-------------------------------------------------------------
	profile.start("l", profile_callback)


	-------------------------------------------------------------
	-- main event loop
	-------------------------------------------------------------
	log:info('Starting TCP Proxy')
	while mg.running() do
		------------------------------------------------------------------------------ poll right interface
		--log:debug('Polling right (virtual) Dev')
		rx = virtualDev:rxBurst(rRXBufs, 63)
		--log:debug(''..rx)
		if currentStrat == STRAT['cookie'] and rx > 0 then
			-- buffer for translated packets
			rTXForwardBufs:allocN(60, rx)
			numForward = 0
			
			rTXAckBufs:allocN(60, rx)
			numAck = 0
		end
		for i = 1, rx do
			local translate = false
			
			local rRXPkt = rRXBufs[i]:getTcp4Packet()
			if not isTcp4(rRXPkt) then
				--log:info('Ignoring rRX packet from server that is not TCP')
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
						setRightVerified(rRXPkt)
						
						-- send ACK to server
						--rTXBufs:alloc(70)
						--local rTXBuf = rTXBufs[1]
						--createAckToServer(rTXBuf, rRXBufs[i], rRXPkt)
						--
						---- done, sending
						----log:debug('Sending rTXBuf via KNI')
						--virtualDev:txSingle(rTXBuf)

						numAck = numAck + 1
						createAckToServer(rTXAckBufs[numAck], rRXBufs[i], rRXPkt)
					----------------------------------------------------------------------- any verified packet from server
					elseif isVerified(rRXPkt, RIGHT_TO_LEFT) then
						-- anything else must be from a verified connection, translate and send via physical nic
						--log:info('Packet of verified connection from server, translate and forward')
						local idx = getIdx(rRXPkt, RIGHT_TO_LEFT)
						if isRst(rRXPkt) then -- TODO move to bottom
							--log:debug('Got RST packet from right ' .. idx)
							setRst(rRXPkt, RIGHT_TO_LEFT)
						elseif isFin(rRXPkt) then
							--log:debug('Got FIN packet from right ' .. idx)
							setFin(rRXPkt, RIGHT_TO_LEFT)
						end
						translate = true
					------------------------------------------------------------------------ not verified connection from server
					else
						--log:debug('Packet of not verified connection from right')
					end
				end
			end
			if translate then
				--log:info('Translating from right to left')
			
				--lTX2Bufs:alloc(70)
				numForward = numForward + 1
				local rTXForwardBuf = rTXForwardBufs[numForward]
				local rTXPkt = rTXForwardBuf:getTcp4Packet()

				sequenceNumberTranslation(rRXBufs[i], rTXForwardBuf, rRXPkt, rTXPkt, RIGHT_TO_LEFT)
			else
				--lTX2Bufs[i]:getTcp4Packet().eth:setType(0)
				--lTX2Bufs[i]:dump()
			end
		end
		
		if currentStrat == STRAT['cookie'] then
			if rx > 0 then	
				--offload checksums to NIC
				--log:debug('Offloading ' .. rx)
				--lTX2Bufs:offloadTcpChecksums(nil, nil, nil, rx)
				--log:debug('rx ' .. rx .. ' numTX2 ' .. numTX2)
		
				-- forwarded to left
				lTXForwardQueue:sendN(rTXForwardBufs, numForward)
				rTXForwardBufs:freeAfter(numForward)
				
				-- ack to right
				virtualDev:txBurst(rTXAckBufs, numAck)
				rTXAckBufs:freeAfter(numAck)
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
				lTXSynAckBufs:allocN(60, rx)
				lTXForwardBufs:allocN(60, rx)
				numSynAck = 0
				numForward = 0
			elseif currentStrat == STRAT['ignore'] then
				-- nothing
			elseif currentStrat == STRAT['reset'] then
				lTXRstBufs:allocN(60, rx)
			elseif currentStrat == STRAT['sequence'] then
				lTXSeqBufs:allocN(60, rx)
			end
		end
		for i = 1, rx do
			local translate = false
			
			local lRXPkt = lRXBufs[i]:getTcp4Packet()
			if not isTcp4(lRXPkt) then
				--log:info('Ignoring packet that is not TCP from left')
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
						forwardTraffic(virtualDev, rTXBufs, lRXBufs[i])
					end
				elseif currentStrat == STRAT['reset'] then
					-- send RST on unverified SYN
					if isSyn(lRXPkt) and not isVerifiedReset(lRXPkt) then
						-- create and send RST packet
						createResponseReset(lTXRstBufs[i], lRXPkt)
					else
						-- everything else simply forward
						forwardTraffic(virtualDev, rTXBufs, lRXBufs[i])
					end
				elseif currentStrat == STRAT['sequence'] then
					-- send wrong sequence number on unverified SYN
					if isSyn(lRXPkt) and not isVerifiedSequence(lRXPkt) then
						-- create and send packet with wrong sequence
						createResponseSequence(lTXSeqBufs[i], lRXPkt)
					elseif isRst(lRXPkt) and not isVerifiedSequence(lRXPkt) then
						setVerifiedSequence(lRXPkt)
						-- do nothing with RX packet
					else
						-- everything else simply forward
						forwardTraffic(virtualDev, rTXBufs, lRXBufs[i])
					end
				elseif currentStrat == STRAT['cookie'] then
					------------------------------------------------------------ SYN -> defense mechanism
					if isSyn(lRXPkt) then
						--log:info('Received SYN from left')
						-- strategy cookie
						numSynAck = numSynAck + 1
						local lTXPkt = lTXSynAckBufs[numSynAck]:getTcp4Packet()
						createSynAckToClient(lTXPkt, lRXPkt)
						-- length
						-- TODO do this via alloc, precrafted packet!
						lTXSynAckBufs[numSynAck]:setSize(lRXBufs[i]:getSize())
						--log:debug(''..lRXBufs[i]:getSize())
					-------------------------------------------------------------------------------------------------------- verified -> translate and forward
					-- check with verified connections
					-- if already verified in both directions, immediately forward, otherwise check cookie
					elseif isVerified(lRXPkt, LEFT_TO_RIGHT) then 
						--log:info('Received packet of verified connection from left, translating and forwarding')
						local idx = getIdx(lRXPkt, LEFT_TO_RIGHT)
						if isRst(lRXPkt) then -- TODO move to bottom
							--log:debug('Got RST packet from left ' .. idx)
							setRst(lRXPkt, LEFT_TO_RIGHT)
							translate = true
						elseif isFin(lRXPkt) then
							--log:debug('Got FIN packet from left ' .. idx)
							setFin(lRXPkt, LEFT_TO_RIGHT)
							translate = true
						end
						translate = true
					------------------------------------------------------------------------------------------------------- not verified, but is ack -> verify cookie
					elseif isAck(lRXPkt) then
						local ack = lRXPkt.tcp:getAckNumber()
						local mss = verifyCookie(lRXPkt)
						if mss then
							--log:info('Received valid cookie from left, starting handshake with server')
							
							if setLeftVerified(lRXPkt) then
								-- connection is left verified, start handshake with right
								--rTXBufs:alloc(60)
								--local rTXBuf = rTXBufs[1]

								--createSynToServer(rTXBuf, lRXBufs[i])
								--
								---- done, sending
								----log:debug('Sending vTXBuf via KNI')
								--virtualDev:txSingle(rTXBuf)
								numForward = numForward + 1
								createSynToServer(lTXForwardBufs[numForward], lRXBufs[i])
							else
								-- was already left verified -> stall
								-- should not happen as it is checked above already
								--log:debug('Already left verified, discarding')
								-- TODO dont just drop...
							end
						else
							log:warn('Wrong cookie, dropping packet ' .. getIdx(lRXPkt, LEFT_TO_RIGHT))
							-- drop, and done
							-- most likely simply the timestamp timed out
							-- but it might also be a DoS attack that tried to guess the cookie
						end
					----------------------------------------------------------------------------------------------- unverified, but not syn/ack -> ignore
					else
						-- not syn, unverified packets -> belongs to already deleted connection -> drop
						log:error('unhandled packet ' .. tostring(isVerified(lRXPkt, LEFT_TO_RIGHT)))
					end
				end
			end
			if translate then
				--log:info('Translating from left to right')
				--rTXBufs:alloc(70)
				--local rTXBuf = rTXBufs[1]

				--local rTXPkt = rTXBufs[1]:getTcp4Packet()
				--sequenceNumberTranslation(lRXBufs[i], rTXBufs[1], lRXPkt, rTXPkt, LEFT_TO_RIGHT)
				--virtualDev:txSingle(rTXBuf)
				numForward = numForward + 1
				sequenceNumberTranslation(lRXBufs[i], lTXForwardBufs[numForward], lRXPkt, lTXForwardBufs[numForward]:getTcp4Packet(), LEFT_TO_RIGHT)
			end
		end
		if rx > 0 then
			if currentStrat == STRAT['cookie'] then	
				--offload checksums to NIC
				--log:debug('rx ' .. rx .. ' numSynAck ' .. numSynAck)

				-- syn ack
				lTXSynAckBufs:offloadTcpChecksums(nil, nil, nil, numSynAck)
		
				lTXQueue:sendN(lTXSynAckBufs, numSynAck)

				lTXSynAckBufs:freeAfter(numSynAck)
			
				-- forwarded
				lTXForwardBufs:offloadTcpChecksums(nil, nil, nil, numForward)
		
				virtualDev:txBurst(lTXForwardBufs, numForward)

				lTXForwardBufs:freeAfter(numForward)

				-- rx
				lRXBufs:free(rx)
			elseif currentStrat == STRAT['ignore'] then	
				-- we dont send packets in reply to syn, so only free rx
				lRXBufs:free(rx)
			elseif currentStrat == STRAT['reset'] then	
				-- send rst packets
				lTXRstBufs:offloadTcpChecksums(nil, nil, nil, rx)
				lTXQueue:sendN(lTXRstBufs, rx)

				lRXBufs:free(rx)
			elseif currentStrat == STRAT['sequence'] then	
				-- send packets with wrong ack number
				lTXSeqBufs:offloadTcpChecksums(nil, nil, nil, rx)
				lTXQueue:sendN(lTXSeqBufs, rx)

				lRXBufs:free(rx)
			end
		end

		----------------------------- all actions by polling left interface done (also all buffers sent or cleared)

		lRXStats:update()
		lTXStats:update()
	end
	printVerifiedConnections()

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
