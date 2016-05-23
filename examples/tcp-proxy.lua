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
--require "tcp/cookie"

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

LEFT_TO_RIGHT = true
RIGHT_TO_LEFT = false


-----------------------------------------------------
-- debug utility 
-----------------------------------------------------

-- print table of string -> string
function sT(t)
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

function profile_callback(thread, samples, vmstate)
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

function isIP4(pkt)
	return pkt.eth:getType() == proto.eth.TYPE_IP 
end

function isTcp4(pkt)
	return isIP4(pkt) and pkt.ip4:getProtocol() == proto.ip4.PROTO_TCP
end

function isSyn(pkt)
	return pkt.tcp:getSyn() == 1
end

function isAck(pkt)
	return pkt.tcp:getAck() == 1
end

function isRst(pkt)
	return pkt.tcp:getRst() == 1
end

function isFin(pkt)
	return pkt.tcp:getFin() == 1
end

function printChecks(pkt)
	print('Is IP4 ' .. tostring(isIP4(pkt)))
	print('Is TCP ' .. tostring(isTcp4(pkt)))
	print('Is SYN ' .. tostring(isSyn(pkt)))
	print('Is ACK ' .. tostring(isAck(pkt)))
end


-------------------------------------------------------------------------------------------
---- Cookie
-------------------------------------------------------------------------------------------

-- one cycle is 64 64 seconds (6 bit right shoft of timestamp)
local timestampValidCycles = 1

-- MSS encodings
local MSS = { 
	mss1=50, 
	mss2=55,
}

function calculateCookie(pkt)
	local tsOrig = getTimestamp()
	--log:debug('Time: ' .. ts .. ' ' .. toBinary(ts))
	ts = lshift(tsOrig, 27)
	--log:debug('Time: ' .. ts .. ' ' .. toBinary(ts))

	local mss = encodeMss()
	mss = lshift(mss, 24)

	local hash = getHash(
		pkt.ip4:getSrc(), 
		pkt.ip4:getDst(), 
		pkt.tcp:getSrc(),
		pkt.tcp:getDst(),
		tsOrig
	)
	--log:debug('Created TS:     ' .. toBinary(ts))
	--log:debug('Created MSS:    ' .. toBinary(mss))
	--log:debug('Created hash:   ' .. toBinary(hash))
	local cookie = ts + mss + hash
	--log:debug('Created cookie: ' .. toBinary(cookie))
	return cookie, mss
end

function verifyCookie(pkt)
	local cookie = pkt.tcp:getAckNumber()
	--log:debug('Got ACK:        ' .. toBinary(cookie))
	cookie = cookie - 1
	--log:debug('Cookie:         ' .. toBinary(cookie))

	-- check timestamp first
	local ts = rshift(cookie, 27)
	--log:debug('TS:           ' .. toBinary(ts))
	if not verifyTimestamp(ts) then
		--log:warn('Received cookie with invalid timestamp')
		return false
	end

	-- check hash
	local hash = band(cookie, 0x00ffffff)
	-- log:debug('Hash:           ' .. toBinary(hash))
	if not verifyHash(hash, pkt.ip4:getSrc(), pkt.ip4:getDst(), pkt.tcp:getSrc(), pkt.tcp:getDst(), ts) then
		--log:warn('Received cookie with invalid hash')
		return false
	else
		-- finally decode MSS and return it
		--log:debug('Received legitimate cookie')
		return decodeMss(band(rshift(cookie, 24), 0x3))
	end
end


-------------------------------------------------------------------------------------------
---- Timestamp
-------------------------------------------------------------------------------------------

function getTimestamp()
	local t = time()
	--log:debug('Time: ' .. t .. ' ' .. toBinary(t))
	-- 64 seconds resolution
	t = rshift(t, 6)
	--log:debug('Time: ' .. t .. ' ' .. toBinary(t))
	-- 5 bits
	t = t % 32
	--log:debug('Time: ' .. t .. ' ' .. toBinary(t))
	return t
end

function verifyTimestamp(t)
	return t + timestampValidCycles >= getTimestamp()
end


-------------------------------------------------------------------------------------------
---- MSS
-------------------------------------------------------------------------------------------

function encodeMss()
	-- 3 bits, allows for 8 different MSS
	mss = 1 -- encoding see MSS
	-- log:debug('MSS: ' .. mss .. ' ' .. toBinary(mss))
	return mss
end

function decodeMss(idx)
	return MSS['mss' .. tostring(idx)] or -1
end


-------------------------------------------------------------------------------------------
---- Hash
-------------------------------------------------------------------------------------------

function getHash(...)
	local args = {...}
	local sum = 0
	for k, v in pairs(args) do
		-- log:debug(k .. ':            ' .. toBinary(tonumber(v)))
		sum = sum + tonumber(v)
	end
	-- log:debug('sum:            ' .. toBinary(sum))
	return band(hash(sum), 0x00ffffff)
end

function verifyHash(oldHash, ...)
	local newHash = getHash(...)
	-- log:debug('Old hash:       ' .. toBinary(oldHash))
	-- log:debug('New hash:       ' .. toBinary(newHash))
	return oldHash == newHash
end

function hash(int)
	-- TODO implement something with real crypto later on
	return int
end


-------------------------------------------------------------------------------------------
---- State keeping
-------------------------------------------------------------------------------------------

-- TODO add some form of timestamp and garbage collection on timeout
-- eg if not refreshed, remove after 60 seconds(2bits, every 30 seconds unset one, if both unset remove)
local verifiedConnections = {}

function getIdx(pkt, leftToRight)
	if leftToRight then
		return pkt.ip4:getSrc() .. ':' .. pkt.tcp:getSrc() .. '-' .. pkt.ip4:getDst() .. ':' .. pkt.tcp:getDst()
	else
		return pkt.ip4:getDst() .. ':' .. pkt.tcp:getDst() .. '-' .. pkt.ip4:getSrc() .. ':' .. pkt.tcp:getSrc()
	end
end

function setLeftVerified(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	local con = verifiedConnections[idx]
	if con then
		-- connection is left verified, 
		-- hence, this syn is duplicated and can be dropped
		--log:debug('Already left verified')
		return false
	end
	con = {}
	con['lAck'] = pkt.tcp:getAckNumber()
	verifiedConnections[idx] = con
	return true
end

function setRightVerified(pkt)
	local idx = getIdx(pkt, RIGHT_TO_LEFT)
	local con = verifiedConnections[idx]
	if not con or not con['lAck'] then
		-- not left verified,
		-- happens if a connection is deleted 
		-- but right still has some packets in flight
		--log:debug('Not left verified, something is wrong')
		return false
	end
	con['diff'] = pkt.tcp:getSeqNumber() - con['lAck'] + 1
	con['lAck'] = nil
	return true
end

function setFin(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]
	if not con then
		-- FIN for not verified connection
		-- means conenction was already deleted
		-- and this packet can be ignored
		--log:debug('FIN for not verified connection ' .. (leftToRight and 'from left ' or 'from right ') .. idx)
		return
	end
	--log:debug('one way FIN ' .. (leftToRight and 'from left' or 'from right'))
	if leftToRight then
		con['lFin'] = true --con['lFin'] .. '-' .. getPkts(con)
	else
		con['rFin'] = true -- con['rFin'] .. '-' .. getPkts(con)
	end
	-- to identify the final ACK of the connection store the Sequence number
	if con['lFin'] and con['rFin'] then 
		con['FinSeqNumber'] = pkt.tcp:getSeqNumber()
	end
end

function setRst(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]
	if not con then
		-- RST for not verified connection
		-- means conenction was already deleted
		-- and this packet can be ignored
		--log:debug('RST for not verified connection ' .. (leftToRight and 'from left ' or 'from right ') .. idx)
		return
	end
	--log:debug('one way RST ' .. (leftToRight and 'from left' or 'from right'))
	if leftToRight then
		con['lRst'] = true --con['lRst'] .. '-' .. getPkts(con)
	else
		con['rRst'] = true --con['rRst'] .. '-' .. getPkts(con)
	end
end

function checkUnsetVerified(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]
	-- RST: in any case, delete connection
	if con['lRst'] or con['rRst'] then 
		unsetVerified(pkt, leftToRight)
	-- FIN: only if both parties sent a FIN
	-- 		+ it has to be an ACK for the last sequence number
	elseif con['lFin'] and con['rFin'] then 
		-- check for ack and the number matches
		if isAck(pkt) and con['FinSeqNumber'] + 1 == pkt.tcp:getAckNumber() then
				unsetVerified(pkt, leftToRight)
		end
		-- otherwise it was an old packet or wrong direction
		-- no action in that case
	end
end

function unsetVerified(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	--log:warn('Deleting connection ' .. idx)
	-- disabled as it has huge performance impact :( (3k reqs/s)
	--verifiedConnections[idx] = nil
end

-- TODO update timstamp
function isVerified(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]

	-- a connection is verified if it is in both directions
	-- in that case, the diff is calculated
	if con and con['diff'] then
		return con
	end
	return false
end

function isVerifiedReset(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	local num = verifiedConnections[idx] 
	if num then
		verifiedConnections[idx] = num + 1
		return true
	else
		verifiedConnections[idx] = 1
		return false
	end
end

-- same as reset
function isVerifiedIgnore(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	if verifiedConnections[idx] then
		return true
	else
		verifiedConnections[idx] = true
		return false
	end
end

function setVerifiedSequence(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	verifiedConnections[idx] = true
end

function isVerifiedSequence(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	if verifiedConnections[idx] then
		return true
	else
		return false
	end
end

function printVerifiedConnections()
	log:debug('********************')
	log:debug('Verified Connections')
	for k, v in pairs(verifiedConnections) do
		local str = ''
		if type(v) == 'table' then
		for ik, iv in pairs(v) do
			str = str .. ', ' .. tostring(ik) .. '=' .. tostring(iv)
		end
		else
		str = tostring(v)
		end
		log:debug(tostring(k) .. ' -> ' .. str)
	end
	log:debug('********************')
end


-------------------------------------------------------------------------------------------
---- Packet modification and crafting for cookie strategy
-------------------------------------------------------------------------------------------

-- simply resend the complete packet, but adapt seq/ack number
function sequenceNumberTranslation(rxBuf, txBuf, rxPkt, txPkt, leftToRight)
	--log:debug('Performing Sequence Number Translation ' .. (leftToRight and 'from left ' or 'from right '))
	
	-- I recall this delivered the wrong size once
	-- however, it is significantly faster (4-5k reqs/s!!)
	local size = rxBuf:getSize() 	
	
	-- copy content
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	txBuf:setSize(size)

	-- translate numbers, depends on direction
	local diff = isVerified(rxPkt, leftToRight)
	if not diff then
		-- packet is not verified, hence, we can't translate it
		-- happens after deleting connections or before second handshake is finished
		--log:error('translation without diff, something is horribly wrong ' .. getIdx(rxPkt, leftToRight))
		--rxBuf:dump()
		return
	end
	if leftToRight then
		txPkt.tcp:setAckNumber(rxPkt.tcp:getAckNumber() + diff['diff'])
	else
		txPkt.tcp:setSeqNumber(rxPkt.tcp:getSeqNumber() - diff['diff'])
	end

	
	-- calculate TCP checksum
	-- IP header does not change, hence, do not recalculate IP checksum
	--if leftToRight then
	--	txBuf:offloadTcpChecksum()
	--else
		txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	--end

	-- check whether connection should be deleted
	checkUnsetVerified(rxPkt, leftToRight)
end

function createAckToServer(txBuf, rxBuf, rxPkt)
	-- set size of tx packet
	local size = rxBuf:getSize()
	txBuf:setSize(size)
	
	-- copy data TODO directly use rx buffer
	--log:debug('copy data')
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	
	-- send packet back with seq, ack + 1
	local txPkt = txBuf:getTcp4Packet()
	local tmp = rxPkt.ip4:getSrc()
	txPkt.ip4:setSrc(rxPkt.ip4:getDst())
	txPkt.ip4:setDst(tmp)
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

function createSynAckToClient(txPkt, rxPkt)
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
	
	txPkt.tcp:setAck() -- TODO move to mempool init
	txPkt.tcp:setSyn() --
	txPkt.tcp:setSeqNumber(cookie)
	txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)
	txPkt.tcp:setWindow(mss)
end

-------------------------------------------------------------------------------------------
---- Packet modification and crafting for protocol violation strategies
-------------------------------------------------------------------------------------------

function forwardTraffic(vDev, txBufs, rxBuf)
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

function createResponseIgnore(txBuf, rxPkt)
	-- yep, nothing
end

function createResponseReset(txBuf, rxPkt)
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

function createResponseSequence(txBuf, rxPkt)
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

	local currentStrat = STRAT['ignore']
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

	-- TX buffers for right to right
	local rTXMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
		}
	end)
	local rTXBufs = rTXMem:bufArray(1)
	
	-- RX buffers for right
	local rRXMem = memory.createMemPool()	
	local rRXBufs = rRXMem:bufArray()


	-------------------------------------------------------------
	-- left/physical interface
	-------------------------------------------------------------
	-- RX buffers for left
	local lRXQueue = lRXDev:getRxQueue(0)
	local lRXMem = memory.createMemPool()	
	local lRXBufs = lRXMem:bufArray()
	lRXStats = stats:newDevRxCounter(lRXDev, "plain")

	-- TX buffers for left to left
	local lTXQueue = lTXDev:getTxQueue(0)
	local lTXMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
		}
	end)
	local lTXBufs = lTXMem:bufArray()
	lTXStats = stats:newDevTxCounter(lTXDev, "plain")
	
	-- buffer for resets
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
	
	-- buffer for sequence
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

	-- TX buffers for right to left
	local lTX2Queue = lTXDev:getTxQueue(1)
	local lTX2Mem = memory.createMemPool()
	local lTX2Bufs = lTX2Mem:bufArray(1)


	-------------------------------------------------------------
	-- profiling
	-------------------------------------------------------------
	profile.start("l", profile_callback)

	-- main event loop
	log:info('Starting TCP Proxy')
	while mg.running() do
		------------------------------------------------------------------------------ poll right interface
		--log:debug('Polling right (virtual) Dev')
		rx = virtualDev:rxBurst(rRXBufs, 63)
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
						rTXBufs:alloc(70)
						local rTXBuf = rTXBufs[1]
						createAckToServer(rTXBuf, rRXBufs[i], rRXPkt)
						
						-- done, sending
						--log:debug('Sending rTXBuf via KNI')
						virtualDev:txSingle(rTXBuf)
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
			
				lTX2Bufs:alloc(70)
				local lTXBuf = lTX2Bufs[1]
				local lTXPkt = lTXBuf:getTcp4Packet()

				sequenceNumberTranslation(rRXBufs[i], lTXBuf, rRXPkt, lTXPkt, RIGHT_TO_LEFT)
				lTX2Queue:send(lTX2Bufs)
			end
		end
		
		if currentStrat == STRAT['cookie'] then
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
				lTXBufs:allocN(60, rx)
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
						local lTXPkt = lTXBufs[i]:getTcp4Packet()
						createSynAckToClient(lTXPkt, lRxPkt)
						-- length
						-- TODO do this via alloc, precrafted packet!
						lTXBufs[i]:setSize(lRXBufs[i]:getSize())
						log:debug(''..lRXBufs[i]:getSize())
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
								rTXBufs:alloc(60)
								local rTXBuf = rTXBufs[1]

								-- set size of tx packet
								local size = lRXBufs[i]:getSize()
								rTXBuf:setSize(size)
								
								-- copy data TODO directly use rx buffer
								ffi.copy(rTXBuf:getData(), lRXBufs[i]:getData(), size)
								
								-- adjust some members: sequency number, flags, checksum, length fields
								local rTXPkt = rTXBuf:getTcp4Packet()
								-- reduce seq num by 1 as during handshake it will be increased by 1 (in SYN/ACK)
								-- this way, it does not have to be translated at all
								rTXPkt.tcp:setSeqNumber(rTXPkt.tcp:getSeqNumber() - 1)
								rTXPkt.tcp:setSyn()
								rTXPkt.tcp:unsetAck()
								rTXPkt:setLength(size)

								-- calculate checksums
								rTXPkt.tcp:calculateChecksum(rTXBuf:getData(), size, true)
								rTXPkt.ip4:calculateChecksum()
								
								-- done, sending
								--log:debug('Sending vTXBuf via KNI')
								virtualDev:txSingle(rTXBuf)
							else
								-- was already left verified -> stall
								-- should not happen as it is checked above already
								--log:debug('Already left verified, discarding')
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
						--log:error('unhandled packet ' .. tostring(isVerified(lRXPkt, LEFT_TO_RIGHT)))
					end
				end
			end
			if translate then
				--log:info('Translating from left to right')
				rTXBufs:alloc(70)
				local rTXBuf = rTXBufs[1]

				local rTXPkt = rTXBufs[1]:getTcp4Packet()
				sequenceNumberTranslation(lRXBufs[i], rTXBufs[1], lRXPkt, rTXPkt, LEFT_TO_RIGHT)
				virtualDev:txSingle(rTXBuf)
			end
		end
		if rx > 0 then
			if currentStrat == STRAT['cookie'] then	
				--offload checksums to NIC
				lTXBufs:offloadTcpChecksums()
		
				lTXQueue:send(lTXBufs)
			
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
