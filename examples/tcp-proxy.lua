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

-- tcp
require "tcp/cookie"

-- utility
local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift


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
	
	local rxDev = device.config{ port = rxPort, txQueues=2 }
	local txDev = device.config{ port = txPort }
	rxDev:wait()
	txDev:wait()
	mg.launchLua("tcpProxySlave", rxDev, txDev)
	
	mg.waitForSlaves()
end


-----------------------------------------------------
-- debug utility TODO move to util or delete
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
-- profiling TODO move to util or new profiling.lua
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
-- check packet type TODO move to proto/...
----------------------------------------------------

function isIP4(pkt)
	return pkt.eth:getType() == proto.eth.TYPE_IP 
end

function isTcp(pkt)
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
	print('Is TCP ' .. tostring(isTcp(pkt)))
	print('Is SYN ' .. tostring(isSyn(pkt)))
	print('Is ACK ' .. tostring(isAck(pkt)))
end


---------------------------------------------------
-- verified connections TODO also move to cookie.lua? export to C, for sure
---------------------------------------------------

-- TODO add some form of timestamp and garbage collection on timeout
-- eg if not refreshed, remove after 60 seconds(2bits, every 30 seconds unset one, if both unset remove)
local verifiedConnections = { num = 0 }

function getIdx(pkt, leftToRight)
--	-- not collision free but might be faster for now; nope, it isn't
--	if leftToRight then
--		return pkt.ip4:getSrc() + pkt.tcp:getSrc() + pkt.ip4:getDst() + pkt.tcp:getDst()
--	else
--		return pkt.ip4:getDst() + pkt.tcp:getDst() + pkt.ip4:getSrc() + pkt.tcp:getSrc()
--	end
	-- collision free but maximal slow
	if leftToRight then
		return pkt.ip4:getSrcString() .. ':' .. pkt.tcp:getSrc() .. '-' .. pkt.ip4:getDstString() .. ':' .. pkt.tcp:getDst()
	else
		return pkt.ip4:getDstString() .. ':' .. pkt.tcp:getDst() .. '-' .. pkt.ip4:getSrcString() .. ':' .. pkt.tcp:getSrc()
	end
end

--function setVerified(pkt, leftToRight)
--	local idx = getIdx(pkt, leftToRight)
--	if not verifiedConnections[idx] then
--		verifiedConnections[idx] = {}
--	end
--	if leftToRight then
--		verifiedConnections[idx]['lSeq'] = pkt.tcp:getSeqNumber()
--		verifiedConnections[idx]['lAck'] = pkt.tcp:getAckNumber()
--	else
--		verifiedConnections[idx]['rSeq'] = pkt.tcp:getSeqNumber()
--		verifiedConnections[idx]['rAck'] = pkt.tcp:getAckNumber()
--		-- response from server, hence, we must have the left values already and can calculate diff
--		-- check anyway :)
--		if not verifiedConnections[idx]['lSeq'] then
--			log:warn('Scumbag server sending random SYN/ACKs. Seriously.')
--			return
--		end
--		verifiedConnections[idx]['diff'] = verifiedConnections[idx]['rSeq'] - verifiedConnections[idx]['lAck'] + 1
--	end
--end

function setLeftVerified(pkt)
	local idx = getIdx(pkt, LEFT_TO_RIGHT)
	local con = verifiedConnections[idx]
	if con then
		log:debug('Already left verified')
		return false
	end
	con = {}
	con['lAck'] = pkt.tcp:getAckNumber()
	con['num'] = verifiedConnections['num']
	con['lPkts'] = 0
	con['rPkts'] = 0
	con['lFin'] = ''
	con['rFin'] = ''
	con['lRst'] = ''
	con['rRst'] = ''
	con['numPkts'] = 0
	verifiedConnections['num'] = verifiedConnections['num'] + 1
	verifiedConnections[idx] = con
	return true
end

function setRightVerified(pkt)
	local idx = getIdx(pkt, RIGHT_TO_LEFT)
	local con = verifiedConnections[idx]
	if not con then
		log:debug('Not left verified, something is wrong')
		return false
	end
	con['rSeq'] = pkt.tcp:getSeqNumber()
	con['diff'] = con['rSeq'] - con['lAck'] + 1
	return true
end

function incPkts(con)
	con['numPkts'] = con['numPkts'] + 1
end

function getPkts(con)
	return con['numPkts']
end

function setFin(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]
	if not con then
		log:debug('FIN for not verified connection ' .. (leftToRight and 'from left' or 'from right'))
		return false
	end
	log:debug('one way FIN ' .. (leftToRight and 'from left' or 'from right'))
	if leftToRight then
		con['lFin'] = getPkts(con)
	else
		con['rFin'] = getPkts(con)
	end
	
	if con['lFin'] and con['rFin'] then
		log:warn('FIN in both directions')
		--verifiedConnections[idx] = nil
		return true
	end
	return false
end

function setRst(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]
	if not con then
		log:debug('RST for not verified connection ' .. (leftToRight and 'from left' or 'from right'))
		return
	end
	log:debug('one way RST ' .. (leftToRight and 'from left' or 'from right'))
	if leftToRight then
		con['lRst'] = getPkts(con)
	else
		con['rRst'] = getPkts(con)
	end
	
	if con['lRst'] and con['rRst'] then
		log:warn('Rst successful, deleting con')
		--verifiedConnections[idx] = nil
	end
end

function unsetVerified(pkt, leftToRight)
	local idx = getIdx(pkt, leftToRight)
	log:warn('Deleting conn')
	verifiedConnections[idx] = nil
end

-- TODO update timstamp
function isVerified(pkt, leftToRight, isReset)
	local idx = getIdx(pkt, leftToRight)
	local con = verifiedConnections[idx]
	if isReset then -- TODO why????
		--verifiedConnections[idx] = nil
		log:warn('RST successful, deleting con')
	end

	if con and con['diff'] then
		if leftToRight then
			con['lPkts'] = con['lPkts'] + 1
		else
			con['rPkts'] = con['rPkts'] + 1
		end
		incPkts(con)
		return con
	end
	return false
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


---------------------------------------------------
-- sequence number translation
---------------------------------------------------

-- simply resend the complete packet, but adapt seq/ack number
function sequenceNumberTranslation(rxBuf, txBuf, rxPkt, txPkt, leftToRight, isReset)
	--log:info('Performing Sequence Number Translation')
	-- calculate packet size
	local size = rxPkt.ip4:getLength() + 14 + 6
	
	-- copy content
	ffi.copy(txBuf:getData(), rxBuf:getData(), size)
	txBuf:setSize(size)

	-- translate numbers, depends on direction
	local diff = isVerified(rxPkt, leftToRight, isReset)
	if not diff or not diff['diff'] then
		log:error('translation without diff, something is horribly wrong')
		rxBuf:dump()
		return
	end
	if leftToRight then
		txPkt.tcp:setSeqNumber(rxPkt.tcp:getSeqNumber())
		txPkt.tcp:setAckNumber(rxPkt.tcp:getAckNumber() + diff['diff'])
	else
		txPkt.tcp:setSeqNumber(rxPkt.tcp:getSeqNumber() - diff['diff'])
		txPkt.tcp:setAckNumber(rxPkt.tcp:getAckNumber())
	end

	-- calculate checksums
	txPkt.tcp:calculateChecksum(txBuf:getData(), size, true)
	txPkt.ip4:calculateChecksum()
	--txPkt:calculateChecksums(txBuf:getData(), size, true)
end


---------------------------------------------------
-- slave
---------------------------------------------------

function tcpProxySlave(rxDev, txDev)
	log:setLevel("DEBUG")
	
	-- virutal KNI
	log:info('Init KNI')
	kni.init(4)
	log:info('Creating virtual Dev')
	local virtualDevMemPool = memory.createMemPool{n=8192}
	local virtualDev = kni.createKNI(0, rxDev, virtualDevMemPool, "vEth1")
	log:info('Ifconfig virtual Dev')
	io.popen("/sbin/ifconfig " .. "vEth1" .. " " .. "192.168.1.1" .. "/" .. "24")
	for i = 0, 100 do
    	virtualDev:handleRequest()	
		mg.sleepMillisIdle(1)
	end
	log:info('ARP virtual Dev')
	io.popen("/usr/sbin/arp -s 192.168.1.101 90:e2:ba:98:58:78")

	for i = 0, 100 do
    	virtualDev:handleRequest()	
		mg.sleepMillisIdle(1)
	end

	-- v tx for right to right
	local vTXMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
		}
	end)
	local vTXBufs = vTXMem:bufArray(1)
	
	-- v rx
	local vRXMem = memory.createMemPool()	
	local vRXBufs = vRXMem:bufArray()


	-- physical interfaces
	-- rx Dev
	local rxQueue = rxDev:getRxQueue(0)
	local rxMem = memory.createMemPool()	
	local rxBufs = rxMem:bufArray()
	rxStats = stats:newDevRxCounter(rxDev, "plain")

	-- tx Dev for left to left
	local txQueue = txDev:getTxQueue(0)
	local txMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
		}
	end)
	local txBufs = txMem:bufArray()
	txStats = stats:newDevTxCounter(txDev, "plain")

	-- tx Dev 2 for right to left
	local tx2Queue = txDev:getTxQueue(1)
	local tx2Mem = memory.createMemPool()
	local tx2Bufs = tx2Mem:bufArray(1)
	
	-- profiling
	--profile.start("l", profile_callback)

	-- main event loop
	log:info('Starting TCP Proxy')
	while mg.running() do
		--------------------------------------------------------------- poll right interface
		-- poll right interface
		--log:debug('Polling right (virtual) Dev')
		rx = virtualDev:rxBurst(vRXBufs, 16)
		--log:debug('vRX: ' .. rx)
		for i = 1, rx do
			local translate = false
			local reset = false
			--log:debug('Pkt #' .. tostring(i))
			local vRXPkt = vRXBufs[i]:getTcp4Packet()
			if not isTcp(vRXPkt) then
				--log:info('Ignoring vRX packet from server that is not TCP')
			else
				--log:debug('vRX Is TCP')
				--vRXBufs[i]:dump()
				local idx = getIdx(vRXPkt, RIGHT_TO_LEFT)
				if isRst(vRXPkt) then
					log:debug('Got RST packet from right ' .. idx)
					reset = true
					setRst(vRXPkt, RIGHT_TO_LEFT)
					translate = true
				elseif isFin(vRXPkt) then
					if setFin(vRXPkt, RIGHT_TO_LEFT) then
						reset = true
					end
					translate = true
				-- servers response, finally establish connection
				elseif isSyn(vRXPkt) and isAck(vRXPkt) then
					log:info('Received SYN/ACK from server, sending ACK back')
					--setVerified(vRXPkt, RIGHT_TO_LEFT)
					setRightVerified(vRXPkt)
					
					-- send ACK to server
					vTXBufs:alloc(70)
					local vTXBuf = vTXBufs[1]

					-- set size of tx packet
					local size = vRXPkt.ip4:getLength() + 14
					vTXBuf:setSize(size)
					
					-- copy data TODO directly use rx buffer
					--log:debug('copy data')
					ffi.copy(vTXBuf:getData(), vRXBufs[i]:getData(), size)
					
					-- send packet back with seq, ack + 1
					local vTXPkt = vTXBuf:getTcp4Packet()
					local tmp = vRXPkt.ip4:getSrc()
					vTXPkt.ip4:setSrc(vRXPkt.ip4:getDst())
					vTXPkt.ip4:setDst(tmp)
					tmp = vRXPkt.tcp:getSrc()
					vTXPkt.tcp:setSrc(vRXPkt.tcp:getDst())
					vTXPkt.tcp:setDst(tmp)
					vTXPkt.tcp:setSeqNumber(vRXPkt.tcp:getAckNumber())
					vTXPkt.tcp:setAckNumber(vRXPkt.tcp:getSeqNumber() + 1)
					vTXPkt.tcp:unsetSyn()
					vTXPkt.tcp:setAck()
					vTXPkt:setLength(size)

					-- calculate checksums
					vTXPkt.tcp:calculateChecksum(vTXBuf:getData(), size, true)
					vTXPkt.ip4:calculateChecksum()
					
					-- done, sending
					--log:debug('Sending vTXBuf via KNI')
					virtualDev:txSingle(vTXBuf)
				else
					-- anything else must be from a verified connection, translate and send via physical nic
					log:info('Packet of verified connection from server, translate and forward')
					translate = true
				end
			end
			if translate then
				log:info('Translating from right to left')
				tx2Bufs:alloc(70)
				local txBuf = tx2Bufs[1]
				local txPkt = tx2Bufs[1]:getTcp4Packet()

				--vRXBufs[i]:dump()
				sequenceNumberTranslation(vRXBufs[i], txBuf, vRXPkt, txPkt, RIGHT_TO_LEFT, reset)
				--tx2Bufs[1]:dump()

				--tx2Bufs:offloadTcpChecksums()
			
				tx2Queue:send(tx2Bufs)
				--tx2Bufs:freeAll()
			end
		end
		
		--log:debug('free vRX')
		vRXBufs:freeAll()

		------------------------------------------------------------------- polling from virtual interface done

		-- receive from physical interface
		rx = rxQueue:tryRecv(rxBufs, 1)

		if rx > 0 then
			txBufs:allocN(60, rx)
			--log:debug('alloced tx bufs ')
		end
		for i = 1, rx do
			local translate = false
			local reset = false
			--log:debug('Pkt #' .. tostring(i))
			local rxPkt = rxBufs[i]:getTcp4Packet()
			if not isTcp(rxPkt) then
				log:info('Ignoring packet that is not TCP from left')
			else
				--log:info('RX pkt')
				--rxBufs[i]:dump()
				--printChecks(rxPkt)
				local idx = getIdx(rxPkt, LEFT_TO_RIGHT)
				if isRst(rxPkt) then
					--log:info('Got RST packet from left ' .. idx)
					setRst(rxPkt, LEFT_TO_RIGHT)
					--reset = true
					translate = true
					reset = true
				elseif isFin(rxPkt) then
					if setFin(rxPkt, LEFT_TO_RIGHT) then
						reset = true
					end
					--log:info('Got FIN packet from left ' .. idx)
					translate = true
				------------------------------------------------------------ SYN -> defense mechanism
				elseif isSyn(rxPkt) then
					--log:info('Received SYN from left')
					-- strategy cookie

					local cookie, mss = calculateCookie(rxPkt)
				
					-- build tx pkt
					local txPkt = txBufs[i]:getTcp4Packet()
					-- MAC addresses
					txPkt.eth:setDst(rxPkt.eth:getSrc())
					txPkt.eth:setSrc(rxPkt.eth:getDst())

					-- IP addresses
					txPkt.ip4:setDst(rxPkt.ip4:getSrc())
					txPkt.ip4:setSrc(rxPkt.ip4:getDst())
					
					-- TCP
					txPkt.tcp:setDst(rxPkt.tcp:getSrc())
					txPkt.tcp:setSrc(rxPkt.tcp:getDst())
					
					txPkt.tcp:setAck()
					txPkt.tcp:setSyn()
					txPkt.tcp:setSeqNumber(cookie)
					txPkt.tcp:setAckNumber(rxPkt.tcp:getSeqNumber() + 1)
					txPkt.tcp:setWindow(mss)

					-- length
					txBufs[i]:setSize(rxBufs[i]:getSize())

					--log:info('TX pkt')
					--txBufs[i]:dump()
				------------------------------------------------------------ ACK -> create connection/translate
				elseif isAck(rxPkt) then
					log:info('Received ACK')
					-- check with existing cons
					-- if already finished the handshake, immediately forward, otherwise check cookie
					local diff = isVerified(rxPkt, LEFT_TO_RIGHT) 
					if diff then
						--log:debug(sT(diff))
						if not diff['diff'] then
							-- this happens when left is faster than right
							-- can't do much aside from discarding it
							log:warn('Received packet of only half verified connection from left, stalling')
						else
							log:info('Received packet of verified connection from left, translating and forwarding')
							translate = true
						end
					else
						local ack = rxPkt.tcp:getAckNumber()
						--log:debug('Got ACK # ' .. ack)
						local mss = verifyCookie(rxPkt)
						if mss then
							--log:debug('mss:            ' .. mss)
							log:info('Received valid cookie from left, starting handshake with server')
							--setVerified(rxPkt, LEFT_TO_RIGHT)
							
							if setLeftVerified(rxPkt) then
								-- establish
								--log:debug('alloc vTXBuf')
								vTXBufs:alloc(70)
								local vTXBuf = vTXBufs[1]

								-- set size of tx packet
								local size = rxPkt.ip4:getLength() + 14
								vTXBuf:setSize(size)
								
								-- copy data TODO directly use rx buffer
								--log:debug('copy data')
								ffi.copy(vTXBuf:getData(), rxBufs[i]:getData(), size)
								
								-- adjust some stuff: sequency number, flags, checksum, length fields
								local vTXPkt = vTXBuf:getTcp4Packet()
								vTXPkt.tcp:setSeqNumber(vTXPkt.tcp:getSeqNumber() - 1) -- reduce seq num by 1 as during handshake it will be increased by 1 (in SYN/ACK)
								vTXPkt.tcp:setSyn()
								vTXPkt.tcp:unsetAck()
								vTXPkt:setLength(size)

								-- calculate checksums
								vTXPkt.tcp:calculateChecksum(vTXBuf:getData(), size, true)
								vTXPkt.ip4:calculateChecksum()
								
								-- done, sending
								--log:debug('Sending vTXBuf via KNI')
								virtualDev:txSingle(vTXBuf)
							else
								-- was already left verified -> stall
								log:warn('Already left verified, stalling')
							end
						else
							log:warn('Wrong cookie, dropping packet')
							-- drop, and done
							-- most likely simply the timestamp timed out
							-- but it might also be a DoS attack that tried to guess the cookie
						end
					end
						
				else
					log:info('Received other TCP packet from left. Should also be forwarded')
					translate = true
				end
			end
			if translate then
				--log:info('Translating from left to right')
				vTXBufs:alloc(70)
				local vTXBuf = vTXBufs[1]

				local vTXPkt = vTXBufs[1]:getTcp4Packet()
				sequenceNumberTranslation(rxBufs[i], vTXBufs[1], rxPkt, vTXPkt, LEFT_TO_RIGHT, reset)
				--log:debug('sending via KNI')
				virtualDev:txSingle(vTXBuf)
			end
		end
		if rx > 0 then	
			--log:debug('Offloading checksums')
			--offload checksums to NIC
			txBufs:offloadTcpChecksums()
	
			--log:debug('Sending')
			txQueue:send(txBufs)
			--log:debug('Sent')
			

			--log:debug('Freeing txBufs')
			txBufs:freeAll()
		end
		--log:debug('Freeing rxBufs')
		rxBufs:free(rx)


		----------------------------- all actions by polling left interface done (also all buffers sent or cleared)

		rxStats:update()
		txStats:update()
	end
	printVerifiedConnections()

	log:info('Releasing KNI device')
	virtualDev:release()
	
	log:info('Closing KNI')
	kni.close()
	
	rxStats:finalize()
	txStats:finalize()

	--profile.stop()

	--print("Profiler results:")

	--for i,v in pairs(profile_stats) do
	--	print( v .. " ::: " .. i)
	--end

	---- this is just for testing garbage collection
	--collectgarbage("collect")
	log:info('Slave done')
end
