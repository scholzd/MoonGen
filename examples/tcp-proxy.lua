local mg		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local log		= require "log"
local kni 		= require "kni"
local ffi		= require "ffi"
local dpdkc 	= require "dpdkc"
local proto		= require "proto/proto"
local check		= require "proto/packetChecks"

local hashMap 	= require "hashMap" -- TODO move to synCookie.lua
local bitMap 	= require "bitMap"

-- tcp SYN defense strategies
local cookie	= require "tcp/synCookie"
local auth		= require "tcp/synAuthentication"

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
	lRXDev:wait()
	lTXDev:wait()
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

local STRAT = {
	cookie 	= 1,
	auth	= 2,
}


----------------------------------------------------
-- check packet type
----------------------------------------------------

local isIP4 = check.isIP4
local isTcp4 = check.isTcp4


-------------------------------------------------------------------------------------------
---- Cookie
-------------------------------------------------------------------------------------------

local verifyCookie = cookie.verifyCookie
local sequenceNumberTranslation = cookie.sequenceNumberTranslation
local createSynAckToClient = cookie.createSynAckToClient
local createSynToServer = cookie.createSynToServer
local createAckToServer = cookie.createAckToServer
local forwardTraffic = cookie.forwardTraffic


-------------------------------------------------------------------------------------------
---- Syn Auth
-------------------------------------------------------------------------------------------

local forwardTrafficAuth = auth.forwardTraffic
local createResponseAuth = auth.createResponseAuth


---------------------------------------------------
-- slave
---------------------------------------------------

function tcpProxySlave(lRXDev, lTXDev)
	log:setLevel("ERROR")
	
	local currentStrat = STRAT['auth']
	local maxBurstSize = 63

	-------------------------------------------------------------
	-- right/virtual interface
	-------------------------------------------------------------
	
	-- RX buffers for right
	local rRXMem = memory.createMemPool()	
	local rRXBufs = virtualDevMemPool:bufArray()
	
	-- TX buffers 
	-- ack to right (on syn/ack from right)
	local numAck = 0
	local rTXAckMem = memory.createMemPool(function(buf)
		buf:getTcp4Packet():fill{
		}
	end)
	local rTXAckBufs = virtualDevMemPool:bufArray(1)
	
	-- right to left forward
	local lTXForwardQueue = lTXDev:getTxQueue(1)
	
	local numForward = 0
	local rTXForwardMem = memory.createMemPool()
	local rTXForwardBufs = virtualDevMemPool:bufArray()


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
	
	-- buffer for syn auth answer to left
	local numAuth = 0
	local lTXAuthBufs = auth.getBufs()

	-- buffers for not TCP packets
	-- need to behandled separately as we cant just offload TCP checksums here
	-- its only a few packets anyway, so handle them separately
	local txNotTcpMem = memory.createMemPool()	
	local txNotTcpBufs = virtualDevMemPool:bufArray(1)


	-------------------------------------------------------------
	-- Hash table
	-------------------------------------------------------------
	log:info("Creating hash table")
	local hashMapCookie = hashMap.createSparseHashMapCookie()
	local bitMapAuth = bitMap.createBitMapAuth()

	
	-------------------------------------------------------------
	-- stall table
	-------------------------------------------------------------
	local stallMem = memory.createMemPool()
	local stallBufs = stallMem:bufArray(1)
	local stallTable = {}


	-------------------------------------------------------------
	-- main event loop
	-------------------------------------------------------------
	log:info('Starting TCP Proxy')
	while mg.running() do
		rx = lRXQueue:tryRecv(lRXBufs, 1)
		numSynAck = 0
		numAuth = 0
		numForward = 0
		for i = 1, rx do
			local lRXPkt = lRXBufs[i]:getTcp4Packet()
			if true then --not isTcp4(lRXPkt) then
				--log:debug('Sending packet that is not TCP')
				txNotTcpBufs:alloc(60)
				forwardTraffic(txNotTcpBufs[1], lRXBufs[i])
				lRXBufs[1]:dump()
				lTXQueue:sendN(txNotTcpBufs, 1)
			else -- TCP
				if currentStrat == STRAT['auth'] then
					-- send wrong sequence number on unverified SYN
					if lRXPkt.tcp:getSyn() and not bitMapAuth:isWhitelisted(lRXPkt) then
						-- create and send packet with wrong sequence
						numAuth = numAuth + 1
						createResponseAuth(lTXAuthBufs[numAuth], lRXPkt)
					else
						-- react to RST and verify connection
						-- or update timestamps but only if connection was verified already
						if lRXPkt.tcp:getRst() then
							bitMapAuth:setWhitelisted(lRXPkt)
						else
							bitMapAuth:updateWhitelisted(lRXPkt)
						end
						
						-- everything else simply forward
						if numForward == 0 then
							lTXForwardBufs:allocN(60, rx - (i - 1))
						end
						numForward = numForward + 1
						forwardTrafficAuth(lTXForwardBufs[numForward], lRXBufs[i])
					end
				else
					if lRXPkt.tcp:getSyn() then
						if not lRXPkt.tcp:getAck() then -- SYN -> send SYN/ACK
							log:debug('Received SYN from left')
							if numSynAck == 0 then
								lTXSynAckBufs:allocN(60, rx - (i - 1))
							end
							numSynAck = numSynAck + 1
							createSynAckToClient(lTXSynAckBufs[numSynAck], lRXPkt)
						else -- SYN/ACK from right -> send ack + stall table lookup
							log:debug('Received SYN/ACK from server, sending ACK back')
							diff = hashMapCookie:setRightVerified(rlXPkt)
							if diff then
								-- ack to server
								lTXAckBufs:allocN(60, 1)
								createAckToServer(lTXAckBufs[1], lRXBufs[i], lRXPkt)
								lTXQueue:sendN(lTXAckBufs, 1)
									
								local index = lRXPkt.tcp:getDstString() .. lRXPkt.tcp:getSrcString() .. lRXPkt.ip4:getDstString() .. lRXPkt.ip4:getSrcString()
								local entry = stallTable[index] 

								if entry then
									local pkt = entry[1]:getTcp4Packet()
									pkt.tcp:setAckNumber(pkt.tcp:getAckNumber() + diff)
									pkt.tcp:calculateChecksum(entry[1]:getData(), entry[1]:getSize(), true)
									lTXQueue:sendSingle(entry[1])
									log:debug("accessed " .. tostring(entry[2]))
									stallTable[index] = nil	
								else
									log:debug("no entry")
								end
							else
								log:debug("right verify failed")
							end
					----------------------------------------------------------------------- any verified packet from server
					else -- check verified status
						local diff = hashMapCookie:isVerified(lRXPkt) 
						if not diff and lRXPkt.tcp:getAck() then -- finish handshake with left, start with right
							log:debug("verifying cookie")
							local mss, wsopt = verifyCookie(lRXPkt)
							if mss then
								log:debug('Received valid cookie from left, starting handshake with server')
								
								hashMapCookie:setLeftVerified(lRXPkt)
								-- connection is left verified, start handshake with right
								if numForward == 0 then
									lTXForwardBufs:allocN(60, rx - (i - 1))
								end
								numForward = numForward + 1
								createSynToServer(lTXForwardBufs[numForward], lRXBufs[i], mss, wsopt)
							else
								log:warn('Wrong cookie, dropping packet ')
								-- drop, and done
								-- most likely simply the timestamp timed out
								-- but it might also be a DoS attack that tried to guess the cookie
							end
						elseif not diff then
							-- not verified, not ack -> drop
							log:warn("dropping unverfied not ack packet")
						elseif diff == "stall" then
							log:debug("stall packet")
							local index = lRXPkt.tcp:getSrcString() .. lRXPkt.tcp:getDstString() .. lRXPkt.ip4:getSrcString() .. lRXPkt.ip4:getDstString()
								stallBufs:allocN(60, 1)
								ffi.copy(stallBufs[1]:getData(), lRXBufs[i]:getData(), lRXBufs[i]:getSize())
								stallBufs[1]:setSize(lRXBufs[i]:getSize())
								local entry =  stallTable[index] 
								if entry then
									stallTable[index] = { stallBufs[1], entry[2] + 1 }
								else
									stallTable[index] = { stallBufs[1], 1 }
								end
						elseif diff then 
							log:debug('Received packet of verified connection from left, translating and forwarding')
							if numForward == 0 then
								lTXForwardBufs:allocN(60, rx - (i - 1))
							end
							numForward = numForward + 1
							sequenceNumberTranslation(diff, lRXBufs[i], lTXForwardBufs[numForward], lRXPkt, lTXForwardBufs[numForward]:getTcp4Packet())
						else
							-- should not happen
							log:error('unhandled packet ' )--.. tostring(isVerified(lRXPkt, LEFT_TO_RIGHT)))
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
			else
				-- send packets with wrong ack number
				lTXAuthBufs:offloadTcpChecksums(nil, nil, nil, numAuth)
				lTXQueue:sendN(lTXAuthBufs, numAuth)
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
	log:info('Releasing KNI device')
	virtualDev:release()
	
	lRXStats:finalize()
	lTXStats:finalize()

	log:info('Slave done')
end
