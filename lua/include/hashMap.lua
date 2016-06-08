local log = require "log"
local ffi = require "ffi"
ffi.cdef [[
	struct sparse_hash_map_cookie_key {
		uint32_t ip_src;
		uint32_t ip_dst;		
		uint16_t tcp_src;
		uint16_t tcp_dst;
	};

	typedef struct sparse_hash_map_cookie_value {
		uint32_t diff;
		uint32_t last_ack;
		uint8_t flags;
	};
	
	struct sparse_hash_map_cookie {};
	struct sparse_hash_map_cookie * mg_sparse_hash_map_cookie_create();
	
	void mg_sparse_hash_map_cookie_insert(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k, uint32_t v);
	struct sparse_hash_map_cookie_value * mg_sparse_hash_map_cookie_find(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k);
	struct sparse_hash_map_cookie_value * mg_sparse_hash_map_cookie_find_update(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k, bool leftFin, bool rightFin, uint32_t last_ack);
]]


local function isFin(pkt)
	return pkt.tcp:getFin() == 1
end

local mod = {}

local sparseHashMapCookie = {}
sparseHashMapCookie.__index = sparseHashMapCookie

function mod.createSparseHashMapCookie()
	log:info("Creating a sparse hash map for TCP SYN flood cookie strategy")
	return setmetatable({
		map = ffi.C.mg_sparse_hash_map_cookie_create()
	}, sparseHashMapCookie)
end


local key = ffi.new("struct sparse_hash_map_cookie_key")
local function sparseHashMapCookieGetKey(pkt, leftToRight)
	if leftToRight then
		key.ip_src = pkt.ip4:getSrc()
		key.ip_dst = pkt.ip4:getDst()
		key.tcp_src = pkt.tcp:getSrc()
		key.tcp_dst = pkt.tcp:getDst()
	else
		key.ip_src = pkt.ip4:getDst()
		key.ip_dst = pkt.ip4:getSrc()
		key.tcp_src = pkt.tcp:getDst()
		key.tcp_dst = pkt.tcp:getSrc()
	end
	return key
end

function sparseHashMapCookie:insert(pkt, diff, leftToRight)
	local k = sparseHashMapCookieGetKey(pkt, leftToRight)
	ffi.C.mg_sparse_hash_map_cookie_insert(self.map, k, diff)
end

function sparseHashMapCookie:find(pkt, leftToRight)
	local k = sparseHashMapCookieGetKey(pkt, leftToRight)
	local r = ffi.C.mg_sparse_hash_map_cookie_find(self.map, k)
	log:debug(tostring(r))
	if not (r == nil) then
		return r
	else
		log:debug("no result")
	end
end

function sparseHashMapCookie:update(pkt, leftToRight)
	local k = sparseHashMapCookieGetKey(pkt, leftToRight)

	-- set/update left/right FIN flags to determine closed connections
	local leftFin = false
	local rightFin = false
	local lastAck = 0
	if isFin(pkt) then
		if leftToRight then
			leftFin = true
		else
			rightFin = true
		end
		-- in case it is the FIN/ACK, also store 
		-- the Seq number to check in in final ACK
		lastAck = pkt.tcp:getSeqNumber()
	end

	local r = ffi.C.mg_sparse_hash_map_cookie_find_update(self.map, k, leftFin, rightFin, lastAck)
	log:debug(tostring(r))
	if not (r == nil) then
		return r
	else
		log:debug("no result")
	end
end

return mod
