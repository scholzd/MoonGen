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
		uint8_t flags;
	};
	
	struct sparse_hash_map_cookie {};
	struct sparse_hash_map_cookie * mg_sparse_hash_map_cookie_create(uint32_t size);
	
	char * mg_sparse_hash_map_cookie_string(struct sparse_hash_map_cookie *m);
	
	void mg_sparse_hash_map_cookie_insert(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k, uint32_t ack);
	bool mg_sparse_hash_map_cookie_finalize(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k, uint32_t seq);
	struct sparse_hash_map_cookie_value * mg_sparse_hash_map_cookie_find_update(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k);
	void mg_sparse_hash_map_cookie_delete(struct sparse_hash_map_cookie *m, struct sparse_hash_map_cookie_key *k);
]]


local function isFin(pkt)
	return pkt.tcp:getFin() == 1
end

local mod = {}

local LEFT_TO_RIGHT = true
local RIGHT_TO_LEFT = false

----------------------------------------------------------------------------------------------------------------------------
---- Google Sparse Hash Map for TCP SYN cookies
----------------------------------------------------------------------------------------------------------------------------

local sparseHashMapCookie = {}
sparseHashMapCookie.__index = sparseHashMapCookie

-- TODO add some form of timestamp and garbage collection on timeout
-- eg if not refreshed, remove after 60 seconds(2bits, every 30 seconds unset one, if both unset remove)
function mod.createSparseHashMapCookie(size)
	log:info("Creating a sparse hash map for TCP SYN flood cookie strategy")
	return setmetatable({
		map = ffi.C.mg_sparse_hash_map_cookie_create(size or 0)
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
	--log:debug("Key: " .. key.ip_src .. ":" .. key.tcp_src .. "->" .. key.ip_dst .. ":" .. key.tcp_dst)
	return key
end

function sparseHashMapCookie:setLeftVerified(pkt)
	--log:debug("set left verified")
	local k = sparseHashMapCookieGetKey(pkt, LEFT_TO_RIGHT)
	local ack = pkt.tcp:getAckNumber()
	ffi.C.mg_sparse_hash_map_cookie_insert(self.map, k, ack)
end

function sparseHashMapCookie:setRightVerified(pkt)
	--log:debug("set right verified")
	local k = sparseHashMapCookieGetKey(pkt, RIGHT_TO_LEFT)
	local seq = pkt.tcp:getSeqNumber()
	local r = ffi.C.mg_sparse_hash_map_cookie_finalize(self.map, k, seq)
	if not r then
		-- not left verified,
		-- happens if a connection is deleted 
		-- but right still has some packets in flight
		--log:debug('Not left verified, something is wrong')
	end
end

function sparseHashMapCookie:isVerified(pkt, leftToRight)
	--log:debug("is verified")
	local k = sparseHashMapCookieGetKey(pkt, leftToRight)

	local diff = ffi.C.mg_sparse_hash_map_cookie_find_update(self.map, k)
	--log:debug(tostring(diff))
	if not (diff == nil) then
		return diff.diff
	else
		--log:debug("no result")
		return false
	end
end

function sparseHashMapCookie:__tostring()
	return ffi.C.mg_sparse_hash_map_cookie_string(self.map)
end

function sparseHashMapCookie:delete(k)
	--log:debug("delete")
	ffi.C.mg_sparse_hash_map_cookie_delete(self.map, k)
end

return mod
