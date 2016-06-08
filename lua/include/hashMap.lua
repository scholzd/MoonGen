local log = require "log"
local ffi = require "ffi"
ffi.cdef [[
	typedef struct ipv4_5t {
		uint32_t ext_ip;
		uint32_t int_ip;		
		uint16_t ext_port;
		uint16_t int_port;
		uint8_t proto;
	} ipv4_5t;
	
	struct v4hash5t {};

	typedef struct ipv4_tcppkt {
		struct ipv4_5t t5;
		uint64_t ts;
		uint8_t ttl;
		uint8_t flags;
	} ipv4_tcppkt;
	
	struct dmap_cookie {};
	struct dmap_cookie_value {};
	struct dmap_cookie* mg_dmap_cookie_create();
	void mg_dmap_cookie_insert(struct dmap_cookie* m, ipv4_tcppkt* p);
	struct dmap_cookie_value*  mg_dmap_cookie_find(struct dmap_cookie* m, ipv4_tcppkt* p);
]]

local mod = {}

local hashMap = {}
hashMap.__index = hashMap

function mod.createHashMap()
	log:info("Creating hash map")
	return setmetatable({
		map = ffi.C.mg_dmap_cookie_create()
	}, hashMap)
end

function hashMap:insert(idx)
	ffi.C.mg_dmap_cookie_insert(self.map, idx)
end

function hashMap:find(idx)
	return ffi.C.mg_dmap_cookie_find(self.map, idx)
end

return mod
