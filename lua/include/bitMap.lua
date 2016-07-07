local log = require "log"
local ffi = require "ffi"
ffi.cdef [[
	struct bit_map_auth_map {};
	struct bit_map_auth_map * mg_bit_map_auth_create();
	
	bool mg_bit_map_auth_update(struct bit_map_auth_map *m, uint32_t k);
	void mg_bit_map_auth_find_update(struct bit_map_auth_map *m, uint32_t k);
	void mg_bit_map_auth_set(struct bit_map_auth_map *m, uint32_t k);
	bool mg_bit_map_auth_get(struct bit_map_auth_map *m, uint32_t k);
]]


local mod = {}

local LEFT_TO_RIGHT = true
local RIGHT_TO_LEFT = false

----------------------------------------------------------------------------------------------------------------------------
----
----------------------------------------------------------------------------------------------------------------------------

local bitMapAuth = {}
bitMapAuth.__index = bitMapAuth

function mod.createBitMapAuth()
	log:info("Creating a bit map for TCP SYN Authentication strategy")
	return setmetatable({
		map = ffi.C.mg_bit_map_auth_create()
	}, bitMapAuth)
end

function bitMapAuth:update(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	return ffi.C.mg_bit_map_auth_update(self.map, k)
end

function bitMapAuth:set(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	ffi.C.mg_bit_map_auth_set(self.map, k)
end

function bitMapAuth:get(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	return ffi.C.mg_bit_map_auth_get(self.map, k)
end

function bitMapAuth:findUpdate(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	ffi.C.mg_bit_map_auth_find_update(self.map, k)
end

function bitMapAuth:updateWhitelisted(pkt)
	self:findUpdate(pkt, leftToRight)
end

function bitMapAuth:isWhitelisted(pkt)
	return self:get(pkt, leftToRight)
end

function bitMapAuth:setWhitelisted(pkt)
	return self:set(pkt, leftToRight)
end

return mod
