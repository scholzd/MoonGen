local log = require "log"
local ffi = require "ffi"
ffi.cdef [[
	struct bit_map_infr_map {};
	struct bit_map_infr_map * mg_bit_map_infr_create();
	
	bool mg_bit_map_infr_update(struct bit_map_infr_map *m, uint32_t k);
	void mg_bit_map_infr_find_update(struct bit_map_infr_map *m, uint32_t k);
	void mg_bit_map_infr_set(struct bit_map_infr_map *m, uint32_t k);
	bool mg_bit_map_infr_get(struct bit_map_infr_map *m, uint32_t k);
]]


local mod = {}

local LEFT_TO_RIGHT = true
local RIGHT_TO_LEFT = false

----------------------------------------------------------------------------------------------------------------------------
----
----------------------------------------------------------------------------------------------------------------------------

local bitMapInfr = {}
bitMapInfr.__index = bitMapInfr

function mod.createBitMapInfr()
	log:info("Creating a bit map for TCP SYN flood infringement strategy")
	return setmetatable({
		map = ffi.C.mg_bit_map_infr_create()
	}, bitMapInfr)
end

function bitMapInfr:update(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	return ffi.C.mg_bit_map_infr_update(self.map, k)
end

function bitMapInfr:set(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	ffi.C.mg_bit_map_infr_set(self.map, k)
end

function bitMapInfr:get(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	return ffi.C.mg_bit_map_infr_get(self.map, k)
end

function bitMapInfr:findUpdate(pkt)
	--log:debug("calling is verified")
	local k = pkt.ip4:getSrc()
	ffi.C.mg_bit_map_infr_find_update(self.map, k)
end

---- ignore
function bitMapInfr:isVerifiedIgnore(pkt)
	return self:update(pkt, leftToRight)
end

function bitMapInfr:updateVerifiedIgnore(pkt)
	self:update(pkt, leftToRight)
end

---- reset
function bitMapInfr:isVerifiedReset(pkt)
	return self:update(pkt, leftToRight)
end

function bitMapInfr:updateVerifiedReset(pkt)
	self:update(pkt, leftToRight)
end

---- sequence
function bitMapInfr:updateVerifiedSequence(pkt)
	self:findUpdate(pkt, leftToRight)
end

function bitMapInfr:isVerifiedSequence(pkt)
	return self:get(pkt, leftToRight)
end

function bitMapInfr:setVerifiedSequence(pkt)
	return self:set(pkt, leftToRight)
end

return mod
