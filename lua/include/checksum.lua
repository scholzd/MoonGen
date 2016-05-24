---------------------------------
--- @file checksum.lua
--- @brief Utility functions for manual checksum calculations.
---------------------------------

local ffi = require "ffi"
local bor, band, bnot, rshift, lshift, bswap = bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift, bit.bswap

local mod = {}

--- Calculate a 16 bit checksum 
--- @param data cdata to calculate the checksum for.
--- @param len Number of bytes to calculate the checksum for.
--- @return 16 bit integer
function checksum(data, len)
	data = ffi.cast("uint16_t*", data)
	local cs = 0
	for i = 0, len / 2 - 1 do
		cs = cs + data[i]
		if cs >= 2^16 then
			cs = band(cs, 0xFFFF) + 1
		end
	end
	-- missing the very last uint_8 for odd sized packets
	if (len % 2) == 1 then
		-- simply null the byte outside of our packet
		cs = cs + band(data[len / 2], 0xFF)
		if cs >= 2^16 then
			cs = band(cs, 0xFFFF) + 1
		end
	end
	return band(bnot(cs), 0xFFFF)
end

-- RFC1624 Eq. 4:
-- HC' = HC - ~m - m'
function checksumUpdateIncremental32(checksum, oldValue, newValue)
	local sum;

	oldValue = bnot(oldValue);

	sum = band(checksum, 0xFFFF);
	sum = sum - (rshift(oldValue, 16) + band(oldValue, 0xFFFF));
	sum = sum - (rshift(newValue, 16) + band(newValue, 0xFFFF));
	
	sum = rshift(sum, 16) + band(sum, 0xFFFF);
	
	return band(sum, 0xFFFF);
end

return mod
