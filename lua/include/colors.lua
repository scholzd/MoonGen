local mRand = math.random
----------------------------------------------------------
---- Color Codes
----------------------------------------------------------

local colorCode = {
	black	= "0;30",
	dgrey	= "1;30",
	red		= "0;31",
	bred 	= "1;31",
	green	= "0;32",
	bgreen	= "1;32",
	brown	= "0;33",
	yellow	= "1;33",
	blue	= "0;34",
	bblue	= "1;34",
	dpurple	= "0;35",
	bpurple	= "1;35",
	dcyan	= "0;36",
	cyan	= "1;36",
	bgrey	= "0;37",
	white 	= "1;37",
	none	= "0"
}

function getColorCode(color)
	color = colorCode[color] or colorCode["none"]
	local tmp = mRand(40, 47)
	return "\027[" .. color .. ";" .. tmp .. "m"
end

function getRandomColorCode()
	local tmp = {}
	local i = 1
	for k, v in pairs(colorCode) do
		tmp[i] = k
		i = i + 1
	end
	local num = mRand(1, #tmp)

	return getColorCode(tmp[num])
end

function randomize(str, ...)
	local result = ""
	str = str:format(...)
	for i = 1, #str do
		local c = str:sub(i,i)
		result = result .. getRandomColorCode() .. c
		-- do something with c
	end
	return result
end
----------------------------------------------------------
---- Colorized String
----------------------------------------------------------

function getColorizedString(str, color)
	return getColorCode(color)  .. str .. getColorCode()
end

function red(str, ...)
	return getColorizedString(str:format(...), "red")
end

function bred(str, ...)
	return getColorizedString(str:format(...), "bred")
end

function yellow(str, ...)
	return getColorizedString(str:format(...), "yellow")
end

function green(str, ...)
	return getColorizedString(str:format(...), "green")
end

function white(str, ...)
	return getColorizedString(str:format(...), "white")
end
