local normalize = require("utils.normalize")
local logger = require("utils.logger")
local scoring = require("scoring")

local _M = {}

local patterns = {
    "union select",
    "or 1=1",
    "drop table",
    "insert into",
    "sleep(",
}

function _M.check(req, state)
    local payload = normalize.prepare(req.payload)


    for _, pat in ipairs(patterns) do
        if payload:find(pat, 1, true) then
            logger.warn("SQLi pattern detected", { pattern = pat, uri = req.uri })
            scoring.add(state, 4, "sqli:" .. pat)
        end
    end
end

return _M
