local normalize = require("detection.utils.normalize")
local logger = require("detection.utils.logger")
local scoring = require("detection.scoring")

local _M = {}

local patterns = {
    "union select",
    "or 1=1",
    "drop table",
    "insert into",
    "sleep(",
}

-- local function fuzz_payload(payload)
--     payload = payload:lower()
--     payload = payload:gsub("[%s'\"`]", "")
--     return payload
-- end

function _M.check(req, state)
    local payload = req.payload
    -- local payload = normalize.prepare(req.payload, state)
    -- payload = fuzz_payload(payload)
    -- logger.warn(payload)

    for _, pat in ipairs(patterns) do
        if payload:find(pat, 1, true) then
            logger.warn("SQLi pattern detected", { pattern = pat, uri = req.uri })
            scoring.add(state, 4, "sqli:" .. pat)
        end
    end
end

return _M
