local normalize = require("utils.normalize")
local logger = require("utils.logger")
local scoring = require("scoring")

local _M = {}

local patterns = {
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "<img",
}

function _M.check(req, state)
    local payload = req.payload


    for _, pat in ipairs(patterns) do
        if payload:find(pat, 1, true) then
            logger.warn("XSS pattern detected", { pattern = pat, uri = req.uri })
            scoring.add(state, 3, "xss:" .. pat)
        end
    end
end

return _M
