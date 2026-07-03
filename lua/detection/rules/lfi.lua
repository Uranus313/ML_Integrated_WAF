local normalize = require("detection.utils.normalize")
local logger = require("detection.utils.logger")
local scoring = require("detection.scoring")

local _M = {}

local patterns = {
    "../",
    "/etc/passwd",
    "php://",
    "/..",
}

function _M.check(req, state)
    local payload = req.payload


    for _, pat in ipairs(patterns) do
        if payload:find(pat, 1, true) then
            logger.warn("LFI attempt detected", { pattern = pat, uri = req.uri })
            scoring.add(state, 5, "lfi:" .. pat)
        end
    end
end

return _M
