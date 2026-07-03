local _M = {}
local scoring = require("detection.scoring")
local logger = require("detection.utils.logger")  -- your logger module

-- Lowercase, trim, collapse spaces
function _M.basic(str)
    if not str then return "" end
    str = str:lower()
    str = str:gsub("[\"']", "")     -- remove quotes
    str = str:gsub("%s+", " ")
    str = str:gsub("^%s+", ""):gsub("%s+$", "")
    return str
end

-- Multi-pass URL decoding with scoring and logging
local function multi_decode_with_score(str, state)
    if not str then return "" end

    local max_iter = 5
    local iterations = 0

    for i = 1, max_iter do
        local decoded = ngx.unescape_uri(str)
        if decoded == str then
            break
        end

        str = decoded
        iterations = i

        -- suspicious: more than 2 layers
        if i >= 3 and state then
            scoring.add(state, 1, "multi-encoding detected")
            logger.warn("Multi-encoding detected", { layers = i, score = state.score })
        end
    end

    -- optionally store depth for ML or logging
    if state then
        state.decoding_depth = iterations
    end

    return str
end

-- Public API: normalize + decode + score
function _M.prepare(str, state)
    str = multi_decode_with_score(str, state)
    str = _M.basic(str)
    return str
end

return _M