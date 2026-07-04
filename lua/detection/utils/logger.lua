local cjson = require("cjson.safe")

local M = {}

local LOG_FILE = "logs/waf.jsonl"

local function write(level, msg, data)

    local f = io.open(LOG_FILE, "a")
    if not f then
        return false
    end

    local entry = {
        timestamp = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        level = level,
        message = msg,
        data = data
    }

    f:write(cjson.encode(entry), "\n")
    f:close()

    return true
end


function write_async(level, msg, data)
    ngx.timer.at(0, function()
        write(level, msg, data)
    end)
end


function M.info(msg, data)
    return write_async("INFO", msg, data)
end

function M.warn(msg, data)
    return write_async("WARN", msg, data)
end

function M.error(msg, data)
    return write_async("ERROR", msg, data)
end



return M