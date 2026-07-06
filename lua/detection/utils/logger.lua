local cjson = require("cjson.safe")
local resty_lock = require("resty.lock")

local M = {}

local LOG_FILE = "logs/waf.jsonl"

local function write(level, msg, data)


     -- Acquire lock
    local lock, err = resty_lock:new("detection_log_locks", {
        timeout = 5,
        exptime = 10,
    })

    if not lock then
        ngx.log(ngx.ERR, "[LOGGER] Failed to create detection lock: ", err)
        return
    end

    local elapsed, err = lock:lock("detections")

    if not elapsed then
        ngx.log(ngx.ERR, "[LOGGER] Failed to acquire detection lock: ", err)
        return
    end

    local f = io.open(LOG_FILE, "a")
    -- if not f then
    --     return false
    -- end

    if not f then
        lock:unlock()
        ngx.log(ngx.ERR, "[LOGGER] Cannot open detection log file: ", err)
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
    local ok, err = lock:unlock()

    if not ok then
        ngx.log(ngx.ERR, "[LOGGER] Failed to release detection lock: ", err)
    end
    return true
end



local function write_async(level, msg, data)
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