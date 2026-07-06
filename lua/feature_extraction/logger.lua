local cjson = require("cjson.safe")
local resty_lock = require("resty.lock")

local M = {}

local function write(tx)

    local json = cjson.encode(tx)

    if not json then
        ngx.log(ngx.ERR, "[LOGGER] Failed to encode transaction")
        return
    end

    -- Acquire lock
    local lock, err = resty_lock:new("feature_extraction_log_locks", {
        timeout = 5,
        exptime = 10,
    })

    if not lock then
        ngx.log(ngx.ERR, "[LOGGER] Failed to create feature extraction lock: ", err)
        return
    end

    local elapsed, err = lock:lock("transactions")

    if not elapsed then
        ngx.log(ngx.ERR, "[LOGGER] Failed to acquire feature extraction lock: ", err)
        return
    end

    -- Critical section
    local file, err = io.open("logs/transactions.jsonl", "a")

    if not file then
        lock:unlock()
        ngx.log(ngx.ERR, "[LOGGER] Cannot open feature extraction log file: ", err)
        return
    end

    file:write(json)
    file:write("\n")
    file:close()

    local ok, err = lock:unlock()

    if not ok then
        ngx.log(ngx.ERR, "[LOGGER] Failed to release feature extraction lock: ", err)
    end
end

function M.write_async(tx)
    ngx.timer.at(0, function()
        write(tx)
    end)
end

return M