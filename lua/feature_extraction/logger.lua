local cjson = require("cjson.safe")

local M = {}

-- IMPORTANT: JSONL format (1 JSON per line)
function M.write(tx)

    local file_path = "logs/transactions.jsonl"

    local json = cjson.encode(tx)

    if not json then
        ngx.log(ngx.ERR, "[LOGGER] Failed to encode transaction")
        return
    end

    local file, err = io.open(file_path, "a")

    if not file then
        ngx.log(ngx.ERR, "[LOGGER] Cannot open log file: ", err)
        return
    end

    file:write(json, "\n")
    file:close()
end

return M