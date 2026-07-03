local M = {}

local function normalize_header_value(value)
    if type(value) == "table" then
        return table.concat(value, ",")
    end

    return tostring(value)
end

function M.extract(tx)

    local f = tx.features
    local headers = tx.raw_request.headers or {}

    local keys = {}

    for name in pairs(headers) do
        table.insert(keys, name)
    end

    table.sort(keys, function(a, b)
        return string.lower(a) < string.lower(b)
    end)

    local parts = {}

    for _, name in ipairs(keys) do
        local value = normalize_header_value(headers[name])
        table.insert(parts, string.lower(name) .. ":" .. value)
    end

    f.header_fingerprint = ngx.md5(table.concat(parts, "\n"))

end

return M