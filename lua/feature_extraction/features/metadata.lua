local M = {}

local function table_size(t)
    if type(t) ~= "table" then
        return 0
    end

    local count = 0

    for _ in pairs(t) do
        count = count + 1
    end

    return count
end

function M.extract(tx)
    local req = tx.raw_request

    tx.features = tx.features or {}
    local f = tx.features

    -- Request metadata
    f.request_method = req.method
    f.request_timestamp = tx.timestamp

    -- Lengths
    f.uri_length = #(req.uri or "")
    f.path_length = #(req.path or "")
    f.query_length = #(req.raw_query or "")
    f.body_length = #(req.body or "")

    -- Total payload size
    f.payload_length =
        f.uri_length +
        f.body_length

    -- Counts
    f.parameter_count = table_size(req.query)
    f.header_count = table_size(req.headers)
    f.cookie_count = table_size(req.cookies)

    -- Request line
    local http_version = req.http_version or 1.1

    f.http_version = http_version

    local version_str = "HTTP/" .. tostring(http_version)

    f.request_line_length =
        #(req.method or "") +
        1 +
        #(req.uri or "") +
        1 +
        #version_str
end

return M