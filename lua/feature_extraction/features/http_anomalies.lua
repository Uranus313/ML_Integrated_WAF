local M = {}

local valid_methods = {
    GET = true,
    POST = true,
    PUT = true,
    DELETE = true,
    PATCH = true,
    HEAD = true,
    OPTIONS = true,
    TRACE = true,
    CONNECT = true
}

function M.extract(tx)

    local f = tx.features

    local req = tx.raw_request
    local headers = req.headers

    --------------------------------------------------
    -- Missing required headers
    --------------------------------------------------

    f.missing_host =
        (headers["host"] == nil or headers["host"] == "") and 1 or 0

    f.missing_user_agent =
        (headers["user-agent"] == nil or headers["user-agent"] == "") and 1 or 0

    --------------------------------------------------
    -- Unexpected Content-Type
    --------------------------------------------------

    local ct = (headers["content-type"] or ""):lower()

    if ct == ""
        or ct:find("application/json", 1, true)
        or ct:find("application/x-www-form-urlencoded", 1, true)
        or ct:find("multipart/form-data", 1, true)
        or ct:find("text/plain", 1, true)
        or ct:find("application/xml", 1, true)
        or ct:find("text/xml", 1, true)
    then
        f.unexpected_content_type = 0
    else
        f.unexpected_content_type = 1
    end



    --------------------------------------------------
    -- Invalid method
    --------------------------------------------------

    f.invalid_method =
        valid_methods[req.method] and 0 or 1

    --------------------------------------------------
    -- Duplicate headers
    --------------------------------------------------

    local duplicates = 0

    for _, value in pairs(headers) do
        if type(value) == "table" then
            duplicates = duplicates + 1
        end
    end

    f.duplicate_headers = duplicates

    --------------------------------------------------
    -- Oversized headers
    --------------------------------------------------

    local oversized = 0

    for _, value in pairs(headers) do

        if type(value) == "table" then
            value = table.concat(value, ",")
        end

        if #tostring(value) > 4096 then
            oversized = oversized + 1
        end

    end

    f.oversized_headers = oversized

end

return M