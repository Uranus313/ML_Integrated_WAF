local M = {}

local function count_matches(str, pattern)
    local count = 0

    for _ in str:gmatch(pattern) do
        count = count + 1
    end

    return count
end

function M.extract(tx)

    local f = tx.features

    local raw = table.concat({
        tx.raw_request.uri or "",
        tx.raw_request.raw_query or "",
        tx.raw_request.body or ""
    }, " ")

    --------------------------------------------------
    -- %XX URL encoding
    --------------------------------------------------

    f.url_encoding_count =
        count_matches(raw, "%%[%x][%x]")

    

    --------------------------------------------------
    -- \\uXXXX
    --------------------------------------------------

    f.unicode_encoding_count =
        count_matches(raw, "\\u%x%x%x%x")

    --------------------------------------------------
    -- 0xABCD...
    --------------------------------------------------

    f.hex_literal_count =
        count_matches(raw, "0[xX][0-9A-Fa-f]+")

    --------------------------------------------------
    -- HTML entities
    --------------------------------------------------

    local named =
        count_matches(raw, "&[%a]+;")

    local numeric =
        count_matches(raw, "&#%d+;")

    local hex =
        count_matches(raw, "&#x[%x]+;")

    f.html_entity_count =
        named + numeric + hex

    --------------------------------------------------
    -- Base64-like strings
    --------------------------------------------------

    local base64 = 0

    for token in raw:gmatch("[%w%+/=]+") do

        if #token >= 16
        and #token % 4 == 0
        and token:match("^[A-Za-z0-9+/=]+$") then

            base64 = base64 + 1

        end
    end

    f.base64_like_count = base64

    --------------------------------------------------
    -- Decode depth
    --------------------------------------------------

    local depth = 0
    local current = raw

    while true do

        local decoded = ngx.unescape_uri(current)

        if decoded == current then
            break
        end

        depth = depth + 1
        current = decoded

        if depth >= 10 then
            break
        end

    end

    f.decode_depth = depth

    f.double_url_encoding =
        (depth >= 2) and 1 or 0

    local total =
    f.url_encoding_count +
    f.unicode_encoding_count +
    f.html_entity_count +
    f.hex_literal_count

    f.encoding_ratio =
        total / math.max(#raw, 1)

end

return M