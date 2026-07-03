local entropy = require("feature_extraction.utils.entropy")

local M = {}

local function get_extension(path)
    if not path then
        return ""
    end

    local ext = path:match("%.([A-Za-z0-9]+)$")

    if ext then
        return ext:lower()
    end

    return ""
end

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

    local f = tx.features
    local req = tx.raw_request

    local path = req.path or ""
    local uri = req.uri or ""
    local query = req.query or {}
    local raw_query = req.raw_query or ""

    ------------------------------------------------------------------
    -- Path structure
    ------------------------------------------------------------------

    local depth = 0
    local segment_count = 0
    local total_segment_length = 0
    local longest_segment = 0

    for segment in path:gmatch("[^/]+") do

        depth = depth + 1
        segment_count = segment_count + 1

        local len = #segment

        total_segment_length = total_segment_length + len

        if len > longest_segment then
            longest_segment = len
        end
    end

    f.path_depth = depth
    f.path_segment_count = segment_count
    f.longest_path_segment = longest_segment

    if segment_count > 0 then
        f.average_path_segment_length =
            total_segment_length / segment_count
    else
        f.average_path_segment_length = 0
    end

    ------------------------------------------------------------------
    -- Character counts
    ------------------------------------------------------------------

    f.slash_count = select(2, path:gsub("/", ""))
    f.dot_count = select(2, path:gsub("%.", ""))

    local _, double_slashes = uri:gsub("//", "")
    f.double_slash_count = double_slashes

    ------------------------------------------------------------------
    -- Extension
    ------------------------------------------------------------------

    local extension = get_extension(path)

    f.extension = extension
    f.extension_length = #extension

    ------------------------------------------------------------------
    -- Query statistics
    ------------------------------------------------------------------

    f.has_query = next(query) ~= nil and 1 or 0
    f.query_parameter_count = table_size(query)

    local total_name_len = 0
    local total_value_len = 0

    local longest_name = 0
    local longest_value = 0

    for name, value in pairs(query) do

        local name_len = #tostring(name)

        total_name_len = total_name_len + name_len

        if name_len > longest_name then
            longest_name = name_len
        end

        if type(value) == "table" then

            for _, v in ipairs(value) do

                local len = #tostring(v)

                total_value_len = total_value_len + len

                if len > longest_value then
                    longest_value = len
                end
            end

        else

            local len = #tostring(value)

            total_value_len = total_value_len + len

            if len > longest_value then
                longest_value = len
            end
        end
    end

    local count = math.max(f.query_parameter_count, 1)

    f.average_query_parameter_length =
        total_name_len / count

    f.max_query_parameter_length =
        longest_name

    f.average_query_value_length =
        total_value_len / count

    f.max_query_value_length =
        longest_value

    ------------------------------------------------------------------
    -- Entropy
    ------------------------------------------------------------------

    f.uri_entropy = entropy.compute(uri)

    ------------------------------------------------------------------
    -- Suspicious URL characteristics
    ------------------------------------------------------------------

    f.contains_encoded_chars =
        uri:find("%%", 1, true) and 1 or 0

    f.path_contains_directory_traversal =
        path:find("..", 1, true) and 1 or 0

    f.contains_null_byte =
        uri:find("%%00", 1, true) and 1 or 0

end

return M