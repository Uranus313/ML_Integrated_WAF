local entropy = require("feature_extraction.utils.entropy")

local M = {}

function M.extract(tx)

    local f = tx.features
    local headers = tx.raw_request.headers or {}

    local total = 0
    local longest = 0
    local count = 0

    local header_names = {}
    local header_values = {}

    for name, value in pairs(headers) do

        -- Save header name
        table.insert(header_names, tostring(name))

        -- Handle repeated headers
        if type(value) == "table" then
            value = table.concat(value, ",")
        end

        value = tostring(value)

        table.insert(header_values, value)

        local len = #value

        total = total + len

        if len > longest then
            longest = len
        end

        count = count + 1
    end

    f.average_header_length =
        count > 0 and total / count or 0

    f.largest_header_length = longest

    f.header_name_entropy =
        entropy.compute(table.concat(header_names, " "))

    f.header_value_entropy =
        entropy.compute(table.concat(header_values, " "))

end

return M