local M = {}

function M.extract(tx)

    local f = tx.features
    local method = (tx.raw_request.method or ""):upper()

    -- reset all
    f.is_get     = 0
    f.is_post    = 0
    f.is_put     = 0
    f.is_patch   = 0
    f.is_delete  = 0
    f.is_options = 0
    f.is_head    = 0
    f.is_other   = 0

    if method == "GET" then
        f.is_get = 1

    elseif method == "POST" then
        f.is_post = 1

    elseif method == "PUT" then
        f.is_put = 1

    elseif method == "PATCH" then
        f.is_patch = 1

    elseif method == "DELETE" then
        f.is_delete = 1

    elseif method == "OPTIONS" then
        f.is_options = 1

    elseif method == "HEAD" then
        f.is_head = 1

    else
        -- 🚨 unknown / suspicious method
        f.is_other = 1
        f.unknown_method = method
    end
end

return M