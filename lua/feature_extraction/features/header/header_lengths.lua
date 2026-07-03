local M = {}

local function length(headers, name)

    local value = headers[name]

    if not value then
        return 0
    end

    if type(value) == "table" then
        value = table.concat(value, ",")
    end

    return #tostring(value)
end

function M.extract(tx)

    local f = tx.features
    local h = tx.raw_request.headers

    f.user_agent_length    = length(h, "user-agent")
    f.cookie_length        = length(h, "cookie")
    f.authorization_length = length(h, "authorization")
    f.referer_length       = length(h, "referer")
    f.origin_length        = length(h, "origin")
    f.accept_length        = length(h, "accept")
    f.content_type_length  = length(h, "content-type")

end

return M