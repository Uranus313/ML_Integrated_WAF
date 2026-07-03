local M = {}

local function exists(headers, name)
    return headers[name] ~= nil and 1 or 0
end

function M.extract(tx)

    local f = tx.features
    local h = tx.raw_request.headers

    f.has_user_agent      = exists(h, "user-agent")
    f.has_cookie          = exists(h, "cookie")
    f.has_referer         = exists(h, "referer")
    f.has_origin          = exists(h, "origin")
    f.has_authorization   = exists(h, "authorization")
    f.has_accept          = exists(h, "accept")
    f.has_accept_language = exists(h, "accept-language")
    f.has_accept_encoding = exists(h, "accept-encoding")
    f.has_content_type    = exists(h, "content-type")
    f.has_content_length  = exists(h, "content-length")
    f.has_x_forwarded_for = exists(h, "x-forwarded-for")
    f.has_x_real_ip       = exists(h, "x-real-ip")
    f.has_x_requested_with= exists(h, "x-requested-with")

end

return M