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

local session_cookie_names = {
    session = true,
    sessionid = true,
    phpsessid = true,
    jsessionid = true,
    aspnetsessionid = true,
    connect_sid = true,
    sid = true,
}

local function looks_like_jwt(value)
    if not value then
        return false
    end

    -- JWT = xxxxx.yyyyy.zzzzz
    return value:match("^[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+%.[A-Za-z0-9_-]+$") ~= nil
end

function M.extract(tx)

    local f = tx.features
    local cookies = tx.raw_request.cookies or {}

    f.cookie_count = table_size(cookies)

    local total_length = 0
    local largest = 0

    f.has_session_cookie = 0
    f.has_jwt_cookie = 0

    for name, value in pairs(cookies) do

        name = string.lower(tostring(name))
        value = tostring(value or "")

        local len = #value

        total_length = total_length + len

        if len > largest then
            largest = len
        end

        if session_cookie_names[name] then
            f.has_session_cookie = 1
        end

        if looks_like_jwt(value) then
            f.has_jwt_cookie = 1
        end
    end

    f.cookie_total_length = total_length
    f.largest_cookie_length = largest

    if f.cookie_count > 0 then
        f.average_cookie_length =
            total_length / f.cookie_count
    else
        f.average_cookie_length = 0
    end

end

return M