local _M = {}

-- Lowercase, trim, collapse spaces
function _M.basic(str)
    if not str then return "" end
    str = str:lower()
    str = str:gsub("%s+", " ")
    str = str:gsub("^%s+", ""):gsub("%s+$", "")
    return str
end

-- Replace URL‑encoded chars
function _M.url_decode(str)
    if not str then return "" end
    str = ngx.unescape_uri(str)
    return str
end

-- Convenience: decode + normalize
function _M.prepare(str)
    return _M.basic(_M.url_decode(str))
end

return _M
