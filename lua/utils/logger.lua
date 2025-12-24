local _M = {}

function _M.info(msg, data)
    ngx.log(ngx.INFO, "[WAF] ", msg, data and (" | " .. require("cjson").encode(data) or ""))
end

function _M.warn(msg, data)
    ngx.log(ngx.WARN, "[WAF] ", msg, data and (" | " .. require("cjson").encode(data) or ""))
end

function _M.error(msg, data)
    ngx.log(ngx.ERR, "[WAF] ", msg, data and (" | " .. require("cjson").encode(data) or ""))
end

return _M
