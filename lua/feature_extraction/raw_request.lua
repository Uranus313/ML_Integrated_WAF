local cjson = require("cjson.safe")

local M = {}

local function flatten_cookies(cookie)
    if not cookie then
        return {}
    end

    local result = {}

    for k,v in cookie:gmatch("([^=; ]+)=([^;]+)") do
        result[k]=v
    end

    return result
end

function M.read()

    ngx.req.read_body()

    local body = ngx.req.get_body_data() or ""

    local headers = ngx.req.get_headers()
    local payload = table.concat({
        ngx.var.request_uri or "",
        body or "",
        headers["cookie"] or "",
        headers["user-agent"] or "",
        headers["referer"] or "",
        headers["authorization"] or "",
    }, " ")
    return {

        request_id = ngx.var.request_id,

        timestamp = ngx.now(),

        iso8601 = ngx.var.time_iso8601,

        raw_request = {

            ip = ngx.var.remote_addr,

            method = ngx.req.get_method(),

            uri = ngx.var.request_uri,

            path = ngx.var.uri,

            raw_query = ngx.var.args or "",

            query = ngx.req.get_uri_args(),

            body = body,

            headers = headers,

            cookies = flatten_cookies(headers["cookie"]),

            http_version = ngx.req.http_version(),
            payload = payload

        },

        features = {}

    }

end

return M