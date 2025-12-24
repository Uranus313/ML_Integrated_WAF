-- Phase 1 WAF bootstrap + basic XSS blocking

local ngx = ngx

-- Log request
ngx.log(ngx.INFO, "[WAF] Request received")

local req = {
    ip = ngx.var.remote_addr,
    method = ngx.req.get_method(),
    uri = ngx.var.request_uri,
    ua = ngx.var.http_user_agent
}

ngx.log(ngx.INFO,
    string.format("[WAF] %s %s %s", req.ip, req.method, req.uri)
)

-- Read query parameters (for GET)
local args = ngx.req.get_uri_args()

-- Function to check for XSS patterns
local function is_malicious(value)
    if not value then return false end
    -- simple check for <script> tags
    if type(value) == "table" then
        for _, v in pairs(value) do
            if type(v) == "string" and string.find(v, "<script>") then
                return true
            end
        end
    elseif type(value) == "string" then
        if string.find(value, "<script>") then
            return true
        end
    end
    return false
end

-- Check all query parameters
for k, v in pairs(args) do
    if is_malicious(v) then
        ngx.log(ngx.WARN, string.format("[WAF] Blocked XSS attack from %s, param: %s", req.ip, k))
        ngx.status = 403
        ngx.say("Forbidden")
        return ngx.exit(403)
    end
end

-- For now, allow everything else
return
