-- Main WAF entry (modular)
local scoring = require("scoring")
local logger  = require("utils.logger")

-- Load all rule modules
local rules = {
    require("rules.xss"),
    require("rules.sqli"),
    require("rules.lfi"),
}

-- Read request info
ngx.req.read_body()
ngx.req.read_body()

local uri = ngx.var.request_uri or ""
local args = ngx.req.get_uri_args()
local body = ngx.req.get_body_data() or ""

local req_body = ngx.req.get_body_data()

-- Flatten query args safely
local function flatten_args(t)
    local list = {}
    for k, v in pairs(t) do
        if type(v) == "table" then
            for _, sub in pairs(v) do
                table.insert(list, tostring(sub))
            end
        else
            table.insert(list, tostring(v))
        end
    end
    return table.concat(list, " ")
end

local req = {
    ip = ngx.var.remote_addr,
    method = ngx.req.get_method(),
    uri = uri,
    query = args,
    body = body,
    payload = uri .. " " .. flatten_args(args) .. " " .. body
}

-- local req = {
--     ip = ngx.var.remote_addr,
--     method = ngx.req.get_method(),
--     uri = ngx.var.request_uri,
--     ua = ngx.var.http_user_agent,
--     body = req_body
-- }

-- Initialize threat scoring
local state = scoring.new()

-- Log the incoming request
logger.info("Request received", { ip = req.ip, method = req.method, uri = req.uri })

-- Run all rules
for _, rule in ipairs(rules) do
    rule.check(req, state)
end

-- If score exceeds threshold, block
if scoring.should_block(state, 2) then
    logger.warn("Request blocked", { ip = req.ip, score = state.score, reasons = state.reasons })
    ngx.status = 403
    ngx.say("Forbidden")
    return ngx.exit(403)
end

-- Request allowed
logger.info("Request allowed", { ip = req.ip, score = state.score })
return
