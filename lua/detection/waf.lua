-- Main WAF entry (modular)
local scoring = require("detection.scoring")
local logger  = require("detection.utils.logger")
local crs = require("detection.conf.crs")
local normalize = require("detection.utils.normalize")
local cjson = require("cjson.safe")
-- Load all rule modules
-- local rules = {
--     require("rules.xss"),
--     require("rules.sqli"),
--     require("rules.lfi"),
-- }


local rules = {}

if crs.enabled_categories.xss then
    table.insert(rules, require("detection.rules.xss"))
end
if crs.enabled_categories.sqli then
    table.insert(rules, require("detection.rules.sqli"))
end
if crs.enabled_categories.lfi then
    table.insert(rules, require("detection.rules.lfi"))
end


-- Flatten query args safely
local function flatten_args(t)
    local list = {}

    local function recurse(val)
        if type(val) == "table" then
            for _, v in pairs(val) do
                recurse(v)
            end
        else
            table.insert(list, tostring(val))
        end
    end

    recurse(t)
    return table.concat(list, " ")
end
-- Flatten headers safely
local function flatten_headers(headers)
    local list = {}
    for k, v in pairs(headers or {}) do
        if type(v) == "table" then
            v = table.concat(v, " ")
        end
        if v then
            table.insert(list, v)
        end
    end
    return table.concat(list, " ")
end

-- Read request info
ngx.req.read_body()

local uri = ngx.var.request_uri or ""
local args = ngx.req.get_uri_args()
local body = ngx.req.get_body_data() or ""

local parsed = cjson.decode(body)
if parsed then
    body = body .. " " .. flatten_args(parsed)
end


local req = {
    ip = ngx.var.remote_addr,
    method = ngx.req.get_method(),
    uri = uri,
    query = args,
    body = body
    -- payload = uri .. " " .. flatten_args(args) .. " " .. body
}

local headers = ngx.req.get_headers()
req.headers = headers
req.ua = headers["user-agent"] or ""
req.cookies = headers["cookie"] or ""

-- req.payload = req.payload .. " " .. req.ua .. " " .. req.cookies
-- for k, v in pairs(headers) do
--     if type(v) == "table" then
--         v = table.concat(v, " ")
--     end
--     req.payload = req.payload .. " " .. tostring(v)
-- end
req.payload = table.concat({
    uri,
    flatten_args(args),
    body,
    req.ua,
    req.cookies,
    flatten_headers(headers)
}, " ")
-- Initialize threat scoring
local state = scoring.new()
-- logger.warn(req.payload)
-- Log the incoming request
-- logger.info("Request received", { ip = req.ip, request_id = ngx.var.request_id, method = req.method, uri = req.uri  })
req.payload = normalize.prepare(req.payload, state)

-- Run all rules
for _, rule in ipairs(rules) do
    rule.check(req, state)
end

-- If score exceeds threshold, block
if scoring.should_block(state, crs.anomaly_threshold) then
    logger.warn("Request blocked", { ip = req.ip , request_id = ngx.var.request_id, score = state.score, reasons = state.reasons })
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header["Content-Type"] = "text/plain"
    ngx.say("Forbidden")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- Request allowed
logger.info("Request allowed", { ip = req.ip, request_id = ngx.var.request_id, score = state.score })
return
