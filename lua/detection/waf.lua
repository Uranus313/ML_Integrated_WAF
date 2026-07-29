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

ngx.req.clear_header("X-Test")
ngx.req.set_header("X-Test", "abc")


local headers = ngx.req.get_headers(0, true)

ngx.log(ngx.ERR, "Hello")
for k, v in pairs(headers) do
    ngx.log(ngx.ERR, string.format("KEY=%q VALUE=%q", k, tostring(v)))
end
for k, v in pairs(headers) do
    ngx.log(ngx.ERR, k .. " = " .. tostring(v))
end
if headers["X-ModSec-Audit"] then
    ngx.log(ngx.ERR, "FOUND MODSEC HEADER")
    ngx.log(ngx.ERR, headers["X-ModSec-Audit"])
else
    ngx.log(ngx.ERR, "NO MODSEC HEADER")
end

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


local tx = ngx.ctx.tx

    if tx then
        ngx.log(ngx.ERR, "Found transaction!")
        ngx.log(ngx.ERR, require("cjson.safe").encode(tx.features))
    else
        ngx.log(ngx.ERR, "No transaction found")
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



local lua_result


-- If score exceeds threshold, block
if scoring.should_block(state, crs.anomaly_threshold) then
    lua_result = logger.warn("Request blocked", { ip = req.ip , request_id = ngx.var.request_id, score = state.score, reasons = state.reasons })
    -- ngx.status = ngx.HTTP_FORBIDDEN
    -- ngx.header["Content-Type"] = "text/plain"
    -- ngx.say("Forbidden")
    -- return ngx.exit(ngx.HTTP_FORBIDDEN)
else
-- Request allowed
lua_result = logger.info("Request allowed", { ip = req.ip, request_id = ngx.var.request_id, score = state.score })
-- return
end


local request = {
    transaction = cjson.encode({
        features = tx.features
    }),
    modsec = headers["X-ModSec-Audit"],
    lua = cjson.encode(lua_result),
}



local sock = ngx.socket.tcp()
sock:settimeout(10000)

local ok, err = sock:connect("127.0.0.1", 9000)
if not ok then
    ngx.log(ngx.ERR, "AI connection failed: ", err)
    return
end

local payload = cjson.encode(request) .. "\n"

local bytes, err = sock:send(payload)
if not bytes then
    ngx.log(ngx.ERR, "AI send failed: ", err)
    sock:close()
    return
end

local response, err = sock:receive("*l")
sock:close()

if not response then
    ngx.log(ngx.ERR, "AI receive failed: ", err)
    return
end

local ai = cjson.decode(response)

ngx.log(ngx.ERR, "AI score: ", ai.score)
ngx.log(ngx.ERR, "AI decision: ", tostring(ai.decision))

if ai.decision then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header["Content-Type"] = "text/plain"
    ngx.say("Blocked by AI")
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end


return



