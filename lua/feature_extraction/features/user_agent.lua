local str = require("feature_extraction.utils.string")

local M = {}

local function contains(ua, pattern)
    return ua:find(pattern, 1, true) ~= nil
end

function M.extract(tx)

    local f = tx.features
    local ua = string.lower(tx.raw_request.headers["user-agent"] or "")

    local ua = str.trim(tx.raw_request.headers["user-agent"]):lower()
    -- Browsers
    f.is_browser =
        contains(ua, "mozilla") or
        contains(ua, "chrome") or
        contains(ua, "firefox") or
        contains(ua, "safari") or
        contains(ua, "edg")

    f.is_browser = f.is_browser and 1 or 0

    -- Mobile
    f.is_mobile =
        (contains(ua, "android") or
         contains(ua, "iphone") or
         contains(ua, "ipad") or
         contains(ua, "mobile")) and 1 or 0

    -- CLI clients
    f.is_curl = contains(ua, "curl") and 1 or 0
    f.is_wget = contains(ua, "wget") and 1 or 0

    -- Programming libraries
    f.is_python_requests =
        (contains(ua, "python-requests") or
         contains(ua, "python")) and 1 or 0

    f.is_go_http =
        (contains(ua, "go-http-client") or
         contains(ua, "golang")) and 1 or 0

    f.is_java =
        (contains(ua, "java") or
         contains(ua, "apache-httpclient")) and 1 or 0

    f.is_powershell =
        contains(ua, "powershell") and 1 or 0

    -- Security tools
    f.is_sqlmap = contains(ua, "sqlmap") and 1 or 0
    f.is_nikto = contains(ua, "nikto") and 1 or 0
    f.is_nmap = contains(ua, "nmap") and 1 or 0
    f.is_burp = contains(ua, "burp") and 1 or 0
    f.is_zap =
        (contains(ua, "zaproxy") or
         contains(ua, "owasp zap")) and 1 or 0

    -- Generic bots/crawlers
    f.is_bot =
        (contains(ua, "bot") or
         contains(ua, "spider") or
         contains(ua, "crawler") or
         contains(ua, "crawl")) and 1 or 0

    -- Empty or missing UA
    local recognized =
    f.is_browser == 1 or
    f.is_mobile == 1 or
    f.is_curl == 1 or
    f.is_wget == 1 or
    f.is_python_requests == 1 or
    f.is_go_http == 1 or
    f.is_java == 1 or
    f.is_powershell == 1 or
    f.is_sqlmap == 1 or
    f.is_nikto == 1 or
    f.is_nmap == 1 or
    f.is_burp == 1 or
    f.is_zap == 1 or
    f.is_bot == 1

    f.unknown_user_agent =
        (#ua > 0 and not recognized) and 1 or 0

    f.has_user_agent =
        (ua == "") and 0 or 1
end

return M