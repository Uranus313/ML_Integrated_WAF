local stringFunctions      = require("feature_extraction.utils.string")

local M = {}

local keyword_map = {

    --------------------------------------------------
    -- Basic XSS
    --------------------------------------------------

    script = "script_count",
    javascript = "javascript_count",

    onload = "onload_count",
    onclick = "onclick_count",
    onerror = "onerror_count",

    iframe = "iframe_count",
    svg = "svg_count",
    img = "img_count",

    alert = "alert_count",

    --------------------------------------------------
    -- JavaScript functions
    --------------------------------------------------

    eval = "eval_count",
    prompt = "prompt_count",
    confirm = "confirm_count",

    settimeout = "settimeout_count",
    setinterval = "setinterval_count",

    fetch = "fetch_count",

    xmlhttprequest = "xmlhttprequest_count",

    --------------------------------------------------
    -- DOM APIs
    --------------------------------------------------

    innerhtml = "innerhtml_count",
    outerhtml = "outerhtml_count",

    write = "write_count",
    writeln = "writeln_count",

    cookie = "cookie_count",
    location = "location_count",

    window = "window_count",
    self = "self_count",
    top = "top_count",
    parent = "parent_count",

    --------------------------------------------------
    -- HTML attributes
    --------------------------------------------------

    src = "src_count",
    href = "href_count",

    --------------------------------------------------
    -- URI schemes
    --------------------------------------------------

    data = "data_count",
    vbscript = "vbscript_count",

    --------------------------------------------------
    -- CSS / JS
    --------------------------------------------------

    expression = "expression_count",

    --------------------------------------------------
    -- HTML elements
    --------------------------------------------------

    embed = "embed_count",
    object = "object_count",
    link = "link_count",
    meta = "meta_count",
    style = "style_count",
    body = "body_count",
    form = "form_count",
    input = "input_count",
    textarea = "textarea_count",
    video = "video_count",
    audio = "audio_count",
    source = "source_count",
    math = "math_count",
    foreignobject = "foreignobject_count"

}



function M.extract(tx)

    local f = tx.features
    local payload = (tx.raw_request.payload or ""):lower()

    --------------------------------------------------
    -- Initialize
    --------------------------------------------------

    for _, feature in pairs(keyword_map) do
        f[feature] = 0
    end

    f.document_cookie_count = 0
    f.xss_keyword_count = 0

    --------------------------------------------------
    -- Tokenize once
    --------------------------------------------------

    for word in payload:lower():gmatch("[A-Za-z_][A-Za-z0-9_]*") do
        local feature = keyword_map[word]
        if feature then
            f[feature] = f[feature] + 1
            f.xss_keyword_count = f.xss_keyword_count + 1
        end
    end

    --------------------------------------------------
    -- Special patterns
    --------------------------------------------------

    f.document_cookie_count =
        stringFunctions.count_pattern(payload, "document%s*%.%s*cookie")

    f.xss_keyword_count =
        f.xss_keyword_count +
        f.document_cookie_count
       

end

return M