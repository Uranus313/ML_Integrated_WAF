local entropy = require("feature_extraction.utils.entropy")

local M = {}

function M.extract(tx)

    local f = tx.features
    local req = tx.raw_request

    local body = req.body or ""
    local headers = req.headers or {}

    local content_type =
        string.lower(headers["content-type"] or "")

    ------------------------------------------------------------
    -- Length
    ------------------------------------------------------------

    f.body_length = #body

    ------------------------------------------------------------
    -- Content-Type detection
    ------------------------------------------------------------

    f.json_body = 0
    f.xml_body = 0
    f.form_body = 0
    f.multipart_body = 0
    f.plain_text_body = 0

    if content_type:find("application/json", 1, true) then
        f.json_body = 1

    elseif content_type:find("application/xml", 1, true)
        or content_type:find("text/xml", 1, true) then
        f.xml_body = 1

    elseif content_type:find("application/x-www-form-urlencoded", 1, true) then
        f.form_body = 1

    elseif content_type:find("multipart/form-data", 1, true) then
        f.multipart_body = 1

    elseif content_type:find("text/plain", 1, true) then
        f.plain_text_body = 1
    end

    ------------------------------------------------------------
    -- Heuristics (when Content-Type is missing or wrong)
    ------------------------------------------------------------

    if #body > 0 then

        local trimmed =
            body:match("^%s*(.-)%s*$")

        if f.json_body == 0 and
           (trimmed:match("^%b{}$") or trimmed:match("^%b[]$")) then
            f.json_body = 1
        end

        if f.xml_body == 0 and
           trimmed:match("^<%?xml") then
            f.xml_body = 1
        end

    end

    ------------------------------------------------------------
    -- Entropy
    ------------------------------------------------------------

    f.body_entropy = entropy.compute(body)

    ------------------------------------------------------------
    -- Line count
    ------------------------------------------------------------

    local line_count = 0

    if #body > 0 then
        for _ in body:gmatch("\n") do
            line_count = line_count + 1
        end
        line_count = line_count + 1
    end

    f.body_line_count = line_count

    ------------------------------------------------------------
    -- Word count
    ------------------------------------------------------------

    local word_count = 0

    for _ in body:gmatch("%S+") do
        word_count = word_count + 1
    end

    f.body_word_count = word_count

    ------------------------------------------------------------
    -- Character statistics
    ------------------------------------------------------------

    local special = 0
    local digits = 0
    local non_ascii = 0

    for i = 1, #body do

        local c = body:sub(i, i)
        local b = body:byte(i)

        if c:match("%d") then
            digits = digits + 1
        end

        if c:match("[<>'\"`;(){}%[%]$%%\\]") then
            special = special + 1
        end

        if b and b > 127 then
            non_ascii = non_ascii + 1
        end
    end

    if #body > 0 then

        f.body_special_character_ratio =
            special / #body

        f.body_digit_ratio =
            digits / #body

        f.body_non_ascii_ratio =
            non_ascii / #body

    else

        f.body_special_character_ratio = 0
        f.body_digit_ratio = 0
        f.body_non_ascii_ratio = 0

    end

    ------------------------------------------------------------
    -- Base64 detection
    ------------------------------------------------------------

    f.body_contains_base64 =
        body:match("[A-Za-z0-9+/=][A-Za-z0-9+/=][A-Za-z0-9+/=][A-Za-z0-9+/=][A-Za-z0-9+/=][A-Za-z0-9+/=][A-Za-z0-9+/=][A-Za-z0-9+/=]+") ~= nil
        and 1 or 0

    ------------------------------------------------------------
    -- Hex detection
    ------------------------------------------------------------

    f.body_contains_hex =
        body:match("0[xX][0-9a-fA-F]+") ~= nil
        and 1 or 0

    ------------------------------------------------------------
    -- Unicode escape detection
    ------------------------------------------------------------

    f.body_contains_unicode_escape =
        body:match("\\u%x%x%x%x") ~= nil
        and 1 or 0

    ------------------------------------------------------------
    -- Null byte detection
    ------------------------------------------------------------

    f.body_contains_null_byte =
        (body:find("%z", 1, true) or body:find("%%00", 1, true))
        and 1 or 0
    
    f.body_contains_directory_traversal =
        body:find("..", 1, true) and 1 or 0    

end

return M