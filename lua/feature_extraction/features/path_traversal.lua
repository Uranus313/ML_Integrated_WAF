local stringFunctions      = require("feature_extraction.utils.string")

local M = {}



function M.extract(tx)

    local f = tx.features
    local payload = (tx.raw_request.payload or ""):lower()

    --------------------------------------------------
    -- Traversal sequences
    --------------------------------------------------

    f.dotdot_count =
        stringFunctions.count_pattern(payload, "%.%.")

    local current = payload
    local count = 0

    while true do
        count = count + stringFunctions.count_pattern(current, "%.%.")

        local decoded = ngx.unescape_uri(current)
        if decoded == current then
            break
        end

        current = decoded
    end

    f.encoded_dotdot_count = math.max(count - f.dotdot_count, 0)
    --------------------------------------------------
    -- Common targets
    --------------------------------------------------

    f.etc_passwd_count =
        stringFunctions.count_pattern(payload, "etc[/\\]passwd")

    f.windows_system32_count =
        stringFunctions.count_pattern(payload, "windows[/\\]system32")

    f.proc_self_count =
        stringFunctions.count_pattern(payload, "proc[/\\]self")

    f.boot_ini_count =
        stringFunctions.count_pattern(payload, "boot%.ini")

    f.win_ini_count =
        stringFunctions.count_pattern(payload, "win%.ini")

    f.hosts_file_count =
        stringFunctions.count_pattern(payload, "etc[/\\]hosts")

    f.shadow_file_count =
        stringFunctions.count_pattern(payload, "etc[/\\]shadow")

    f.id_rsa_count =
        stringFunctions.count_pattern(payload, "id_rsa")

    --------------------------------------------------
    -- Slash / Backslash statistics
    --------------------------------------------------

    local slash = 0
    local backslash = 0

    for i = 1, #payload do

        local c = payload:sub(i, i)

        if c == "/" then
            slash = slash + 1

        elseif c == "\\" then
            backslash = backslash + 1

        end

    end

    if backslash == 0 then
        f.slash_backslash_ratio = slash
    else
        f.slash_backslash_ratio = slash / backslash
    end

    --------------------------------------------------
    -- Total indicators
    --------------------------------------------------

    f.traversal_keyword_count =
          f.dotdot_count
        + f.etc_passwd_count
        + f.windows_system32_count
        + f.proc_self_count
        + f.boot_ini_count
        + f.win_ini_count
        + f.hosts_file_count
        + f.shadow_file_count
        + f.id_rsa_count

end

return M