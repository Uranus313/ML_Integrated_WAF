local stringFunctions      = require("feature_extraction.utils.string")
local M = {}



function M.extract(tx)

    local f = tx.features
    local payload = (tx.raw_request.payload or ""):lower()

    --------------------------------------------------
    -- Multipart boundary
    --------------------------------------------------

    local ct = tx.raw_request.headers["content-type"] or ""

    local boundary =
        ct:match("boundary=([^;]+)")

    if boundary then

        f.multipart_boundary_count =
            stringFunctions.count_pattern(payload, boundary)

    else

        f.multipart_boundary_count = 0

    end

    --------------------------------------------------
    -- filename=
    --------------------------------------------------

    f.filename_count =
        stringFunctions.count_pattern(payload, 'filename%s*=')

    --------------------------------------------------
    -- Executable extensions
    --------------------------------------------------

    local executable = 0

    local extensions = {
        "exe",
        "dll",
        "php",
        "phtml",
        "php3",
        "php4",
        "php5",
        "phar",
        "jsp",
        "jspx",
        "asp",
        "aspx",
        "ashx",
        "cgi",
        "pl",
        "py",
        "rb",
        "sh",
        "bash",
        "bat",
        "cmd",
        "ps1",
        "jar",
        "war",
        "ear"
    }

    for _, ext in ipairs(extensions) do
        executable =
            executable +
            stringFunctions.count_pattern(payload, "%." .. ext)
    end

    f.executable_extension_count = executable



end

return M