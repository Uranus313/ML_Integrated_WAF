local M = {}

function M.trim(s)
    return (s or ""):match("^%s*(.-)%s*$")
end

return M