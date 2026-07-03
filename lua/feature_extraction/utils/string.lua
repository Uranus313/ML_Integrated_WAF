local M = {}

function M.trim(s)
    return (s or ""):match("^%s*(.-)%s*$")
end

function M.count_pattern(str, pattern)

    local count = 0

    for _ in str:gmatch(pattern) do
        count = count + 1
    end

    return count

end

return M