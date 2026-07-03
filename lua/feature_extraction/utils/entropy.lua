local M = {}

function M.compute(str)

    if not str or #str == 0 then
        return 0
    end

    local freq = {}

    -- Count character frequencies
    for i = 1, #str do
        local c = str:sub(i, i)
        freq[c] = (freq[c] or 0) + 1
    end

    local entropy = 0
    local len = #str

    for _, count in pairs(freq) do
        local p = count / len
        entropy = entropy - p * (math.log(p) / math.log(2))
    end

    return entropy
end

return M