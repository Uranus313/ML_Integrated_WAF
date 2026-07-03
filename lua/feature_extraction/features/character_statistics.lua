local M = {}

function M.extract(tx)

    local f = tx.features
    local payload = tx.raw_request.payload or ""

    local letters = 0
    local digits = 0
    local whitespace = 0
    local uppercase = 0
    local lowercase = 0
    local punctuation = 0
    local non_ascii = 0
    local special = 0

    for i = 1, #payload do

        local c = payload:sub(i, i)
        local b = payload:byte(i)

        if c:match("%a") then
            letters = letters + 1

            if c:match("%u") then
                uppercase = uppercase + 1
            else
                lowercase = lowercase + 1
            end

        elseif c:match("%d") then
            digits = digits + 1

        elseif c:match("%s") then
            whitespace = whitespace + 1

        elseif c:match("[%p]") then
            punctuation = punctuation + 1
        end

        if b and b > 127 then
            non_ascii = non_ascii + 1
        end

        if c:match("[<>'\"`;(){}%[%]$%%\\]") then
            special = special + 1
        end
    end

    ------------------------------------------------------------
    -- Counts
    ------------------------------------------------------------

    f.letter_count = letters
    f.digit_count = digits
    f.space_count = whitespace
    f.special_count = special
    f.punctuation_count = punctuation

    ------------------------------------------------------------
    -- Ratios
    ------------------------------------------------------------

    local len = #payload

    if len > 0 then

        f.letter_ratio = letters / len
        f.digit_ratio = digits / len
        f.whitespace_ratio = whitespace / len
        f.special_ratio = special / len
        f.uppercase_ratio = uppercase / len
        f.lowercase_ratio = lowercase / len
        f.punctuation_ratio = punctuation / len
        f.non_ascii_ratio = non_ascii / len

    else

        f.letter_ratio = 0
        f.digit_ratio = 0
        f.whitespace_ratio = 0
        f.special_ratio = 0
        f.uppercase_ratio = 0
        f.lowercase_ratio = 0
        f.punctuation_ratio = 0
        f.non_ascii_ratio = 0

    end

end

return M