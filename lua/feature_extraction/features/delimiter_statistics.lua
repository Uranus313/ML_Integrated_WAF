local M = {}

function M.extract(tx)

    local f = tx.features
    local payload = tx.raw_request.payload or ""

    --------------------------------------------------
    -- Initialize counters
    --------------------------------------------------

    local quote = 0
    local dquote = 0
    local backtick = 0
    local semicolon = 0
    local colon = 0
    local comma = 0
    local equal = 0
    local ampersand = 0
    local pipe = 0
    local percent = 0

    local slash = 0
    local backslash = 0
    local hash = 0
    local at = 0
    local question = 0
    local star = 0
    local plus = 0
    local minus = 0
    local underscore = 0
    local dollar = 0

    local parentheses = 0
    local brackets = 0
    local braces = 0
    local angle = 0

    --------------------------------------------------
    -- Single pass
    --------------------------------------------------

    for i = 1, #payload do

        local c = payload:sub(i, i)

        if c == "'" then
            quote = quote + 1

        elseif c == '"' then
            dquote = dquote + 1

        elseif c == "`" then
            backtick = backtick + 1

        elseif c == ";" then
            semicolon = semicolon + 1

        elseif c == ":" then
            colon = colon + 1

        elseif c == "," then
            comma = comma + 1

        elseif c == "=" then
            equal = equal + 1

        elseif c == "&" then
            ampersand = ampersand + 1

        elseif c == "|" then
            pipe = pipe + 1

        elseif c == "%" then
            percent = percent + 1

        elseif c == "/" then
            slash = slash + 1

        elseif c == "\\" then
            backslash = backslash + 1

        elseif c == "#" then
            hash = hash + 1

        elseif c == "@" then
            at = at + 1

        elseif c == "?" then
            question = question + 1

        elseif c == "*" then
            star = star + 1

        elseif c == "+" then
            plus = plus + 1

        elseif c == "-" then
            minus = minus + 1

        elseif c == "_" then
            underscore = underscore + 1

        elseif c == "$" then
            dollar = dollar + 1

        elseif c == "(" or c == ")" then
            parentheses = parentheses + 1

        elseif c == "[" or c == "]" then
            brackets = brackets + 1

        elseif c == "{" or c == "}" then
            braces = braces + 1

        elseif c == "<" or c == ">" then
            angle = angle + 1
        end
    end

    --------------------------------------------------
    -- Store features
    --------------------------------------------------

    f.quote_count = quote
    f.double_quote_count = dquote
    f.backtick_count = backtick
    f.semicolon_count = semicolon
    f.colon_count = colon
    f.comma_count = comma
    f.equal_count = equal
    f.ampersand_count = ampersand
    f.pipe_count = pipe
    f.percent_count = percent

    f.slash_count = slash
    f.backslash_count = backslash
    f.hash_count = hash
    f.at_count = at
    f.question_mark_count = question
    f.star_count = star
    f.plus_count = plus
    f.minus_count = minus
    f.underscore_count = underscore
    f.dollar_count = dollar

    f.parentheses_count = parentheses
    f.bracket_count = brackets
    f.brace_count = braces
    f.angle_bracket_count = angle

end

return M