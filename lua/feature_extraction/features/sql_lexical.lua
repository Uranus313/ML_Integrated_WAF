local M = {}

local keyword_map = {

    union = "union_count",
    select = "select_count",
    insert = "insert_count",
    update = "update_count",
    delete = "delete_count",
    drop = "drop_count",
    create = "create_count",

    sleep = "sleep_count",
    benchmark = "benchmark_count",

    information_schema = "information_schema_count",

    ["or"] = "or_keyword_count",
    ["and"] = "and_keyword_count",

    ["from"] = "from_count",
    ["where"] = "where_count",
    ["having"] = "having_count",
    ["into"] = "into_count",
    ["values"] = "values_count",

    exec = "exec_count",
    execute = "execute_count",

    cast = "cast_count",
    convert = "convert_count",
    declare = "declare_count",

    waitfor = "waitfor_count",

    xp_cmdshell = "xp_cmdshell_count",

    load_file = "load_file_count",
    outfile = "outfile_count",

    ascii = "ascii_count",
    substring = "substring_count",
    char = "char_count",
    concat = "concat_count",
    group_concat = "group_concat_count"

}

function M.extract(tx)

    local f = tx.features
    local payload = (tx.raw_request.payload or ""):lower()

    --------------------------------------------------
    -- Initialize all counters
    --------------------------------------------------

    f.sql_keyword_count = 0

    for _, feature in pairs(keyword_map) do
        f[feature] = 0
    end

    --------------------------------------------------
    -- Tokenize once
    --------------------------------------------------

    for word in payload:gmatch("[%w_]+") do

        local feature = keyword_map[word]

        if feature then
            f[feature] = f[feature] + 1
            f.sql_keyword_count = f.sql_keyword_count + 1
        end

    end

end

return M