
local stringFunctions      = require("feature_extraction.utils.string")

local M = {}

local keyword_map = {

    --------------------------------------------------
    -- Shells
    --------------------------------------------------

    bash = "bash_count",
    sh = "sh_count",
    cmd = "cmd_count",
    powershell = "powershell_count",

    --------------------------------------------------
    -- Download tools
    --------------------------------------------------

    wget = "wget_count",
    curl = "curl_count",

    --------------------------------------------------
    -- Network
    --------------------------------------------------

    nc = "nc_count",
    netcat = "netcat_count",

    --------------------------------------------------
    -- Languages
    --------------------------------------------------

    python = "python_count",
    perl = "perl_count",
    php = "php_count",
    ruby = "ruby_count",

    --------------------------------------------------
    -- File commands
    --------------------------------------------------

    cat = "cat_count",
    ls = "ls_count",
    rm = "rm_count",
    mv = "mv_count",
    cp = "cp_count",
    chmod = "chmod_count",
    chown = "chown_count",

    --------------------------------------------------
    -- Information
    --------------------------------------------------

    whoami = "whoami_count",
    uname = "uname_count",
    id = "id_count",

    --------------------------------------------------
    -- Network utilities
    --------------------------------------------------

    ping = "ping_count",
    nslookup = "nslookup_count",
    dig = "dig_count",

    --------------------------------------------------
    -- Environment
    --------------------------------------------------

    env = "env_count",
    export = "export_count",

    --------------------------------------------------
    -- Execution
    --------------------------------------------------

    system = "system_count",
    exec = "exec_count",
    shell_exec = "shell_exec_count",
    passthru = "passthru_count",
    popen = "popen_count",
    proc_open = "proc_open_count",
    eval = "eval_count",

    --------------------------------------------------
    -- Privilege
    --------------------------------------------------

    sudo = "sudo_count",

    --------------------------------------------------
    -- Utilities
    --------------------------------------------------

    busybox = "busybox_count",
    nohup = "nohup_count",
    tee = "tee_count",
    mkfifo = "mkfifo_count"

}

function M.extract(tx)

    local f = tx.features
    local payload = (tx.raw_request.payload or ""):lower()

    --------------------------------------------------
    -- Initialize
    --------------------------------------------------

    f.command_keyword_count = 0

    for _, feature in pairs(keyword_map) do
        f[feature] = 0
    end

    --------------------------------------------------
    -- Tokenize
    --------------------------------------------------

    for word in payload:gmatch("[A-Za-z_][A-Za-z0-9_]*") do

        local feature = keyword_map[word]

        if feature then
            f[feature] = f[feature] + 1
            f.command_keyword_count =
                f.command_keyword_count + 1
        end

    end

    f["/bin/sh_count"] =
    stringFunctions.count_pattern(payload, "/bin/sh")

    f["/bin/bash_count"] =
        stringFunctions.count_pattern(payload, "/bin/bash")

    f["/bin_count"] =
        stringFunctions.count_pattern(payload, "/bin")

    f["/usr/bin_count"] =
        stringFunctions.count_pattern(payload, "/usr/bin")

    f.command_keyword_count =
        f.command_keyword_count
        + f["/bin/sh_count"]
        + f["/bin/bash_count"]
        + f["/bin_count"]
        + f["/usr/bin_count"]    

end

return M