-- 初始化
-- 获取当前路径
CURRENT_PATH = "e:/website/openresty/waf/"
-- 全局变量
RULE_FILES = {}
WAF_CONFIG = {}
WHITE_IPS = {}
WHITE_HOST = {}
BLACK_IPS = {}
WHITE_CIDRS = {}
BLACK_CIDRS = {}
-- 派生的 O(1) 查询 set，由 load_ips/load_hosts 在 init 阶段填充
WHITE_IP_SET = {}
WHITE_HOST_SET = {}
BLACK_IP_SET = {}
LOGGERS = {}
DEBUG = false

local function buildSet(list, set)
    for k in pairs(set) do set[k] = nil end
    if list then
        for _, v in ipairs(list) do
            set[v] = true
        end
    end
end

local function cleanLine(line)
    if not line then return "" end
    -- 剥离注释与回车换行符，并去除首尾空白
    line = string.match(line, "^[^#]*") or ""
    line = string.gsub(line, "[\r\n]+", "")
    return (string.gsub(line, "^%s*(.-)%s*$", "%1"))
end

-- 更新 package.path 以包含 utils 和 rules 目录（防重复追加）
if not string.find(package.path, CURRENT_PATH .. "/utils/?.lua", 1, true) then
    package.path = package.path .. ";" .. CURRENT_PATH .. "/utils/?.lua;" .. CURRENT_PATH .. "/rules/?.lua"
end

-- 加载配置文件
function load_config()
    local filename = CURRENT_PATH .. "conf.d/waf.conf"
    WAF_CONFIG = {}
    local f = io.open(filename, "r")
    if not f then
        ngx.log(ngx.ERR, "Failed to open config file: ", filename)
        return
    end
    for line in f:lines() do
        line = cleanLine(line)
        if line ~= "" then
            local key, value = string.match(line, "^([^=%s]+)%s*=%s*(.-)$")
            if key and value then
                -- 剔除首尾成对的双引号或单引号，保留值内部合法空格
                value = string.gsub(value, '^"(.-)"$', "%1")
                value = string.gsub(value, "^'(.-)'$", "%1")
                WAF_CONFIG[key] = value
                ngx.log(ngx.INFO, "WAF Config line match: " .. key .. " = " .. value)
            else
                ngx.log(ngx.WARN, "Invalid config line: " .. line)
            end
        end
    end
    f:close()
end

-- 加载 IP 列表
function load_ips()
    WHITE_IPS = {}
    BLACK_IPS = {}
    WHITE_CIDRS = {}
    BLACK_CIDRS = {}
    buildSet(nil, WHITE_IP_SET)
    buildSet(nil, BLACK_IP_SET)

    if WAF_CONFIG["mode"] == "off" then
        ngx.log(ngx.INFO, "WAF is off")
        return
    end

    local white_ip_file = CURRENT_PATH .. "conf.d/whiteIp"
    local black_ip_file = CURRENT_PATH .. "conf.d/blackIp"
    local iputils = require("ip")

    local wf = io.open(white_ip_file, "r")
    if wf then
        for line in wf:lines() do
            line = cleanLine(line)
            if line ~= "" then
                if line:find("/", 1, true) then
                    local range = iputils.parseCidrRange(line)
                    if range then
                        table.insert(WHITE_CIDRS, range)
                        table.insert(WHITE_IPS, line)
                    else
                        ngx.log(ngx.WARN, "Invalid white CIDR line: ", line)
                    end
                else
                    table.insert(WHITE_IPS, line)
                end
            end
        end
        wf:close()
    end
    ngx.log(ngx.INFO, "WAF white ips: " .. #WHITE_IPS .. " (cidrs: " .. #WHITE_CIDRS .. ")")

    local bf = io.open(black_ip_file, "r")
    if bf then
        for line in bf:lines() do
            line = cleanLine(line)
            if line ~= "" then
                if line:find("/", 1, true) then
                    local range = iputils.parseCidrRange(line)
                    if range then
                        table.insert(BLACK_CIDRS, range)
                        table.insert(BLACK_IPS, line)
                    else
                        ngx.log(ngx.WARN, "Invalid black CIDR line: ", line)
                    end
                else
                    table.insert(BLACK_IPS, line)
                end
            end
        end
        bf:close()
    end
    ngx.log(ngx.INFO, "WAF black ips: " .. #BLACK_IPS .. " (cidrs: " .. #BLACK_CIDRS .. ")")

    buildSet(WHITE_IPS, WHITE_IP_SET)
    buildSet(BLACK_IPS, BLACK_IP_SET)
end

-- 函数：遍历目录（确保关闭 popen 句柄，避免子进程句柄泄漏）
local function iterate_directory(directory)
    local files = {}
    local is_windows = package.config:sub(1, 1) == "\\"
    local cmd
    if is_windows then
        local win_dir = directory:gsub("/", "\\")
        cmd = 'dir "' .. win_dir .. '" /b /a-d'
    else
        cmd = 'ls -1 "' .. directory .. '"'
    end
    local iter = io.popen(cmd)
    if iter then
        for file in iter:lines() do
            file = file:gsub("[\r\n]+", "")
            if file ~= "" and file ~= "." and file ~= ".." then
                table.insert(files, file)
            end
        end
        iter:close()
    end
    local idx = 0
    return function()
        idx = idx + 1
        return files[idx]
    end
end

--加载HOST白名单
function load_hosts()
    WHITE_HOST = {}
    buildSet(nil, WHITE_HOST_SET)

    if WAF_CONFIG["mode"] == "off" then
        ngx.log(ngx.INFO, "WAF is off")
        return
    end

    local white_host_file = CURRENT_PATH .. "conf.d/whitehost"
    local hf = io.open(white_host_file, "r")
    if hf then
        for line in hf:lines() do
            line = cleanLine(line)
            if line ~= "" then
                table.insert(WHITE_HOST, line:lower())
            end
        end
        hf:close()
    end
    ngx.log(ngx.INFO, "WAF white hosts: " .. #WHITE_HOST)

    buildSet(WHITE_HOST, WHITE_HOST_SET)
end

-- 加载规则
-- 合法 position 集合（支持 uri/body/cookie/user-agent/headers）
local VALID_POSITIONS = { uri = true, body = true, cookie = true, ["user-agent"] = true, headers = true }

function load_rules()
    RULE_FILES = {}
    if WAF_CONFIG["mode"] == "off" then
        return
    end

    local rules_directory = CURRENT_PATH .. "rules/"

    for file in iterate_directory(rules_directory) do
        if file:match("%.lua$") then
            local key = file:match("^([%w_]+)%..*$")  -- 例如 "sqli"
            if key then
                local config_key = "exp_" .. key  -- 例如 "exp_backup"
                if WAF_CONFIG[config_key] == "off" then
                    -- 跳过处理此文件
                else
                    local file_path = rules_directory .. file
                    ngx.log(ngx.INFO, "WAF initialized with rule: ", file_path)
                    local ok, raw = pcall(require, key)
                    if ok and type(raw) == "table" then
                        -- 切分 positions 并做白名单校验（未知 position 会被规则静默失效，必须告警）
                        local positions = {}
                        for part in string.gmatch(raw.position or "", '([^,]+)') do
                            part = part:match("^%s*(.-)%s*$"):lower()
                            if VALID_POSITIONS[part] then
                                table.insert(positions, part)
                            else
                                ngx.log(ngx.WARN, "rule ", key, ": unknown position '", part,
                                    "' (valid: uri/body/cookie/user-agent/headers)")
                            end
                        end

                        -- 派生独立的预处理 rules 列表，不写回 require 表（保持规则文件作为只读 DSL）
                        local preprocessed = {}
                        if raw.rules then
                            for _, item in ipairs(raw.rules) do
                                if item.pattern then
                                    table.insert(preprocessed, {
                                        pattern    = item.pattern:match("^%s*(.-)%s*$"),
                                        name       = item.name,
                                        confidence = tonumber(item.confidence) or 1,
                                    })
                                end
                            end
                        end

                        RULE_FILES[key] = {
                            name      = raw.name or key,
                            desc      = raw.desc or "",
                            level     = raw.level or "medium",
                            positions = positions,
                            rules     = preprocessed,
                        }
                    else
                        ngx.log(ngx.ERR, "Failed to require rule ", key, ": ", tostring(raw))
                    end
                end
            end
        end
    end
end

function load_debug()
    DEBUG = (WAF_CONFIG["debug"] == "on")

    local logPath = WAF_CONFIG["log_path"]
    if logPath and logPath ~= "" then
        local localFile = require("localFile")
        localFile.ensureDirExists(logPath)
    end
end

ngx.log(ngx.INFO, "WAF init...... ")

-- 初始化随机数种子
math.randomseed(ngx.now() * 1000 + ngx.worker.pid())

ngx.log(ngx.INFO, "WAF loading config......")
-- 执行初始化函数
load_config()
ngx.log(ngx.INFO, "WAF loading ips......")
load_ips()
ngx.log(ngx.INFO, "WAF loading hosts......")
load_hosts()
ngx.log(ngx.INFO, "WAF loading rules......")
load_rules()
ngx.log(ngx.INFO, "WAF init finished.")
load_debug()

