-- 初始化
-- 获取当前路径
CURRENT_PATH = "e:/website/openresty/waf/"
-- 全局变量
RULE_FILES = {}
WAF_CONFIG = {}
WHITE_IPS = {}
WHITE_HOST = {}
BLACK_IPS = {}
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

-- 更新 package.path 以包含 utils 目录
package.path = package.path .. ";" .. CURRENT_PATH .. "/utils/?.lua;" .. CURRENT_PATH .. "/rules/?.lua"

-- 加载配置文件
function load_config()
    local filename = CURRENT_PATH .. "conf.d/waf.conf"
    WAF_CONFIG = {}
    for line in io.lines(filename) do
       -- ngx.log(ngx.INFO, "WAF Config line: ", line)
        line = string.match(line, "^[^#]*")
        if line then
            line = string.gsub(line, "%s+", "")
            if line ~= "" then
                local key, value = string.match(line, "([^=]+)=([^=]+)")
                if key and value then
                    
                    -- trim
                    key = string.gsub(key, "^%s*(.-)%s*$", "%1")
                    value = string.gsub(value, "^%s*(.-)%s*$", "%1")
                    -- 剔除引号
                    value = string.gsub(value, "^\"(.-)\"$", "%1")
                    WAF_CONFIG[key] = value
                    ngx.log(ngx.INFO, "WAF Config line match: " .. key .. " = " .. value)
                else
                    ngx.log(ngx.WARN, "Invalid config line: " .. line)
                end
            end
        end
    end
end

-- 加载 IP 列表
function load_ips()
    if WAF_CONFIG["mode"] == "off" then
        ngx.log(ngx.INFO, "WAF is off")
        return
    end

    local white_ip_file = CURRENT_PATH .. "conf.d/whiteIp"
    local black_ip_file = CURRENT_PATH .. "conf.d/blackIp"

    local iputils = require("ip")
    for line in io.lines(white_ip_file) do
        if line:find("/") then
            local ips = iputils.parseCidr(line)
            for _, ip in ipairs(ips) do
                table.insert(WHITE_IPS, ip)
            end
        else
            table.insert(WHITE_IPS, line)
        end
    end
    ngx.log(ngx.INFO, "WAF white ips: ".. #WHITE_IPS)
    for line in io.lines(black_ip_file) do
        if line:find("/") then
            local ips = iputils.parseCidr(line)
            for _, ip in ipairs(ips) do
                table.insert(BLACK_IPS, ip)
            end
        else
            table.insert(BLACK_IPS, line)
        end
    end
    ngx.log(ngx.INFO, "WAF black ips: ".. #BLACK_IPS)

    buildSet(WHITE_IPS, WHITE_IP_SET)
    buildSet(BLACK_IPS, BLACK_IP_SET)
end
-- 函数：遍历目录
local function iterate_directory(directory)
    local iter = io.popen('dir "' .. directory .. '" /b')
    return function()
        local file = iter:read()
        if file and file ~= "." and file ~= ".." then
            return file
        end
    end
end
--加载HOST白名单
function load_hosts()
    if WAF_CONFIG["mode"] == "off" then
        ngx.log(ngx.INFO, "WAF is off")
        return
    end

    local white_host_file = CURRENT_PATH .. "conf.d/whitehost"
    for line in io.lines(white_host_file) do
          table.insert(WHITE_HOST, line)
    end
    ngx.log(ngx.INFO, "WAF white hosts: ".. #WHITE_HOST)

    buildSet(WHITE_HOST, WHITE_HOST_SET)
end
-- 加载规则
-- 合法 position 集合（与 access 阶段 checkData 元素前缀对应）
local VALID_POSITIONS = { uri = true, body = true, cookie = true, ["user-agent"] = true }

function load_rules()
    if WAF_CONFIG["mode"] == "off" then
        return
    end

    local rules_directory = CURRENT_PATH .. "rules/"

    for file in iterate_directory(rules_directory) do
        if file:match("%.lua$") then
            local key = file:match("^(%w+)%..*$")  -- 例如 "sqli"
            local config_key = "exp_" .. key  -- 例如 "exp_backup"
            if WAF_CONFIG[config_key] == "off" then
                -- 跳过处理此文件
            else
                local file_path = rules_directory .. file
                ngx.log(ngx.INFO, "WAF initialized with rule: ", file_path)
                local raw = require(key)

                -- 切分 positions 并做白名单校验（未知 position 会被规则静默失效，必须告警）
                local positions = {}
                for part in string.gmatch(raw.position or "", '([^,]+)') do
                    if VALID_POSITIONS[part] then
                        table.insert(positions, part)
                    else
                        ngx.log(ngx.WARN, "rule ", key, ": unknown position '", part,
                            "' (valid: uri/body/cookie/user-agent)")
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
                                confidence = item.confidence,
                            })
                        end
                    end
                end

                RULE_FILES[key] = {
                    name      = raw.name,
                    desc      = raw.desc,
                    level     = raw.level,
                    positions = positions,
                    rules     = preprocessed,
                }
            end
        end
    end
end

function load_debug()
    if WAF_CONFIG["debug"] == "on" then
        DEBUG = true
    end

    local logPath = WAF_CONFIG["log_path"]

    -- 判断当前操作系统
    local is_windows = package.config:sub(1, 1) == "\\"

    -- 检查目录是否存在
    local f = io.open(logPath, "r")
    if not f then
        if is_windows then
            -- Windows 使用 mkdir 创建目录
            os.execute('mkdir "' .. logPath .. '"')
        else
            -- Unix 使用 mkdir -p 创建目录
            os.execute("mkdir -p " .. logPath .. " && chmod 777 " .. logPath)
        end
    else
        f:close()
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

