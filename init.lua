-- 初始化
-- 获取当前路径
CURRENT_PATH = "e:/website/openresty/waf/"
-- 全局变量
RULE_FILES = {}
WAF_CONFIG = {}
WHITE_IPS = {}
WHITE_HOST = {}
BLACK_IPS = {}
LOGGERS = {}
DEBUG = false

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
end
-- 加载规则
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
                RULE_FILES[key] = require(key)
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

