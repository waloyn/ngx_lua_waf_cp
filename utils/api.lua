local _M = {}
local cjson = require "cjson.safe"
local cache = require "cache"
local logger = require "logger"
local localFile = require "localFile"

-- 校验规则文件名（严格白名单：仅允许字母、数字、下划线并以 .lua 结尾，阻断 ../ 与 Windows 反斜杠 \ 穿越）
local function isValidRuleFile(ruleFile)
    if type(ruleFile) ~= "string" then
        return false
    end
    return ruleFile:match("^[a-zA-Z0-9_]+%.lua$") ~= nil
end

-- 在空环境沙箱中预校验规则 Lua 源码（防 RCE 注入与语法损坏）
local function validateRuleCode(code)
    if type(code) ~= "string" or #code == 0 or #code > 262144 then
        return false, "Invalid rule content size"
    end
    local fn, err = loadstring(code, "rule_sandbox")
    if not fn then
        return false, "Lua syntax error: " .. tostring(err)
    end
    if setfenv then
        setfenv(fn, {})
    end
    local ok, res = pcall(fn)
    if not ok or type(res) ~= "table" or type(res.rules) ~= "table" then
        return false, "Rule must return a table containing a 'rules' list"
    end
    for idx, item in ipairs(res.rules) do
        if type(item) ~= "table" or type(item.pattern) ~= "string" then
            return false, "Invalid rule item at index " .. idx
        end
        local trimmed = item.pattern:match("^%s*(.-)%s*$")
        local _, re_err = ngx.re.match("", trimmed, "isjo")
        if re_err then
            return false, "Invalid regex at index " .. idx .. ": " .. tostring(re_err)
        end
    end
    return true
end

-- 内部辅助：合并一条统计计数至 stats 结构（统一操作系统 unknown/Unknown 大小写并累加）
local function mergeStatKey(stats, ip_counts, key, val)
    val = tonumber(val) or 0
    if val == 0 then return end

    local sub_key = key:match("^count_(.+)$") or key:match("^hourly_(.+)$")
    if not sub_key then return end

    if sub_key == "reqCount" then
        stats.total_requests = stats.total_requests + val
        return
    end

    if sub_key == "reqDenyCount" then
        stats.blocked_requests = stats.blocked_requests + val
        return
    end

    -- 统计操作系统分布（合并 unknown 与 Unknown，统一格式为 Unknown）
    local os_match = sub_key:match("^os_(.+)$")
    if os_match then
        if os_match:lower() == "unknown" then
            os_match = "Unknown"
        end
        stats.os_distribution[os_match] = (stats.os_distribution[os_match] or 0) + val
        return
    end

    -- 统计状态码分布
    local status_match = sub_key:match("^status_(%d+)$")
    if status_match then
        stats.status_distribution[status_match] = (stats.status_distribution[status_match] or 0) + val
        return
    end

    -- 统计域名访问分布
    local host_match = sub_key:match("^host_(.+)$")
    if host_match then
        stats.host_distribution[host_match] = (stats.host_distribution[host_match] or 0) + val
        return
    end

    -- 统计攻击类型分布
    local attack_match = sub_key:match("^attack_(.+)$")
    if attack_match then
        stats.attack_types[attack_match] = (stats.attack_types[attack_match] or 0) + val
        return
    end

    -- 统计IP访问
    local ip_match = sub_key:match("^ip_(.+)$")
    if ip_match then
        ip_counts[ip_match] = (ip_counts[ip_match] or 0) + val
        return
    end
end

-- 内部辅助：整理 IP Top 20 排序
local function finalizeStats(stats, ip_counts)
    for ip, count in pairs(ip_counts) do
        table.insert(stats.top_ips, { ip = ip, count = count })
    end
    table.sort(stats.top_ips, function(a, b) return a.count > b.count end)
    if #stats.top_ips > 20 then
        local top20 = {}
        for i = 1, 20 do
            top20[i] = stats.top_ips[i]
        end
        stats.top_ips = top20
    end
    return stats
end

-- 获取统计数据（默认：进程启动以来的总计；支持快捷筛选项：hour / day / week / month）
function _M.getStats(period)
    local countCache = require("cache"):new("nova_waf_count")
    local p = (period or "process"):lower()
    if p == "" or p == "all" or p == "total" then
        p = "process"
    elseif p == "today" then
        p = "day"
    elseif p == "7d" then
        p = "week"
    elseif p == "30d" then
        p = "month"
    end

    local stats = {
        total_requests = 0,
        blocked_requests = 0,
        blocked_ips = (BLACK_IPS and #BLACK_IPS) or 0,
        os_distribution = {},
        status_distribution = {},
        host_distribution = {},
        attack_types = {},
        top_ips = {},
        period = p
    }
    local ip_counts = {}

    -- 1. 当前小时统计
    if p == "hour" then
        countCache:getAllPrefixKeys("hourly_", function(key)
            local val = tonumber(countCache:cacheGet(key)) or 0
            mergeStatKey(stats, ip_counts, key, val)
        end)
        local direct_req = tonumber(countCache:cacheGet("hourly_reqCount")) or 0
        if stats.total_requests < direct_req then stats.total_requests = direct_req end
        local direct_deny = tonumber(countCache:cacheGet("hourly_reqDenyCount")) or 0
        if stats.blocked_requests < direct_deny then stats.blocked_requests = direct_deny end
        return finalizeStats(stats, ip_counts)
    end

    -- 2. 进程启动以来的总计（默认项，永不按小时清空）
    if p == "process" then
        countCache:getAllPrefixKeys("count_", function(key)
            local val = tonumber(countCache:cacheGet(key)) or 0
            mergeStatKey(stats, ip_counts, key, val)
        end)
        local direct_req = tonumber(countCache:cacheGet("count_reqCount")) or 0
        if stats.total_requests < direct_req then stats.total_requests = direct_req end
        local direct_deny = tonumber(countCache:cacheGet("count_reqDenyCount")) or 0
        if stats.blocked_requests < direct_deny then stats.blocked_requests = direct_deny end
        return finalizeStats(stats, ip_counts)
    end

    -- 3. 按日/周/月聚合（读取归档磁盘 JSON + 内存中当前小时数据）
    local num_days = 1
    if p == "week" then
        num_days = 7
    elseif p == "month" then
        num_days = 30
    end

    local base_path = (WAF_CONFIG and WAF_CONFIG["log_path"]) or (CURRENT_PATH .. "../logs/waf")
    local count_dir = base_path .. "/count/"
    local cjson = require "cjson.safe"
    local now_ts = ngx.time()

    for i = 0, num_days - 1 do
        local date_str = os.date("%Y-%m-%d", now_ts - (i * 86400))
        local day_dir = count_dir .. date_str
        for h = 0, 23 do
            local fn = string.format("%s/%02d.json", day_dir, h)
            local f = io.open(fn, "r")
            if not f then
                fn = string.format("%s/%d.json", day_dir, h)
                f = io.open(fn, "r")
            end
            if f then
                local content = f:read("*a")
                f:close()
                if content and content ~= "" then
                    for block in content:gmatch("%b{}") do
                        local obj = cjson.decode(block)
                        if type(obj) == "table" then
                            for k, v in pairs(obj) do
                                mergeStatKey(stats, ip_counts, k, v)
                            end
                        end
                    end
                end
            end
        end
    end

    -- 加上当前小时内存中未落盘的动态计数
    countCache:getAllPrefixKeys("hourly_", function(key)
        local val = tonumber(countCache:cacheGet(key)) or 0
        mergeStatKey(stats, ip_counts, key, val)
    end)
    local direct_req = tonumber(countCache:cacheGet("hourly_reqCount")) or 0
    if stats.total_requests < direct_req then stats.total_requests = direct_req end
    local direct_deny = tonumber(countCache:cacheGet("hourly_reqDenyCount")) or 0
    if stats.blocked_requests < direct_deny then stats.blocked_requests = direct_deny end

    return finalizeStats(stats, ip_counts)
end

-- 获取攻击类型分布（使用已定义的 nova_waf_count 共享内存字典）
function _M.getAttackDistribution()
    local countCache = require("cache"):new("nova_waf_count")
    local distribution = {
        sqli  = tonumber(countCache:cacheGet("count_attack_sqli")) or 0,
        xss   = tonumber(countCache:cacheGet("count_attack_xss")) or 0,
        cc    = tonumber(countCache:cacheGet("count_attack_cc")) or 0,
        cmd   = tonumber(countCache:cacheGet("count_attack_cmd")) or 0,
        other = tonumber(countCache:cacheGet("count_attack_other")) or 0
    }
    return distribution
end

-- 获取请求趋势数据（使用已定义的 nova_waf_count 共享内存字典）
function _M.getRequestTrend()
    local countCache = require("cache"):new("nova_waf_count")
    local trend = {}
    for i = 0, 23 do
        local key = string.format("count_requests_hour_%d", i)
        trend[i + 1] = tonumber(countCache:cacheGet(key)) or 0
    end
    return trend
end

-- 获取IP黑名单
function _M.getBlackList()
    local blacklist = {}
    local file = io.open(CURRENT_PATH .. "conf.d/blackIp", "r")
    if file then
        for line in file:lines() do
            line = line:gsub("[\r\n]+", "")
            if line ~= "" then
                table.insert(blacklist, line)
            end
        end
        file:close()
    end
    return blacklist
end

-- 重载WAF配置
function _M.reloadConfig()
    local success = true
    local message = "配置重载成功"

    local ok, err = pcall(function()
        -- 清理规则模块缓存（同时清理 short name 与 rules. 前缀名，确保 load_rules 读取最新磁盘内容）
        local rulesPath = CURRENT_PATH .. "rules/"
        local files = localFile.getFiles(rulesPath)
        for _, file in ipairs(files) do
            local rule = file:match("^([%w_]+)%.lua$")
            if rule then
                package.loaded[rule] = nil
                package.loaded["rules." .. rule] = nil
            end
        end

        -- 重新执行当前 Worker 的配置与规则加载函数（不调用 flush_all 以保留已封禁攻击者状态）
        if load_config then load_config() end
        if load_ips then load_ips() end
        if load_hosts then load_hosts() end
        if load_rules then load_rules() end
        if load_debug then load_debug() end

        -- 尝试通知 Nginx Master 重载（同步所有 Worker 进程）
        local prefix = ngx.config.prefix()
        local is_windows = package.config:sub(1, 1) == "\\"
        local reload_cmd
        if is_windows and prefix then
            local win_prefix = prefix:gsub("/", "\\"):gsub("\\+$", "")
            reload_cmd = 'cd /d "' .. win_prefix .. '" && nginx -s reload'
        else
            reload_cmd = "nginx -s reload"
        end
        local reload_res = os.execute(reload_cmd)
        if not (reload_res == true or reload_res == 0) then
            ngx.log(ngx.WARN, "nginx -s reload returned non-zero (in-process config reloaded): ", tostring(reload_res))
        end
    end)

    if not ok then
        success = false
        message = "配置重载失败: " .. (err or "未知错误")
        ngx.log(ngx.ERR, "Failed to reload WAF config: ", err)
    end

    return success, message
end

-- 添加IP到黑名单
function _M.addToBlackList(ip)
    if type(ip) ~= "string" or ip:find("[\r\n]") then
        return false
    end
    local file = io.open(CURRENT_PATH .. "conf.d/blackIp", "a")
    if file then
        file:write(ip .. "\n")
        file:close()
        return true
    end
    return false
end

-- 从黑名单移除IP
function _M.removeFromBlackList(ip)
    local blacklist = _M.getBlackList()
    local file = io.open(CURRENT_PATH .. "conf.d/blackIp", "w")
    if file then
        for _, v in ipairs(blacklist) do
            if v ~= ip then
                file:write(v .. "\n")
            end
        end
        file:close()
        return true
    end
    return false
end

-- 获取IP白名单
function _M.getWhiteList()
    local whitelist = {}
    local file = io.open(CURRENT_PATH .. "conf.d/whiteIp", "r")
    if file then
        for line in file:lines() do
            line = line:gsub("[\r\n]+", "")
            if line ~= "" then
                table.insert(whitelist, line)
            end
        end
        file:close()
    end
    return whitelist
end

-- 添加IP到白名单
function _M.addToWhiteList(ip)
    if type(ip) ~= "string" or ip:find("[\r\n]") then
        return false
    end
    local file = io.open(CURRENT_PATH .. "conf.d/whiteIp", "a")
    if file then
        file:write(ip .. "\n")
        file:close()
        return true
    end
    return false
end

-- 从白名单移除IP
function _M.removeFromWhiteList(ip)
    local whitelist = _M.getWhiteList()
    local file = io.open(CURRENT_PATH .. "conf.d/whiteIp", "w")
    if file then
        for _, v in ipairs(whitelist) do
            if v ~= ip then
                file:write(v .. "\n")
            end
        end
        file:close()
        return true
    end
    return false
end

-- 获取规则配置
function _M.getRules()
    local rules = {}
    local rulesPath = CURRENT_PATH .. "rules/"
    local files = localFile.getFiles(rulesPath)

    for _, file in ipairs(files) do
        if isValidRuleFile(file) then
            local ruleName = file:match("^([a-zA-Z0-9_]+)%.lua$")
            if ruleName then
                -- 安全地加载规则模块
                local ok, ruleModule = pcall(require, "rules." .. ruleName)
                if not ok or type(ruleModule) ~= "table" then
                    ok, ruleModule = pcall(require, ruleName)
                end
                if ok and type(ruleModule) == "table" then
                    local configKey = "exp_" .. ruleName
                    local enabled = WAF_CONFIG and WAF_CONFIG[configKey] ~= "off"

                    rules[ruleName] = {
                        file = file,
                        name = ruleModule.name or ruleName,
                        desc = ruleModule.desc or "",
                        level = ruleModule.level or "medium",
                        position = ruleModule.position or "uri,body",
                        enabled = enabled
                    }
                else
                    ngx.log(ngx.WARN, "Failed to load rule module: ", ruleName)
                end
            end
        end
    end

    return rules
end

-- 获取单个规则文件内容
function _M.getRuleContent(ruleFile)
    if not isValidRuleFile(ruleFile) then
        ngx.log(ngx.WARN, "Rejected invalid rule file name: ", tostring(ruleFile))
        return nil
    end
    local file = io.open(CURRENT_PATH .. "rules/" .. ruleFile, "r")
    if file then
        local content = file:read("*a")
        file:close()
        return content
    end
    return nil
end

-- 更新规则配置（含文件名白名单校验与空环境沙箱语法/结构预检）
function _M.updateRule(ruleFile, ruleContent)
    if not isValidRuleFile(ruleFile) then
        ngx.log(ngx.WARN, "Rejected invalid rule file name on update: ", tostring(ruleFile))
        return false
    end
    local valid, err = validateRuleCode(ruleContent)
    if not valid then
        ngx.log(ngx.ERR, "Rejected unsafe or invalid rule content for ", ruleFile, ": ", err)
        return false
    end
    local file = io.open(CURRENT_PATH .. "rules/" .. ruleFile, "w")
    if file then
        file:write(ruleContent)
        file:close()
        return true
    end
    return false
end

-- 读取配置文件
function _M.readFile(fileName)
    -- 只允许读取conf.d目录下的特定文件
    local allowedFiles = {
        blackIp = true,
        whiteIp = true,
        whitehost = true,
        ["waf.conf"] = true
    }

    if not allowedFiles[fileName] then
        return nil
    end

    local file = io.open(CURRENT_PATH .. "conf.d/" .. fileName, "r")
    if file then
        local content = file:read("*a")
        file:close()
        return content
    end
    return nil
end

-- 更新规则状态
function _M.switchRule(ruleFile, enabled)
    if not isValidRuleFile(ruleFile) then
        ngx.log(ngx.ERR, "Invalid rule file name: ", tostring(ruleFile))
        return false
    end
    local ruleName = ruleFile:match("^([a-zA-Z0-9_]+)%.lua$")
    if not ruleName then
        ngx.log(ngx.ERR, "Invalid rule file name: ", ruleFile)
        return false
    end

    ngx.log(ngx.INFO, "Switching rule: ", ruleName, " to ", enabled and "on" or "off")

    -- 读取waf.conf文件
    local wafConfPath = CURRENT_PATH .. "conf.d/waf.conf"
    local file = io.open(wafConfPath, "r")
    if not file then
        ngx.log(ngx.ERR, "Failed to open waf.conf for reading")
        return false
    end

    local content = file:read("*a")
    file:close()

    -- 构建查找的规则配置项
    local ruleKey = "exp_" .. ruleName
    local newValue = enabled and "\"on\"" or "\"off\""

    -- 替换规则状态
    local pattern = "(" .. ruleKey .. ")%s*=%s*[\"']?[^\"'\r\n]*[\"']?"
    local count = 0
    local newContent = string.gsub(content, pattern, function()
        count = count + 1
        return ruleKey .. " = " .. newValue
    end)

    if count == 0 then
        ngx.log(ngx.WARN, "Config key not found: ", ruleKey, ", appending to file")
        newContent = content .. "\n" .. ruleKey .. " = " .. newValue .. "\n"
    else
        ngx.log(ngx.INFO, "Updated ", count, " occurrence(s) of ", ruleKey)
    end

    -- 写回文件
    file = io.open(wafConfPath, "w")
    if not file then
        ngx.log(ngx.ERR, "Failed to open waf.conf for writing")
        return false
    end

    file:write(newContent)
    file:close()

    if WAF_CONFIG then
        WAF_CONFIG[ruleKey] = enabled and "on" or "off"
    end

    return true
end

-- 保存配置文件
function _M.saveFile(fileName, content)
    -- 只允许保存conf.d目录下的特定文件
    local allowedFiles = {
        blackIp = true,
        whiteIp = true,
        whitehost = true,
        ["waf.conf"] = true
    }

    if not allowedFiles[fileName] or type(content) ~= "string" then
        return false
    end

    local file = io.open(CURRENT_PATH .. "conf.d/" .. fileName, "w")
    if file then
        file:write(content)
        file:close()
        return true
    end
    return false
end

-- 获取系统日志（校验日期格式、复用 sanitizeHost 清洗域名，并倒序返回最新 limit 条记录）
function _M.getLogs(host, date, limit)
    if type(date) ~= "string" or not date:match("^%d%d%d%d%-%d%d%-%d%d$") then
        ngx.log(ngx.WARN, "Invalid log query date: ", tostring(date))
        return {}
    end
    limit = tonumber(limit) or 100
    if limit < 1 then limit = 1 elseif limit > 1000 then limit = 1000 end

    local safeHost = logger.sanitizeHost(host)
    local ipUtil = require("ip")
    local baseLogsPath = (WAF_CONFIG and WAF_CONFIG["log_path"]) or (CURRENT_PATH .. "../logs/waf")
    local logFilePath = baseLogsPath .. "/" .. date .. "/" .. safeHost .. ".log"

    local file = io.open(logFilePath, "r")
    if not file then
        return {}
    end

    -- 使用环形缓冲区读取文件尾部最新的 limit 行，保证最新告警在前且内存占用恒定
    local ring = {}
    local total = 0
    for line in file:lines() do
        if line ~= "" then
            total = total + 1
            ring[((total - 1) % limit) + 1] = line
        end
    end
    file:close()

    local content = {}
    local count = math.min(total, limit)
    for i = 0, count - 1 do
        local idx = ((total - 1 - i) % limit) + 1
        local line = ring[idx]
        if line then
            local ok, logData = pcall(cjson.decode, line)
            if ok and logData and logData.ip then
                logData.ip_location = ipUtil.getIPLocation(logData.ip)
                line = cjson.encode(logData) or line
            end
            table.insert(content, line)
        end
    end
    return content
end

return _M
