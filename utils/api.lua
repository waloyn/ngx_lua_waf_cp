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

-- 获取统计数据
function _M.getStats()
    local countCache = require("cache"):new("nova_waf_count")
    local stats = {
        total_requests = tonumber(countCache:cacheGet("count_reqCount")) or 0,
        blocked_requests = tonumber(countCache:cacheGet("count_reqDenyCount")) or 0,
        blocked_ips = (BLACK_IPS and #BLACK_IPS) or 0,
        os_distribution = {},
        status_distribution = {},
        host_distribution = {},
        attack_types = {},
        top_ips = {}
    }

    -- 获取所有统计数据的key
    countCache:getAllPrefixKeys("count_", function(key)
        local val = tonumber(countCache:cacheGet(key)) or 0

        -- 统计操作系统分布
        local os_match = key:match("^count_os_(.+)$")
        if os_match then
            stats.os_distribution[os_match] = val
        end

        -- 统计状态码分布
        local status_match = key:match("^count_status_(%d+)$")
        if status_match then
            stats.status_distribution[status_match] = val
        end

        -- 统计域名访问分布
        local host_match = key:match("^count_host_(.+)$")
        if host_match then
            stats.host_distribution[host_match] = val
        end

        -- 统计攻击类型分布
        local attack_match = key:match("^count_attack_(.+)$")
        if attack_match then
            stats.attack_types[attack_match] = val
        end

        -- 统计IP访问
        local ip_match = key:match("^count_ip_(.+)$")
        if ip_match then
            table.insert(stats.top_ips, { ip = ip_match, count = val })
        end
    end)

    -- 对IP访问量进行排序，只返回前20个
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
