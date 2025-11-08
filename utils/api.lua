local _M = {}
local cjson = require "cjson"
local cache = require "cache"
local logger = require "logger"
local localFile = require "localFile"

-- 获取统计数据
function _M.getStats()
    local countCache = require("cache"):new("nova_waf_count")
    local stats = {
        total_requests = tonumber(countCache:cacheGet("count_reqCount", 0)) or 0,
        blocked_requests = tonumber(countCache:cacheGet("count_reqDenyCount", 0)) or 0,
        blocked_ips = #BLACK_IPS or 0,
        os_distribution = {},
        status_distribution = {},
        host_distribution = {},
        top_ips = {}
    }
    
    -- 获取所有统计数据的key
    countCache:getAllPrefixKeys("count_", function(key)
        local val = tonumber(countCache:cacheGet(key, 0)) or 0
        
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
        
        -- 统计IP访问
        local ip_match = key:match("^count_ip_(.+)$")
        if ip_match then
            table.insert(stats.top_ips, {ip = ip_match, count = val})
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

-- 获取攻击类型分布
function _M.getAttackDistribution()
    local distribution = {
        sqli = ngx.shared.stats:get("attack_sqli") or 0,
        xss = ngx.shared.stats:get("attack_xss") or 0,
        cc = ngx.shared.stats:get("attack_cc") or 0,
        cmd = ngx.shared.stats:get("attack_cmd") or 0,
        other = ngx.shared.stats:get("attack_other") or 0
    }
    return distribution
end

-- 获取请求趋势数据
function _M.getRequestTrend()
    local trend = {}
    for i = 0, 23 do
        local key = string.format("requests_hour_%d", i)
        trend[i+1] = ngx.shared.stats:get(key) or 0
    end
    return trend
end

-- 获取IP黑名单
function _M.getBlackList()
    local blacklist = {}
    local file = io.open(CURRENT_PATH .. "conf.d/blackIp", "r")
    if file then
        for line in file:lines() do
            table.insert(blacklist, line)
        end
        file:close()
    end
    return blacklist
end


-- 重载WAF配置
function _M.reloadConfig()
    local success = true
    local message = "配置重载成功"

    -- 重新加载配置文件
    local ok, err = pcall(function()
        -- 重新加载WAF规则
        package.loaded["waf"] = nil
        package.loaded["init"] = nil
        require("waf")
        require("init")

        -- 重新加载规则模块
        local rules = {"bot", "cmd", "dns", "ldap", "path", "sensitive", "spring", "sqli", "ssrf", "xss", "xxe"}
        for _, rule in ipairs(rules) do
            package.loaded["rules." .. rule] = nil
            require("rules." .. rule)
        end

        -- 清理缓存
        ngx.shared.nova_waf:flush_all()

        -- 执行nginx -s reload命令
        local nginx_reload_ok = os.execute("nginx -s reload")
        if not nginx_reload_ok then
            error("Failed to reload Nginx configuration")
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
            table.insert(whitelist, line)
        end
        file:close()
    end
    return whitelist
end

-- 添加IP到白名单
function _M.addToWhiteList(ip)
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
        if file:match(".lua$") then
            local ruleName = file:match("(.+).lua$")
            local ruleModule = require("rules." .. ruleName)
            rules[ruleName] = {
                file = file,
                name = ruleModule.name,
                desc = ruleModule.desc
            }
        end
    end
    return rules
end

-- 获取单个规则文件内容
function _M.getRuleContent(ruleFile)
    local file = io.open(CURRENT_PATH .. "rules/" .. ruleFile, "r")
    if file then
        local content = file:read("*a")
        file:close()
        return content
    end
    return nil
end

-- 更新规则配置
function _M.updateRule(ruleFile, ruleContent)
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
        whitehost = true
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
    return false
end

-- 更新规则状态
function _M.switchRule(ruleFile, enabled)
    -- 获取规则名称（去掉.lua后缀）
    local ruleName = ruleFile:match("(.+)%.lua$")
    if not ruleName then return false end
    
    -- 读取waf.conf文件
    local wafConfPath = CURRENT_PATH .. "conf.d/waf.conf"
    local file = io.open(wafConfPath, "r")
    if not file then return false end
    
    local content = file:read("*a")
    file:close()
    
    -- 构建查找的规则配置项
    local ruleKey = "exp_" .. ruleName
    local newValue = enabled and "\"on\"" or "\"off\""
    
    -- 替换规则状态
    local pattern = "(" .. ruleKey .. ")%s*=%s*\"[^\"]*\""
    local newContent = string.gsub(content, pattern, ruleKey .. " = " .. newValue)
    
    -- 写回文件
    file = io.open(wafConfPath, "w")
    if not file then return false end
    
    file:write(newContent)
    file:close()
    
    return true
end
-- 保存配置文件
function _M.saveFile(fileName, content)
    -- 只允许保存conf.d目录下的特定文件
    local allowedFiles = {
        blackIp = true,
        whiteIp = true,
        whitehost = true
    }
    
    if not allowedFiles[fileName] then
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

-- 获取系统日志
function _M.getLogs(host, date, limit)
    local wafLogsPath = CURRENT_PATH .. "../logs/waf/"
    local file = io.open(wafLogsPath..date.."/"..host..".log", "r")
    if file then
        local content = {}
        for i = 1,limit do
            local line = file:read("*l")
            if not line then
                break
            end
            table.insert(content, line)
        end
        file:close()
        return content
    end
    return false
end

return _M