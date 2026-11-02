local localCache = require "cache"
local _M = {}
_M.__index = _M

-- 动态统计键默认 TTL（24 小时），防止恶意扫描随机 Referer/Host 撑爆 nova_waf_count 共享内存
local DYNAMIC_KEY_TTL = 86400

-- 创建新的统计对象
function _M:new()
    local t = {
        KEY_PREFIX = "count_",
        HOURLY_PREFIX = "hourly_",
        REQ_COUNT = "reqCount",
        REQ_DENY_COUNT = "reqDenyCount",
        LAST_DAY = "lastDay",
        LAST_DAY_HOUR = "lastDayHour",
        LOCK_KEY = "count_lock",
        cache = localCache:new("nova_waf_count"),
        lock_dict = ngx.shared.dict_locks
    }

    setmetatable(t, self)
    return t
end

-- 函数用于判断是否为爬虫
local function is_crawler(ua)
    local crawlers = {
        "bot", "spider", "crawler", "slurp", "archiver", "search"
    }
    local lower_ua = string.lower(ua)
    for _, crawler in ipairs(crawlers) do
        if string.find(lower_ua, crawler, 1, true) then
            return true
        end
    end
    return false
end

-- 有序操作系统匹配列表（必须先匹配移动/子特征如 Windows Phone、Android、iPhone/iPad，再匹配通用 Linux / Mac OS X）
local OS_PATTERNS = {
    { "Windows Phone", "Windows Phone" },
    { "Android",       "Android" },
    { "iPhone",        "iOS" },
    { "iPad",          "iOS" },
    { "Windows NT 10.0", "Windows 10/11" },
    { "Windows NT 6.3",  "Windows 8.1" },
    { "Windows NT 6.2",  "Windows 8" },
    { "Windows NT 6.1",  "Windows 7" },
    { "Windows NT 6.0",  "Windows Vista" },
    { "Windows NT 5.2",  "Windows Server 2003/XP x64" },
    { "Windows NT 5.1",  "Windows XP" },
    { "Windows NT 5.0",  "Windows 2000" },
    { "Macintosh",     "Mac OS X" },
    { "BlackBerry",    "BlackBerry" },
    { "FreeBSD",       "FreeBSD" },
    { "OpenBSD",       "OpenBSD" },
    { "NetBSD",        "NetBSD" },
    { "SunOS",         "Solaris" },
    { "Linux",         "Linux" },
}

local function detect_os(ua)
    for i = 1, #OS_PATTERNS do
        local item = OS_PATTERNS[i]
        if string.find(ua, item[1], 1, true) then
            return item[2]
        end
    end
    return "Unknown"
end

function _M:addReqCount(ip)
    self:Incr(self.REQ_COUNT)

    -- 记录当前小时请求趋势
    local current_time = os.date("*t", ngx.time())
    if current_time and current_time.hour then
        self:Incr("requests_hour_" .. current_time.hour, DYNAMIC_KEY_TTL)
    end

    -- 进行UA分析
    local ua = ngx.var.http_user_agent
    local key = "os_Unknown"
    if ua then
        if is_crawler(ua) then
            key = "os_crawler"
        else
            key = "os_" .. detect_os(ua)
        end
    end
    self:Incr(key)

    -- 进行访问域名分析（截断超长异常 Host 并设置 TTL 防共享内存耗尽）
    local host = ngx.var.host
    if host and #host > 0 and #host <= 128 then
        self:Incr("host_" .. host, DYNAMIC_KEY_TTL)
    end

    -- 进行来源分析（仅提取 Referer 域名部分或截断至 128 字符，防随机 URL 撑爆字典）
    local referer = ngx.var.http_referer
    if referer and #referer > 0 then
        local ref_host = referer:match("^https?://([^/]+)") or referer:sub(1, 128)
        self:Incr("referer_" .. ref_host, DYNAMIC_KEY_TTL)
    end

    -- 进行IP来源分析
    if ip and #ip <= 64 then
        self:Incr("ip_" .. ip, DYNAMIC_KEY_TTL)
    end
end

function _M:addStatusCount()
    local status = ngx.status
    if status then
        self:Incr("status_" .. status)
    end
end

function _M:addReqDenyCount()
    self:Incr(self.REQ_DENY_COUNT)
end

-- 智能分类攻击类型、统计键名、攻击目标与是否为CC攻击（对齐安全分析报告）
local function classifyAttack(ruleName, uri)
    local raw = (ruleName or "") .. " " .. (uri or "")
    local lower = string.lower(raw)

    if lower:find("cc", 1, true) then
        return "CC攻击", "cc", "其他", true
    elseif lower:find("blind", 1, true) or lower:find("sleep", 1, true) or lower:find("benchmark", 1, true) or lower:find("waitfor", 1, true) then
        return "SQL盲注攻击探测", "sql_blind", "数据", false
    elseif lower:find("sql", 1, true) then
        return "SQL注入攻击", "sqli", "数据", false
    elseif lower:find("xss", 1, true) or lower:find("script", 1, true) or lower:find("alert", 1, true) then
        return "跨站脚本攻击(XSS)", "xss", "应用", false
    elseif lower:find("command", 1, true) or lower:find("cmd", 1, true) or lower:find("rce", 1, true) or lower:find("execution", 1, true) then
        return "远程代码执行漏洞攻击", "cmd", "服务器", false
    elseif lower:find("path traversal", 1, true) or lower:find("traversal", 1, true) or lower:find("include", 1, true) or lower:find("lfi", 1, true) or lower:find("rfi", 1, true) or lower:find("/%.%./", 1, true) then
        return "文件包含漏洞攻击", "file_inclusion", "文件", false
    elseif lower:find("sensitive", 1, true) and (lower:find("dir", 1, true) or lower:find("directory", 1, true) or lower:find("path", 1, true)) then
        return "敏感目录访问", "sensitive_dir", "文件", false
    elseif lower:find("sensitive", 1, true) or lower:find("info%.php", 1, true) or lower:find("install%.php", 1, true) or lower:find("swagger", 1, true) then
        return "敏感文件探测", "sensitive_file", "文件", false
    elseif lower:find("backup", 1, true) or lower:find("leak", 1, true) or lower:find("%.zip", 1, true) or lower:find("%.tar", 1, true) or lower:find("%.rar", 1, true) or lower:find("%.bak", 1, true) or lower:find("upload", 1, true) or lower:find("%.env", 1, true) then
        return "可疑文件访问", "suspicious_file", "文件", false
    elseif lower:find("bot", 1, true) or lower:find("crawler", 1, true) or lower:find("scan", 1, true) or lower:find("spider", 1, true) or lower:find("unknown", 1, true) then
        return "Unknown扫描", "scanner", "其他", false
    elseif lower:find("encoding", 1, true) or lower:find("character", 1, true) or lower:find("special", 1, true) then
        return "特殊字符URL访问", "special_url", "应用", false
    elseif lower:find("xxe", 1, true) or lower:find("entity", 1, true) then
        return "XML外部实体注入", "xxe", "数据", false
    elseif lower:find("ssrf", 1, true) then
        return "SSRF漏洞攻击", "ssrf", "应用", false
    elseif lower:find("ssti", 1, true) then
        return "SSTI模板注入", "ssti", "应用", false
    elseif lower:find("deserialize", 1, true) then
        return "反序列化漏洞攻击", "deserialize", "服务器", false
    elseif lower:find("spring", 1, true) then
        return "Spring框架漏洞攻击", "spring", "应用", false
    elseif lower:find("dns", 1, true) or lower:find("ceye", 1, true) then
        return "DNS重绑定攻击", "dns", "服务器", false
    elseif lower:find("nosql", 1, true) then
        return "NoSQL注入", "nosql", "数据", false
    else
        return "其他攻击", "other", "其他", false
    end
end
_M.classifyAttack = classifyAttack

-- 记录攻击类型分布及多维指标
function _M:addAttackCount(ruleName, ip, host, uri)
    if not ruleName then
        self:Incr("attack_other")
        return
    end

    local cat_name, cat_key, target, is_cc = classifyAttack(ruleName, uri)
    local current_time = os.date("*t", ngx.time())
    local hour = (current_time and current_time.hour) or 0

    -- 1. 兼容原有统计键 (attack_sqli, attack_xss, etc.)
    self:Incr("attack_" .. cat_key)

    -- 2. 细化中文分类统计（用于漏洞类型饼图与行为统计矩阵）
    self:Incr("atkname_" .. cat_name)

    -- 3. 攻击目标分类统计（数据、应用、服务器、文件、其他，用于雷达图）
    self:Incr("target_" .. target)

    -- 4. 区分漏洞攻击与 CC 攻击
    if is_cc then
        self:Incr("attack_cc_total")
        self:Incr("cc_hour_" .. hour, DYNAMIC_KEY_TTL)
        if ip and #ip <= 64 then
            self:Incr("cc_ip_" .. ip, DYNAMIC_KEY_TTL)
        end
    else
        self:Incr("attack_vuln_total")
        self:Incr("vuln_hour_" .. hour, DYNAMIC_KEY_TTL)
        if ip and #ip <= 64 then
            self:Incr("vuln_ip_" .. ip, DYNAMIC_KEY_TTL)
        end
    end

    -- 5. 恶意 IP 统计与地理归属统计
    if ip and #ip <= 64 then
        self:Incr("attacker_ip_" .. ip, DYNAMIC_KEY_TTL)
        local ok, ipUtil = pcall(require, "ip")
        if ok and ipUtil and ipUtil.getIPLocation then
            local loc = ipUtil.getIPLocation(ip)
            if loc and loc ~= "" then
                local country = loc:match("^([^-]+)") or loc
                if country == "内网IP" then country = "局域网" end
                self:Incr("attack_geo_" .. country, DYNAMIC_KEY_TTL)
            end
        end
    end

    -- 6. 受攻击 HOST 统计
    if host and #host > 0 and #host <= 128 then
        self:Incr("attack_host_" .. host, DYNAMIC_KEY_TTL)
    end
end

function _M:save2Disk(lastDay, hour)
    local keysData = {}
    self.cache:getAllPrefixKeys(self.HOURLY_PREFIX, function(key)
        local val = tonumber(self.cache:cacheGet(key) or 0)
        self.cache:cacheDel(key)
        -- 将 hourly_ 转换为 count_ 保存至磁盘 JSON，保持与已有历史 JSON 格式完全一致
        local diskKey = key:gsub("^" .. self.HOURLY_PREFIX, self.KEY_PREFIX)
        keysData[diskKey] = val
    end)

    -- 每个小时的数据保存为JSON格式,存储为 count/20210101/01.json 的形式
    local path = "count/" .. tostring(lastDay)
    local fileName = string.format("%02d.json", tonumber(hour) or 0)
    local localFile = require "localFile"
    local json = require "cjson.safe"
    local encoded = json.encode(keysData)
    if encoded then
        localFile.writeFile(path, fileName, encoded, "wb")
    end
end

function _M:onExitNginx()
    if WAF_CONFIG and WAF_CONFIG["statistics"] == "off" then
        return
    end
    local current_time = os.date("*t", ngx.time())
    local hour = current_time.hour
    local lastDayHour = self.cache:cacheGet(self.LAST_DAY_HOUR) or hour
    local lastDay = self.cache:cacheGet(self.LAST_DAY) or ngx.today()

    self:save2Disk(lastDay, lastDayHour)
end

function _M:Incr(key, expireTime)
    -- 未开启统计
    if WAF_CONFIG and WAF_CONFIG["statistics"] == "off" then
        return
    end

    local current_time = os.date("*t", ngx.time())
    local nowDayHour = current_time.hour
    local nowDay = ngx.today()

    local lastDayHour = self.cache:cacheGet(self.LAST_DAY_HOUR)
    local lastDay = self.cache:cacheGet(self.LAST_DAY)

    -- 当日期或小时发生变化时，使用带 TTL 的原子锁执行上一时段归档落盘
    if lastDayHour ~= nowDayHour or lastDay ~= nowDay then
        if self.lock_dict and self.lock_dict:add(self.LOCK_KEY, true, 10) then
            -- 双重检查，防止多 Worker 重复归档
            local curLastHour = self.cache:cacheGet(self.LAST_DAY_HOUR)
            local curLastDay = self.cache:cacheGet(self.LAST_DAY)
            if curLastHour ~= nowDayHour or curLastDay ~= nowDay then
                self.cache:cacheSet(self.LAST_DAY_HOUR, nowDayHour)
                self.cache:cacheSet(self.LAST_DAY, nowDay)
                if curLastHour ~= nil and curLastDay ~= nil then
                    self:save2Disk(curLastDay, curLastHour)
                end
            end
            self.lock_dict:delete(self.LOCK_KEY)
        end
    end

    -- 无论是否持有归档锁，当前请求的原子递增计数：
    -- 1. count_ 前缀作为进程启动以来的总计（保留在内存中，不被按小时删除）
    self.cache:cacheIncr(self.KEY_PREFIX .. key, 1, expireTime)
    -- 2. hourly_ 前缀作为当前小时的独立统计（按小时归档落盘并清空）
    self.cache:cacheIncr(self.HOURLY_PREFIX .. key, 1, expireTime or DYNAMIC_KEY_TTL)
end

return _M
