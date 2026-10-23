local localCache = require "cache"
local _M = {}
_M.__index = _M

-- 动态统计键默认 TTL（24 小时），防止恶意扫描随机 Referer/Host 撑爆 nova_waf_count 共享内存
local DYNAMIC_KEY_TTL = 86400

-- 创建新的统计对象
function _M:new()
    local t = {
        KEY_PREFIX = "count_",
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
    local key = "os_unknown"
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

-- 记录攻击类型分布
function _M:addAttackCount(ruleName)
    if not ruleName then
        self:Incr("attack_other")
        return
    end
    local lower = string.lower(ruleName)
    if lower:find("sql", 1, true) then
        self:Incr("attack_sqli")
    elseif lower:find("xss", 1, true) then
        self:Incr("attack_xss")
    elseif lower:find("cc", 1, true) then
        self:Incr("attack_cc")
    elseif lower:find("command", 1, true) or lower:find("cmd", 1, true) then
        self:Incr("attack_cmd")
    else
        self:Incr("attack_other")
    end
end

function _M:save2Disk(lastDay, hour)
    local keysData = {}
    self.cache:getAllPrefixKeys(self.KEY_PREFIX, function(key)
        local val = tonumber(self.cache:cacheGet(key) or 0)
        self.cache:cacheDel(key)
        keysData[key] = val
    end)

    -- 每个小时的数据保存为JSON格式,存储为 count/20210101/01.json 的形式
    local path = "count/" .. tostring(lastDay)
    local fileName = string.format("%02d.json", tonumber(hour) or 0)
    local localFile = require "localFile"
    local json = require "cjson.safe"
    local encoded = json.encode(keysData)
    if encoded then
        localFile.writeFile(path, fileName, encoded)
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

    -- 无论是否持有归档锁，当前请求的原子递增计数必须无条件执行，避免并发丢数
    self.cache:cacheIncr(self.KEY_PREFIX .. key, 1, expireTime)
end

return _M
