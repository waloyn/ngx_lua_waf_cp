---@diagnostic disable: need-check-nil
local localCache = require "cache"
local localCount = require "count"
local cjson = require "cjson.safe"   -- safe 版本：编码失败返回 nil+err 而非 raise
local decoder = require "decoder"
local ip = require "ip"

-- 缓存 403 页面内容（模块级缓存，只读取一次；修改 403.html 需 reload nginx）
local cached403Content = nil
local function get403Content()
    if cached403Content then
        return cached403Content
    end
    local file, err = io.open(CURRENT_PATH .. "conf.d/403.html", "r")
    if not file then
        ngx.log(ngx.ERR, "Failed to open 403.html: ", err)
        return "<html><body><h1>403 Forbidden</h1></body></html>"
    end
    cached403Content = file:read("*all")
    file:close()
    return cached403Content
end

-- HTML 转义，防止模板渲染产生 XSS
local HTML_ESCAPE_MAP = { ['&'] = '&amp;', ['<'] = '&lt;', ['>'] = '&gt;', ['"'] = '&quot;', ["'"] = '&#39;' }
local function htmlEscape(s)
    if s == nil then return "" end
    return (string.gsub(tostring(s), "[&<>\"']", HTML_ESCAPE_MAP))
end

-- 安全替换模板占位符：用 function 形式，避免替换串中 `%` 被 gsub 当元字符处理
local function safeReplace(content, placeholder, value)
    local escaped = htmlEscape(value)
    return (string.gsub(content, placeholder, function() return escaped end))
end

-- 异步写日志，避免在 access 热路径同步 IO
local function asyncLog(host, logStr)
    local ok, err = ngx.timer.at(0, function(premature, h, s)
        if premature then return end
        -- 在 timer 上下文内重新 require，避免依赖跨上下文的 upvalue（reload/worker 边界下可能为 nil）
        local ok_req, logger_mod = pcall(require, "logger")
        if not ok_req or not logger_mod then
            ngx.log(ngx.ERR, "asyncLog: failed to require logger: ", tostring(logger_mod))
            return
        end
        local hostLogger = logger_mod:new(h)
        hostLogger:log(s .. '\n')
    end, host, logStr)
    if not ok then
        ngx.log(ngx.ERR, "failed to create log timer: ", err)
    end
end

local Waf = {}
Waf.__index = Waf

-- Constructor
function Waf:new()
    local ipAddr = ip.getClientIP()
    -- 0 表示不限制 header 数量，避免攻击者发 >100 个 header 时形成 WAF 盲区
    local headers = ngx.req.get_headers(0)
    local host = headers["Host"] or headers["host"] or ngx.var.host
    local instance = {
        ip = ipAddr,
        host = host,
        headers = headers,
        request_id = ngx.var.request_id,
        key_block = "block:" .. ipAddr,
        key_possibly = "possibly:" .. ipAddr,
        key_attack = "attack:" .. ipAddr,
        key_attack_count = "attackCount:" .. ipAddr,
        key_cc = "cc:" .. ipAddr,

        possibly_timeout = tonumber(WAF_CONFIG["possibly_timeout"]) or 300,
        possibly_count = tonumber(WAF_CONFIG["possibly_count"]) or 10,
        block_count = tonumber(WAF_CONFIG["block_count"]) or 10,
        block_time = tonumber(WAF_CONFIG["block_time"]) or 600,
        block_timeout = tonumber(WAF_CONFIG["block_timeout"]) or 600,
        cache = localCache:new(),
        count = localCount:new(),
    }
    setmetatable(instance, self)
    return instance
end

function Waf:isWhiteIp()
    if WHITE_IP_SET[self.ip] == true then
        return true
    end
    return ip.isIpInCidrs(self.ip, WHITE_CIDRS)
end

function Waf:isWhiteHost()
    if not self.host then
        return false
    end
    local lower_host = tostring(self.host):lower()
    if WHITE_HOST_SET[lower_host] == true then
        return true
    end
    local host_only = lower_host:match("^([^:]+)")
    return host_only ~= nil and WHITE_HOST_SET[host_only] == true
end

function Waf:isBlackIp()
    if BLACK_IP_SET[self.ip] == true then
        return true
    end
    return ip.isIpInCidrs(self.ip, BLACK_CIDRS)
end

function Waf:isBlockedIp()
    local value = self.cache:cacheGet(self.key_block)
    if value then
        return true
    end
    return false
end

function Waf:ret403(msg)
    self.count:addReqDenyCount()
    local content = get403Content()

    ngx.header.content_type = "text/html"
    ngx.status = ngx.HTTP_FORBIDDEN
    -- 用 function 形式替换，避免替换串中 `%` 被 gsub 解释为捕获引用
    content = safeReplace(content, "{BLOCK_REASON}", msg)
    content = safeReplace(content, "{REQUEST_ID}", self.request_id)
    content = safeReplace(content, "{REQUEST_TIME}", ngx.localtime())
    content = safeReplace(content, "{IP}", self.ip)
    if WAF_CONFIG["debug"] == "on" then
        ngx.say(htmlEscape(msg))
    else
        ngx.say(content)
    end
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

function Waf:recordRequest(rule, body)
    local logTable = {
        request_id = self.request_id,
        attack_type = rule,
        ip = self.ip,
        request_time = ngx.localtime(),
        http_method = ngx.var.request_method,
        request_uri = ngx.var.request_uri,
        request_protocol = ngx.var.server_protocol,
        request_data = body,
        user_agent = ngx.var.http_user_agent,
        headers = self.headers
    }
    local logStr, err = cjson.encode(logTable)
    if logStr then
        asyncLog(self.host, logStr)
    else
        ngx.log(ngx.ERR, "failed to encode json: ", err)
    end
end

function Waf:blockIp(attackCount)
    -- debug 模式下不进行IP封锁
    if WAF_CONFIG["debug"] == "on" then
        return true
    end
    -- 在相当长的一段时间内如果又发生IP封禁行为，将会延长封禁时间
    self.cache:cacheSet(self.key_block, 1, self.block_timeout * attackCount)
    self.cache:cacheDel(self.key_possibly)
    self.cache:cacheDel(self.key_attack)
    -- 记录在100分钟内的攻击次数，用于提高封禁时间
    self.cache:cacheSet(self.key_attack_count, attackCount, self.block_timeout * 10)
    ngx.log(ngx.INFO, "Block IP: ", self.ip, " for ", self.block_timeout * attackCount, " seconds")
end

function Waf:inAttack(rule, body, level, desc, possibly)
    self:recordRequest(rule, body)
    self.count:addAttackCount(rule)

    -- 监控模式下仅记录日志与统计，不拦截请求
    if WAF_CONFIG["mode"] == "monitor" then
        return false
    end

    -- 连续攻击封禁IP
    local attackCount = tonumber(self.cache:cacheGet(self.key_attack_count) or 0)
    ngx.log(ngx.INFO, self.ip, " attackCount: ", attackCount)
    if attackCount > 0 then
        self:blockIp(attackCount + 1)
        return true
    end

    -- 累加可疑度评分（原子递增，避免多 worker 竞态）
    local weight = tonumber(possibly) or 1
    local total = self.cache:cacheIncr(self.key_possibly, weight, self.possibly_timeout) or weight
    ngx.log(ngx.INFO, self.ip, " possibly: ", total)
    if total < tonumber(self.possibly_count) then
        -- 尚未达到触发拦截的置信度阈值，放行本次请求
        return false
    end

    -- 置信度达到阈值，记录本次恶意攻击行为并拦截本次请求
    local attackValue = self.cache:cacheIncr(self.key_attack, 1, self.block_time) or 1
    ngx.log(ngx.INFO, self.ip, " attack: ", attackValue)

    if attackValue >= self.block_count then
        self:blockIp(1)
    end
    return true
end

function Waf:isBigRequest()
    local body_size = self:calculateRequestSize()
    local max_body_size = tonumber(WAF_CONFIG["body_max_size"]) or (1024 * 1024)
    if body_size > max_body_size then
        return true
    end
    return false
end

function Waf:isCCAttack()
    if WAF_CONFIG["cc_defence"] == "off" then
        return false
    end
    local limit = tonumber(WAF_CONFIG["cc_limit"]) or 100
    local seconds = tonumber(WAF_CONFIG["cc_seconds"]) or 60

    -- 原子递增，避免高并发计数丢失
    local count = self.cache:cacheIncr(self.key_cc, 1, seconds) or 1
    if count > limit then
        return true
    end
    return false
end

-- 读取并缓存请求 body（一次性）：避免 attack 和 calculateRequestSize 重复 read_body + io.open
function Waf:_getRawBody()
    if self._raw_body_cached then
        return self._raw_body
    end
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        -- body 落盘到临时文件时，get_body_data 返回 nil，回读文件避免规则绕过
        local body_file = ngx.req.get_body_file()
        if body_file then
            local f = io.open(body_file, "rb")
            if f then
                body = f:read("*all")
                f:close()
            end
        end
    end
    self._raw_body = body or ""
    self._raw_body_cached = true
    return self._raw_body
end

function Waf:attack()
    local max_decode_count = tonumber(WAF_CONFIG["decode_max_count"] or 10)
    local raw_uri = ngx.var.request_uri or ""
    local checkData = {}

    local uri = decoder.unescape(raw_uri, max_decode_count)
    if uri == nil then
        if self:inAttack("Malicious encoding - URI", "", "high", "恶意编码攻击", self.possibly_count) then
            self:ret403("Malicious encoding detected.")
        end
        return
    end
    table.insert(checkData, { pos = "uri", is_header = false, text = uri })

    -- headers 逐值入 checkData，避免 join 后跨值误命中
    for k, v in pairs(self.headers) do
        local k_lower = string.lower(tostring(k))
        local values = type(v) == "table" and v or { v }
        for _, vv in ipairs(values) do
            local decoded_val = decoder.unescape(tostring(vv), max_decode_count)
            if decoded_val == nil then
                if self:inAttack("Malicious encoding - Header", "", "high", "恶意编码攻击", self.possibly_count) then
                    self:ret403("Malicious encoding detected.")
                end
                return
            end
            table.insert(checkData, {
                pos = k_lower,
                is_header = true,
                text = k_lower .. ": " .. decoded_val
            })
        end
    end

    local body = decoder.unescape(self:_getRawBody(), max_decode_count)
    if body == nil then
        if self:inAttack("Malicious encoding - Body", "", "high", "恶意编码攻击", self.possibly_count) then
            self:ret403("Malicious encoding detected.")
        end
        return
    end
    if body ~= "" then
        table.insert(checkData, { pos = "body", is_header = false, text = body })
    end

    -- 规则匹配（positions 和 pattern 已在 init 阶段预处理）
    for _, item in ipairs(checkData) do
        for _, rule in pairs(RULE_FILES) do
            local hit_pos = nil
            for _, p in ipairs(rule.positions) do
                if item.pos == p or (p == "headers" and item.is_header) then
                    hit_pos = item.pos
                    break
                end
            end
            if hit_pos then
                for _, patternItem in ipairs(rule.rules) do
                    if ngx.re.match(item.text, patternItem.pattern, "isjo") then
                        local should_block = self:inAttack(
                            rule.name .. " - " .. hit_pos .. " - " .. patternItem.name,
                            body,
                            rule.level,
                            rule.desc,
                            patternItem.confidence
                        )
                        if should_block then
                            if WAF_CONFIG["debug"] == "on" then
                                self:ret403("Attack detected, Debug msg: " ..
                                    rule.name ..
                                    " - " .. patternItem.name .. " => " .. patternItem.pattern .. " [TEXT] => " .. item.text)
                            else
                                self:ret403("Attack detected.")
                            end
                            return
                        end
                        -- 若未达拦截阈值（如低置信度累加中或处于 monitor 模式），跳出当前规则继续审计其余规则
                        break
                    end
                end
            end
        end
    end
end

function Waf:calculateRequestSize()
    local headers_size = 0
    for k, v in pairs(self.headers) do
        headers_size = headers_size + #k
        if type(v) == "table" then
            for _, vv in ipairs(v) do
                headers_size = headers_size + #vv
            end
        else
            headers_size = headers_size + #v
        end
    end

    -- chunked 传输无 content_length，复用已缓存的 body 长度（避免重复读文件）
    local body_length = tonumber(ngx.var.content_length)
    if not body_length then
        body_length = #self:_getRawBody()
    end
    local method_size = #ngx.req.get_method()
    local uri_size = #ngx.var.request_uri

    return headers_size + body_length + method_size + uri_size
end

function Waf:process()
    self.count:addReqCount(self.ip)
    local mode = WAF_CONFIG["mode"]
    if mode == "off" then
        ngx.log(ngx.INFO, "WAF is off")
        return
    elseif self:isWhiteIp() then
        ngx.log(ngx.INFO, "White IP: ", self.ip)
        return
    elseif self:isWhiteHost() then
        ngx.log(ngx.INFO, "White HOST: ", tostring(self.host))
        return
    end

    local is_monitor = (mode == "monitor")

    if self:isBlackIp() then
        ngx.log(ngx.WARN, "Black IP: ", self.ip)
        if not is_monitor then
            self:ret403("Your IP has been blacklisted")
            return
        end
    elseif self:isBlockedIp() then
        ngx.log(ngx.WARN, "Blocked IP: ", self.ip)
        if not is_monitor then
            self:ret403("Your IP has been blocked")
            return
        end
    elseif self:isCCAttack() then
        ngx.log(ngx.WARN, "CC Attack: ", self.ip)
        self:recordRequest("CC Attack", "")
        self.count:addAttackCount("cc")
        if not is_monitor then
            self:ret403("CC Attack")
            return
        end
    elseif self:isBigRequest() then
        ngx.log(ngx.WARN, "Big request: ", self.ip)
        if not is_monitor then
            self:ret403("Request body is too large")
            return
        end
    end

    self:attack()
end

if ngx and ngx.get_phase and ngx.get_phase() == "access" then
    local myWaf = Waf:new()
    myWaf:process()
end

return Waf
