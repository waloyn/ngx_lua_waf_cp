---@diagnostic disable: need-check-nil
local localCache = require "cache"
local localCount = require "count"
local cjson = require "cjson.safe"   -- safe 版本：编码失败返回 nil+err 而非 raise
local decoder = require "decoder"
local ip = require "ip"
local behavior = require "behavior"
local challenge = require "challenge"

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

-- 是否已通过人机挑战（签名 Cookie 绑定 IP，有效期由 cc_challenge_ttl 控制）
function Waf:hasPassedChallenge()
    if not self:isChallengeEnabled() then
        return false
    end
    return challenge.is_passed(self)
end

-- 静态资源扩展名：只对页面导航做挑战/行为评估，避免图片、脚本把挑战页当资源加载
local STATIC_EXT = {
    css = true, js = true, mjs = true, map = true,
    png = true, jpg = true, jpeg = true, gif = true, webp = true, avif = true, bmp = true, svg = true, ico = true,
    woff = true, woff2 = true, ttf = true, otf = true, eot = true,
    mp3 = true, mp4 = true, webm = true, ogg = true, wav = true, flv = true, m3u8 = true, ts = true,
    zip = true, gz = true, rar = true, ["7z"] = true, tar = true, pdf = true, doc = true, docx = true,
    xls = true, xlsx = true, ppt = true, pptx = true, txt = true, csv = true,
}

-- 仅对浏览器页面导航请求做人机挑战，静态资源/接口请求保持原有 429 语义
function Waf:isNavigationRequest()
    -- 只挑战 GET：HEAD 没有响应体，POST 多为接口提交
    if ngx.req.get_method() ~= "GET" then
        return false
    end
    local uri = ngx.var.uri or ""
    local ext = uri:match("%.([%w]+)$")
    if ext and STATIC_EXT[string.lower(ext)] then
        return false
    end
    local dest = behavior.header(self, "sec-fetch-dest")
    if dest then
        return dest == "document" or dest == "iframe" or dest == "frame"
    end
    local accept = behavior.header(self, "accept") or ""
    return string.find(string.lower(accept), "text/html", 1, true) ~= nil
end

-- 计算行为风险分（供 CC 触发后的分级处置与日志使用）
function Waf:behaviorScore()
    if WAF_CONFIG["behavior_defence"] == "off" then
        return 0, {}
    end
    return behavior.evaluate(self, self:isNavigationRequest())
end

-- 统一的拦截响应：按 status 返回（403=规则拦截，429=CC 限流）
function Waf:retStatus(status, msg)
    self.count:addReqDenyCount()
    local content = get403Content()

    ngx.header.content_type = "text/html"
    ngx.status = status
    -- 用 function 形式替换，避免替换串中 `%` 被 gsub 解释为捕获引用
    content = safeReplace(content, "{BLOCK_REASON}", msg)
    content = safeReplace(content, "{REQUEST_ID}", self.request_id)
    content = safeReplace(content, "{REQUEST_TIME}", ngx.localtime())
    content = safeReplace(content, "{IP}", self.ip)
    content = safeReplace(content, "{STATUS}", tostring(status))
    content = safeReplace(content, "{STATUS_TEXT}", status == 429 and "请求过于频繁" or "访问被拒绝")
    if WAF_CONFIG["debug"] == "on" then
        ngx.say(htmlEscape(msg))
    else
        ngx.say(content)
    end
    ngx.exit(status)
end

-- 兼容保留：默认 403 拦截
function Waf:ret403(msg)
    return self:retStatus(ngx.HTTP_FORBIDDEN, msg)
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
    self.count:addAttackCount(rule, self.ip, self.host, ngx.var.request_uri)

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

function Waf:isCCAttack(passed)
    if WAF_CONFIG["cc_defence"] == "off" then
        return false
    end
    local limit = tonumber(WAF_CONFIG["cc_limit"]) or 100
    local seconds = tonumber(WAF_CONFIG["cc_seconds"]) or 60

    local key = self.key_cc
    if passed then
        -- 已通过挑战的客户端使用独立的高水位计数，防止“解一次题后无限刷”
        local factor = tonumber(WAF_CONFIG["cc_passed_factor"]) or 6
        if factor < 1 then factor = 1 end
        limit = limit * factor
        key = "ccp:" .. self.ip
    end

    -- 原子递增，避免高并发计数丢失
    local count = self.cache:cacheIncr(key, 1, seconds) or 1
    if count > limit then
        return true
    end
    return false
end

-- 人机挑战是否启用（cc_challenge=off 时全部回退为原有 429/403 语义）
function Waf:isChallengeEnabled()
    return (WAF_CONFIG["cc_challenge"] or "auto") ~= "off"
end

-- 行为特征风险分级：返回 "challenge"（进挑战）、"block"（直接拒绝）或 nil（放行）
-- 仅对浏览器导航请求评估，静态资源与接口请求继续沿用 CC 限流逻辑
function Waf:behaviorVerdict()
    if WAF_CONFIG["behavior_defence"] == "off" then
        return nil, 0, {}
    end
    if not self:isNavigationRequest() then
        return nil, 0, {}
    end

    local block_score = tonumber(WAF_CONFIG["behavior_block_score"]) or 0
    -- 挑战关闭且未显式配置直接拦截阈值时，行为检测仅保持惰性，避免 403 误伤
    if not self:isChallengeEnabled() and block_score <= 0 then
        return nil, 0, {}
    end

    local sample = tonumber(WAF_CONFIG["behavior_sample"]) or 10
    local key = "behc:" .. self.ip
    local seen = self.cache:cacheIncr(key, 1, tonumber(WAF_CONFIG["behavior_window"]) or 60) or 1
    if seen <= sample then
        return nil, 0, {}
    end

    local score, reasons = self:behaviorScore()
    local challenge_score = tonumber(WAF_CONFIG["behavior_challenge_score"]) or 6

    if block_score > 0 and score >= block_score then
        return "block", score, reasons
    end
    if score >= challenge_score then
        return "challenge", score, reasons
    end
    return nil, score, reasons
end

-- CC/行为触发后的统一处置：
--   1. 挑战关闭或非导航请求：保持原有 429（不把 HTML 挑战页返回给接口客户端）；
--   2. 导航请求：下发人机挑战；下发失败时回退 429。
-- 同一 IP 的日志与统计按窗口节流，防止持续攻击把磁盘日志与共享计数打爆。
function Waf:shouldLogThrottled(kind)
    local seconds = tonumber(WAF_CONFIG["attack_log_interval"]) or 60
    if seconds <= 0 then
        return true
    end
    local key = "wafthrottle:" .. kind .. ":" .. self.ip
    return self.cache:cacheAdd(key, 1, seconds) == true
end

function Waf:handleCC(reason, detail)
    local issued, created = false, false
    -- 仅对浏览器页面导航下发 HTML 挑战；接口/静态资源继续返回 429，避免客户端解析异常
    if self:isChallengeEnabled() and self:isNavigationRequest() then
        issued, created = challenge.issue(self, {
            reason = reason,
            orig = ngx.var.request_uri,
        })
        if issued then
            self.count:addReqDenyCount()
            if created and self:shouldLogThrottled("cc_challenge") then
                ngx.log(ngx.WARN, "CC challenge issued: ", self.ip,
                    " reason=", tostring(reason), " detail=", tostring(detail))
                self:recordRequest("CC Challenge", "")
                self.count:addAttackCount("cc", self.ip, self.host, ngx.var.request_uri)
            end
            return
        end
    end

    self.count:addReqDenyCount()
    if self:shouldLogThrottled("cc_block") then
        ngx.log(ngx.WARN, "CC Attack: ", self.ip, " (", tostring(detail or reason), ")")
        self:recordRequest("CC Attack", "")
        self.count:addAttackCount("cc", self.ip, self.host, ngx.var.request_uri)
    end
    self:retStatus(429, "CC Attack")
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
    -- 名单热更新：管理员改动 IP 黑白名单 / Host 白名单后，本 worker 下一次请求即生效（无需重载 nginx）
    if ensure_lists_fresh then ensure_lists_fresh() end

    -- 人机验证提交入口：必须在统计/名单/CC 判定之前处理，否则验证请求自身会被计入 CC 计数
    if challenge.is_verify_request(ngx.var.uri) then
        if WAF_CONFIG["mode"] == "protection" then
            challenge.handle_verify(self)
        else
            ngx.exit(ngx.HTTP_NOT_FOUND)
        end
        return
    end

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
    -- 已通过人机挑战的浏览器在有效期内跳过 CC 与行为检测（规则检测仍然生效）
    local passed = self:hasPassedChallenge()

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
    elseif not passed and self:isCCAttack(false) then
        if is_monitor then
            -- 监控模式仅记录，不拦截
            if self:shouldLogThrottled("cc_block") then
                ngx.log(ngx.WARN, "CC Attack (monitor): ", self.ip)
                self:recordRequest("CC Attack", "")
                self.count:addAttackCount("cc", self.ip, self.host, ngx.var.request_uri)
            end
        else
            self:handleCC("cc", "rate-limit")
            return
        end
    elseif passed and self:isCCAttack(true) then
        -- 已通过挑战但仍超出放大后的阈值，说明是持续刷量，直接 429
        if self:shouldLogThrottled("cc_block") then
            ngx.log(ngx.WARN, "CC flood after challenge: ", self.ip)
            self:recordRequest("CC Attack", "")
            self.count:addAttackCount("cc", self.ip, self.host, ngx.var.request_uri)
        end
        if not is_monitor then
            self:retStatus(429, "CC Attack")
            return
        end
    elseif not passed then
        local verdict, score, reasons = self:behaviorVerdict()
        if is_monitor and verdict then
            -- 监控模式仅记录行为判定结果
            if self:shouldLogThrottled("behavior_monitor") then
                ngx.log(ngx.WARN, "Behavior ", verdict, " (monitor): ", self.ip, " score=", score,
                    " reasons=", table.concat(reasons, ","))
                self:recordRequest("Behavior Detection", "")
                self.count:addAttackCount("Behavior Detection", self.ip, self.host, ngx.var.request_uri)
            end
        elseif verdict == "block" then
            self.count:addReqDenyCount()
            if self:shouldLogThrottled("behavior_block") then
                ngx.log(ngx.WARN, "Behavior blocked: ", self.ip, " score=", score,
                    " reasons=", table.concat(reasons, ","))
                self:recordRequest("Behavior Detection", "")
                self.count:addAttackCount("Behavior Detection", self.ip, self.host, ngx.var.request_uri)
            end
            self:ret403("Abnormal access behavior detected")
            return
        elseif verdict == "challenge" then
            local issued, created = challenge.issue(self, { reason = "behavior", orig = ngx.var.request_uri })
            if not issued then
                -- 挑战关闭或下发失败：按可疑行为降级处置，避免放行
                self.count:addReqDenyCount()
                if self:shouldLogThrottled("behavior_block") then
                    ngx.log(ngx.WARN, "Behavior blocked (challenge unavailable): ", self.ip, " score=", score)
                    self:recordRequest("Behavior Detection", "")
                    self.count:addAttackCount("Behavior Detection", self.ip, self.host, ngx.var.request_uri)
                end
                self:ret403("Abnormal access behavior detected")
                return
            end
            self.count:addReqDenyCount()
            if created and self:shouldLogThrottled("behavior_challenge") then
                ngx.log(ngx.WARN, "Behavior challenge: ", self.ip, " score=", score,
                    " reasons=", table.concat(reasons, ","))
                self:recordRequest("Behavior Challenge", "")
                self.count:addAttackCount("Behavior Challenge", self.ip, self.host, ngx.var.request_uri)
            end
            return
        end
    end

    if self:isBigRequest() then
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
