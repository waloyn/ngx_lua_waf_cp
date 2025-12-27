---@diagnostic disable: need-check-nil
local localCache = require "cache"
local localCount = require "count"

-- 缓存 403 页面内容（模块级缓存，只读取一次）
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

-- 将列表转换为 hash table 以提高查找效率
local function listToSet(list)
    local set = {}
    if list then
        for _, v in ipairs(list) do
            set[v] = true
        end
    end
    return set
end

local Waf = {}
Waf.__index = Waf

-- Constructor
function Waf:new()
    local ip = require "ip"
    local ipAddr = ip.getClientIP()
    local host = ngx.req.get_headers()["Host"]
    local instance = {
        ip = ipAddr,
        host = host,
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
        -- 预转换为 hash table 提高查找效率
        whiteIpSet = listToSet(WHITE_IPS),
        whiteHostSet = listToSet(WHITE_HOST),
        blackIpSet = listToSet(BLACK_IPS)
    }
    setmetatable(instance, self)
    return instance
end

function Waf:isWhiteIp()
    return self.whiteIpSet[self.ip] == true
end

function Waf:isWhiteHost()
    return self.whiteHostSet[self.host] == true
end

function Waf:isBlackIp()
    return self.blackIpSet[self.ip] == true
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
    content = string.gsub(content, "{BLOCK_REASON}", msg)
    content = string.gsub(content, "{REQUEST_ID}", self.request_id)
    content = string.gsub(content, "{REQUEST_TIME}", ngx.localtime())
    content = string.gsub(content, "{IP}", self.ip)
    if WAF_CONFIG["debug"] == "on" then
        ngx.say(msg)
    else
        ngx.say(content)
    end
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

function Waf:recordRequest(rule, body)
    local logger = require "logger"
    local cjson = require "cjson"
    local hostLogger = logger:new(self.host)
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
        headers = ngx.req.get_headers()
    }
    local logStr, err = cjson.encode(logTable)
    if logStr then
        hostLogger:log(logStr .. '\n')
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

    -- 监控模式下不拦截请求
    if WAF_CONFIG["mode"] == "monitor" then
        return false
    end

    -- 连续攻击封禁IP
    local attackCount = tonumber(self.cache:cacheGet(self.key_attack_count) or 0)
    ngx.log(ngx.INFO, self.ip, " attackCount: ", attackCount)
    if attackCount > 0 then
        -- 只要之前有一次攻击，并且被检测到存在攻击行为，就会封禁IP
        self:blockIp(attackCount + 1)
        return true
    end

    -- 置信度高的攻击直接封禁IP
    local prevPossibly = tonumber(self.cache:cacheGet(self.key_possibly) or 0)
    local total = possibly + prevPossibly

    ngx.log(ngx.INFO, self.ip, " possibly: ", total)

    self.cache:cacheSet(self.key_possibly, total, self.possibly_timeout)
    if total < tonumber(self.possibly_count) then
        return false
    end

    -- 攻击次数超过阈值，封禁IP
    local attackValue = tonumber(self.cache:cacheGet(self.key_attack) or 1)
    self.cache:cacheSet(self.key_attack, attackValue + 1, self.block_time)
    ngx.log(ngx.INFO, self.ip, " attack: ", attackValue)

    if attackValue > self.block_count then
        self:blockIp(1)
        return true
    end
    return false
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

    local key = self.key_cc
    local value = tonumber(self.cache:cacheGet(key) or 0)
    local count = value + 1
    if count > limit then
        return true
    end
    self.cache:cacheSet(key, count, seconds)
    return false
end

function Waf:UnEscapeUri(uri, max_attempts)
    local decoded_uri = uri
    local prev_decoded_uri = ""
    local attempts = 0
    while decoded_uri ~= prev_decoded_uri and attempts < max_attempts do
        prev_decoded_uri = decoded_uri
        decoded_uri = ngx.unescape_uri(decoded_uri)
        attempts = attempts + 1
    end

    if attempts >= max_attempts then
        return nil
    end

    local decoded_uri_2 = decoded_uri
    prev_decoded_uri = ""
    attempts = 0
    -- 解码字符实体的函数
    while decoded_uri_2 ~= prev_decoded_uri and attempts < max_attempts do
        prev_decoded_uri = decoded_uri_2
        local new_decoded_uri, _, err = ngx.re.gsub(decoded_uri_2, "&#(\\d+);", function(m)
            return string.char(tonumber(m[1]))
        end, "jo")

        if not new_decoded_uri then
            ngx.log(ngx.ERR, "Error during regex substitution: ", err)
            return nil
        end

        decoded_uri_2 = new_decoded_uri
        attempts = attempts + 1
    end

    if attempts >= max_attempts then
        return nil
    end

    return string.lower(decoded_uri_2)
end

function Waf:trim(s)
    return s:match("^%s*(.-)%s*$")
end

function Waf:attack()
    local max_decode_count = tonumber(WAF_CONFIG["decode_max_count"] or 10)
    local uri = ngx.var.request_uri
    local checkData = {}

    uri = self:UnEscapeUri(uri, max_decode_count)
    table.insert(checkData, "uri: " .. uri)
    local headers = ngx.req.get_headers()

    for k, v in pairs(headers) do
        local header
        -- 判断 v 是否是表类型,处理相同名称多值情况
        if type(v) == "table" then
            header = k .. ": " .. table.concat(v, ",")
        else
            header = k .. ": " .. v
        end
        header = self:UnEscapeUri(header, max_decode_count)
        table.insert(checkData, header)
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data() or ""
    body = self:UnEscapeUri(body, max_decode_count) or ""
    table.insert(checkData, "body: " .. body)
    for _, data in ipairs(checkData) do
        if data == nil then
            ngx.log(ngx.INFO, "Attack detected: ", "Malicious encoding")
            self:inAttack("Malicious encoding", "Malicious encoding", "low", "Malicious encoding", self.possibly_count)
            self:ret403("Malicious encoding")
            return
        else
            for _, rule in pairs(RULE_FILES) do
                for _, patternItem in pairs(rule.rules) do
                    local positions = {}

                    -- 使用 string.gmatch 分割字符串
                    for part in string.gmatch(rule.position, '([^,]+)') do
                        table.insert(positions, part)
                    end

                    -- 现在 positions 是一个包含各部分的表
                    -- 例如: positions = {"uri", "body", "cookie"}
                    -- 在你的逻辑中使用分割后的部分
                    for _, p in ipairs(positions) do
                        if data:sub(1, #p) == p then
                            local regex = string.lower(patternItem.pattern):match("^%s*(.-)%s*$")
                            if ngx.re.match(data, regex, "isjo") then
                                -- 记录攻击并判断是否需要封禁
                                self:inAttack(rule.name .. " - " .. p .. " - " .. patternItem.name, body, rule.level, rule.desc, patternItem.confidence)
                                -- 无论是否封禁，检测到攻击都返回 403
                                if WAF_CONFIG["debug"] == "on" then
                                    self:ret403("Attack detected,Debug msg: " ..
                                        rule.name ..
                                        " - " .. patternItem.name .. " => " .. regex .. " [TEXT] => " .. data)
                                else
                                    self:ret403("Attack detected.")
                                end
                                return
                            end
                        end
                    end
                end
            end
        end
    end
end

function Waf:calculateRequestSize()
    local headers_size = 0
    local headers = ngx.req.get_headers()
    for k, v in pairs(headers) do
        headers_size = headers_size + #k
        if type(v) == "table" then
            for _, vv in ipairs(v) do
                headers_size = headers_size + #vv
            end
        else
            headers_size = headers_size + #v
        end
    end

    local body_length = tonumber(ngx.var.content_length) or 0
    local method_size = #ngx.req.get_method()
    local uri_size = #ngx.var.request_uri

    local total_size = headers_size + body_length + method_size + uri_size
    return total_size
end

function Waf:process()
    self.count:addReqCount(self.ip)
    if WAF_CONFIG["mode"] == "off" then
        ngx.log(ngx.INFO, "WAF is off")
        return
    elseif self:isWhiteIp() then
        ngx.log(ngx.WARN, "White IP")
        return
    elseif self:isWhiteHost() then
        ngx.log(ngx.WARN, "White HOST")
        return
    elseif self:isBlackIp() then
        ngx.log(ngx.WARN, "Black IP")
        self:ret403("Your IP has been blacklisted")
        return
    elseif self:isBlockedIp() then
        ngx.log(ngx.WARN, "Blocked IP")
        self:ret403("Your IP has been blocked")
        return
    elseif self:isCCAttack() then
        ngx.log(ngx.WARN, "CC Attack")
        self:ret403("CC Attack")
        return
    elseif self:isBigRequest() then
        ngx.log(ngx.WARN, "Big request")
        self:ret403("Request body is too large")
        return
    else
        self:attack()
    end
end

local myWaf = Waf:new()
myWaf:process()
