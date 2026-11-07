-- CC 行为特征检测
-- 对导航类请求（浏览器页面访问）做轻量指纹评分，输出风险分与命中原因。
-- 设计原则：
--   1. 只做字符串/表遍历，避免在 access 热路径引入正则编译开销；
--   2. 仅导航请求写入请求间隔状态，防止静态资源/API 把共享字典打满；
--   3. 评分只作为“是否进入挑战”的依据，不直接封禁，降低误伤。
local _M = {}

local DICT_NAME = "nova_waf"
local STATE_PREFIX = "beh:"
local STATE_TTL = 180          -- 请求间隔状态保留时长（秒）
local MAX_SCORE = 20

-- 常见自动化客户端 UA 特征（全部使用 plain find，大小写不敏感）
local TOOL_UA_TOKENS = {
    "curl/", "wget/", "python-requests", "python-urllib", "python-httpx",
    "go-http-client", "java/", "okhttp", "libwww-perl", "httpclient",
    "apache-httpclient", "scrapy", "axios/", "node-fetch", "undici",
    "guzzlehttp", "lua-resty-http", "powershell", "winhttp",
    "postmanruntime", "insomnia", "httpie/", "aiohttp/", "requests/",
}

local CANONICAL_HEADERS = {
    ["user-agent"] = "User-Agent",
    ["accept"] = "Accept",
    ["accept-language"] = "Accept-Language",
    ["accept-encoding"] = "Accept-Encoding",
    ["cookie"] = "Cookie",
    ["referer"] = "Referer",
    ["sec-fetch-mode"] = "Sec-Fetch-Mode",
    ["sec-fetch-dest"] = "Sec-Fetch-Dest",
    ["sec-ch-ua"] = "Sec-Ch-Ua",
    ["x-requested-with"] = "X-Requested-With",
}

-- 读取请求头（兼容 header 名大小写差异与多值 header）
local function header(ctx, name)
    local h = ctx and ctx.headers
    if type(h) ~= "table" then
        return nil
    end
    local v = h[name]
    if v == nil then
        local canon = CANONICAL_HEADERS[name]
        if canon then
            v = h[canon]
        end
    end
    if type(v) == "table" then
        return v[1]
    end
    return v
end

_M.header = header

-- 浏览器 UA 判定（仅用于头部完整性交叉验证，不作为放行依据）
local function is_mozilla_ua(lower_ua)
    return string.find(lower_ua, "mozilla/", 1, true) ~= nil
end

local function is_chromium_ua(lower_ua)
    return string.find(lower_ua, "chrome/", 1, true) ~= nil
        or string.find(lower_ua, "chromium/", 1, true) ~= nil
        or string.find(lower_ua, "edg/", 1, true) ~= nil
end

-- 解析并更新请求间隔状态，返回评分增量与原因
local function evaluate_timing(ctx, score, reasons)
    local shared = ngx and ngx.shared and ngx.shared[DICT_NAME]
    if not shared then
        return score
    end

    local now = ngx.now()
    local key = STATE_PREFIX .. tostring(ctx.ip or "unknown")
    local last_ts, last_gap, reg = 0, -1, 0

    local raw = shared:get(key)
    if type(raw) == "string" then
        local a, b, c = string.match(raw, "^([%d%.]+)|([%-%d%.]+)|(%d+)$")
        if a then
            last_ts = tonumber(a) or 0
            last_gap = tonumber(b) or -1
            reg = tonumber(c) or 0
        end
    end

    local gap = -1
    if last_ts > 0 then
        gap = (now - last_ts) * 1000
        if gap >= 0 and gap <= 10000 and last_gap >= 0
            and math.abs(gap - last_gap) <= 8 then
            reg = reg + 1
        else
            reg = 0
        end

        -- 连续 5 次以上间隔几乎一致（±8ms），典型脚本定时器特征
        if reg >= 6 then
            score = score + 5
            reasons[#reasons + 1] = "regular-timing"
        elseif reg >= 3 then
            score = score + 3
            reasons[#reasons + 1] = "regular-timing"
        elseif reg >= 1 then
            score = score + 1
            reasons[#reasons + 1] = "regular-timing"
        end

        -- 高频连发（导航请求间隔 < 60ms，人为点击几乎不可能）
        if gap >= 0 and gap < 60 then
            score = score + 1
            reasons[#reasons + 1] = "rapid-repeat"
        end
    end

    -- 写回状态（失败不影响主流程）
    shared:set(key, string.format("%.3f|%.1f|%d", now, gap, reg), STATE_TTL)
    return score
end

-- 计算请求风险分
-- @param ctx Waf 实例（需包含 ip / headers）
-- @param is_navigation 是否为浏览器页面导航请求
-- @return score, reasons
function _M.evaluate(ctx, is_navigation)
    local score = 0
    local reasons = {}

    local ua = header(ctx, "user-agent") or ""
    local lower_ua = string.lower(ua)

    -- 1. UA 特征
    if ua == "" then
        score = score + 4
        reasons[#reasons + 1] = "missing-ua"
    elseif #ua < 20 then
        score = score + 2
        reasons[#reasons + 1] = "short-ua"
    end

    for i = 1, #TOOL_UA_TOKENS do
        if string.find(lower_ua, TOOL_UA_TOKENS[i], 1, true) then
            score = score + 4
            reasons[#reasons + 1] = "tool-ua"
            break
        end
    end

    -- 2. 协议与请求头完整性（真实浏览器会携带一整套协商头）
    local protocol = ngx and ngx.var and ngx.var.server_protocol
    if protocol == "HTTP/1.0" then
        score = score + 3
        reasons[#reasons + 1] = "http10"
    end

    local accept = header(ctx, "accept")
    if not accept or accept == "" then
        score = score + 2
        reasons[#reasons + 1] = "no-accept"
    elseif is_navigation then
        local lower_accept = string.lower(accept)
        if not string.find(lower_accept, "text/html", 1, true)
            and not string.find(lower_accept, "*/*", 1, true) then
            score = score + 1
            reasons[#reasons + 1] = "odd-accept"
        end
    end

    if not header(ctx, "accept-language") then
        score = score + 2
        reasons[#reasons + 1] = "no-accept-language"
    end

    if not header(ctx, "accept-encoding") then
        score = score + 1
        reasons[#reasons + 1] = "no-accept-encoding"
    end

    local sec_fetch = header(ctx, "sec-fetch-mode")
    if is_mozilla_ua(lower_ua) and not sec_fetch then
        score = score + 3
        reasons[#reasons + 1] = "no-sec-fetch"
    end

    if is_chromium_ua(lower_ua) and not header(ctx, "sec-ch-ua") then
        score = score + 1
        reasons[#reasons + 1] = "no-client-hints"
    end

    local header_count = 0
    if type(ctx.headers) == "table" then
        for _ in pairs(ctx.headers) do
            header_count = header_count + 1
        end
    end
    if header_count < 4 then
        score = score + 2
        reasons[#reasons + 1] = "few-headers"
    end

    -- 3. 首次导航无来源、无 Cookie（爬虫冷启动特征，权重较低）
    if is_navigation and not header(ctx, "referer") and not header(ctx, "cookie") then
        score = score + 1
        reasons[#reasons + 1] = "cold-navigation"
    end

    -- 4. 请求间隔规律性（仅导航请求维护状态，控制共享内存占用）
    if is_navigation and ngx and ngx.shared and ngx.shared[DICT_NAME] then
        score = evaluate_timing(ctx, score, reasons)
    end

    if score > MAX_SCORE then
        score = MAX_SCORE
    end

    return score, reasons
end

return _M
