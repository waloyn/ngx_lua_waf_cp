-- 请求载荷解码工具：递归 URL 解码 + 递归 HTML 实体解码
-- 设计目标：让规则匹配能穿透多层编码绕过（如 %252e、&#x2e;、&amp;）
-- 调用方：waf.lua attack 阶段对 uri/header/body 做归一化

local _M = {}

-- 常见命名实体（最小集，覆盖攻击 payload 常用）
local NAMED_ENTITIES = {
    lt = '<', gt = '>', amp = '&', quot = '"', apos = "'", nbsp = ' ',
}

-- 码点 -> UTF-8 字节序列
local function codepointToUtf8(code)
    if code < 0x80 then
        return string.char(code)
    elseif code < 0x800 then
        return string.char(0xC0 + math.floor(code / 0x40), 0x80 + (code % 0x40))
    elseif code < 0x10000 then
        return string.char(
            0xE0 + math.floor(code / 0x1000),
            0x80 + math.floor((code % 0x1000) / 0x40),
            0x80 + (code % 0x40))
    else
        return string.char(
            0xF0 + math.floor(code / 0x40000),
            0x80 + math.floor((code % 0x40000) / 0x1000),
            0x80 + math.floor((code % 0x1000) / 0x40),
            0x80 + (code % 0x40))
    end
end

-- 递归 URL 解码：每轮调用 ngx.unescape_uri 直至稳定或达到上限
-- @return decoded 或 nil（达到上限表示嵌套过深，疑似恶意）
function _M.url_unescape_recursive(input, max_attempts)
    local cur = input
    local prev = ""
    local attempts = 0
    while cur ~= prev and attempts < max_attempts do
        prev = cur
        cur = ngx.unescape_uri(cur)
        attempts = attempts + 1
    end
    if attempts >= max_attempts then
        return nil
    end
    return cur
end

local ENTITY_PATTERN = [[&(?:#x([0-9a-fA-F]+)|#(\d+)|([a-zA-Z][a-zA-Z0-9]{1,9}));]]

-- 单轮 HTML 实体解码
local function html_entity_unescape_once(cur)
    local replaced, _, err = ngx.re.gsub(cur, ENTITY_PATTERN, function(m)
        local code
        if m[1] and m[1] ~= "" then
            code = tonumber(m[1], 16)
        elseif m[2] and m[2] ~= "" then
            code = tonumber(m[2])
        elseif m[3] and m[3] ~= "" then
            return NAMED_ENTITIES[m[3]:lower()] or m[0]
        end
        if not code or code < 0 or code > 0x10FFFF then
            return m[0]
        end
        if code <= 255 then
            return string.char(code)
        end
        local ok, ch = pcall(codepointToUtf8, code)
        return ok and ch or m[0]
    end, "jo")
    if not replaced then
        ngx.log(ngx.ERR, "html entity decode error: ", err)
        return nil
    end
    return replaced
end

-- 递归 HTML 实体解码：支持 &#NNN; / &#xNN; / 常见命名实体
-- @return decoded 或 nil
function _M.html_entity_unescape_recursive(input, max_attempts)
    local cur = input
    local prev = ""
    local attempts = 0
    while cur ~= prev and attempts < max_attempts do
        prev = cur
        local replaced = html_entity_unescape_once(cur)
        if not replaced then
            return nil
        end
        cur = replaced
        attempts = attempts + 1
    end
    if attempts >= max_attempts then
        return nil
    end
    return cur
end

-- 不动点交替归一化：在同一循环内交替执行 URL 解码与 HTML 实体解码，防止 &#x25;3c 等混合编码绕过
-- @return 归一化字符串，或 nil（解码轮次达到上限视为恶意嵌套）
function _M.unescape(input, max_attempts)
    if type(input) ~= "string" or input == "" then
        return input or ""
    end
    max_attempts = tonumber(max_attempts) or 10
    local cur = input
    local prev = ""
    local attempts = 0
    while cur ~= prev and attempts < max_attempts do
        prev = cur
        local u = ngx.unescape_uri(cur)
        local h = html_entity_unescape_once(u)
        if not h then
            return nil
        end
        cur = h
        attempts = attempts + 1
    end
    if attempts >= max_attempts then
        return nil
    end
    return cur
end

return _M
