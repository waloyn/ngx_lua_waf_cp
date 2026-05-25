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

-- 递归 HTML 实体解码：支持 &#NNN; / &#xNN; / 常见命名实体
-- @return decoded 或 nil
function _M.html_entity_unescape_recursive(input, max_attempts)
    local cur = input
    local prev = ""
    local attempts = 0
    while cur ~= prev and attempts < max_attempts do
        prev = cur
        local replaced, _, err = ngx.re.gsub(cur, ENTITY_PATTERN, function(m)
            local code
            if m[1] and m[1] ~= "" then
                code = tonumber(m[1], 16)
            elseif m[2] and m[2] ~= "" then
                code = tonumber(m[2])
            elseif m[3] and m[3] ~= "" then
                return NAMED_ENTITIES[m[3]] or m[0]
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
        cur = replaced
        attempts = attempts + 1
    end
    if attempts >= max_attempts then
        return nil
    end
    return cur
end

-- 一次性归一化：先 URL 再 HTML 实体
-- @return 归一化字符串，或 nil（任一阶段超限）
function _M.unescape(input, max_attempts)
    local s = _M.url_unescape_recursive(input, max_attempts)
    if s == nil then return nil end
    return _M.html_entity_unescape_recursive(s, max_attempts)
end

return _M
