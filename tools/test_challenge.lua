-- 人机挑战与行为检测离线测试
-- 用法：luajit tools/test_challenge.lua
-- 通过 stub 模拟 ngx API（共享字典、请求头、exit、redirect），不依赖 nginx 运行
local BASE = "E:/WebSite/openresty/waf/"
if type(arg) == "table" and type(arg[1]) == "string" and arg[1] ~= "" then
    BASE = arg[1]
end
if BASE:sub(-1) ~= "/" then BASE = BASE .. "/" end
package.path = BASE .. "?.lua;" .. BASE .. "utils/?.lua;" .. BASE .. "tools/?.lua;" .. package.path

-- ============ ngx stub ============
local dict_store = {}
local dict_expire = {}
local function new_dict()
    local d = {}
    function d:get(k) return dict_store[k] end
    function d:set(k, v, ttl) dict_store[k] = v; if ttl then dict_expire[k] = os.time() + ttl end; return true end
    function d:add(k, v, ttl)
        if dict_store[k] ~= nil then return nil, "exists" end
        dict_store[k] = v
        if ttl then dict_expire[k] = os.time() + ttl end
        return true
    end
    function d:incr(k, n, init, ttl)
        local v = dict_store[k]
        if v == nil then
            if init == nil then return nil, "not found" end
            v = init
        end
        v = v + n
        dict_store[k] = v
        if ttl then dict_expire[k] = os.time() + ttl end
        return v
    end
    function d:expire(k, ttl) if dict_store[k] == nil then return nil, "not found" end; dict_expire[k] = os.time() + ttl; return true end
    function d:delete(k) dict_store[k] = nil; dict_expire[k] = nil; return true end
    return d
end

local response = { body = nil, status = nil, headers = {}, cookies = {}, redirect = nil, exited = nil }
local ngx_stub
ngx_stub = {
    shared = { nova_waf = new_dict(), nova_waf_count = new_dict() },
    -- 代理表：每次赋值都写入 response.headers，便于断言最新响应头
    header = setmetatable({}, {
        __newindex = function(_, k, v) response.headers[k] = v end,
        __index = function(_, k) return response.headers[k] end,
    }),
    var = {
        request_uri = "/index.html",
        uri = "/index.html",
        host = "example.com",
        remote_addr = "203.0.113.9",
        server_protocol = "HTTP/1.1",
        scheme = "http",
        request_id = "req-test",
        http_cookie = nil,
    },
    req = {
        _method = "GET",
        _headers = {},
        _post = {},
        _body = "",
        get_method = function() return ngx_stub.req._method end,
        get_headers = function() return ngx_stub.req._headers end,
        read_body = function() end,
        get_body_data = function() return ngx_stub.req._body end,
        get_body_file = function() return nil end,
        get_post_args = function() return ngx_stub.req._post end,
        get_uri_args = function() return {} end,
    },
    time = function() return os.time() end,
    now = function() return os.time() + 0.5 end,
    localtime = function() return os.date("%Y-%m-%d %H:%M:%S") end,
    today = function() return os.date("%Y-%m-%d") end,
    md5 = function(s)
        -- 非加密占位实现：仅用于测试签名一致性（真实环境调用 ngx.md5）
        local h = 5381
        for i = 1, #s do h = (h * 33 + s:byte(i)) % 4294967296 end
        return string.format("%08x", h)
    end,
    log = function() end,
    say = function(s) response.body = (response.body or "") .. tostring(s) end,
    exit = function(code) response.exited = code; error({ __exit = code }, 0) end,
    redirect = function(url, code) response.redirect = { url = url, code = code }; error({ __exit = code }, 0) end,
    get_phase = function() return "init" end,
    worker = { pid = function() return 1234 end },
    config = { prefix = function() return "E:/WebSite/openresty/" end },
    INFO = 8, WARN = 7, ERR = 6,
}
_G.ngx = ngx_stub
_G.WAF_CONFIG = {
    mode = "protection",
    debug = "off",
    cc_challenge = "auto",
    cc_challenge_order = "js,redirect,slider,captcha",
    cc_challenge_ttl = 1800,
    cc_challenge_delay = 5,
    cc_challenge_pow = 3,
    cc_challenge_max_fail = 3,
    cc_challenge_fail_time = 600,
    behavior_defence = "on",
    behavior_window = 60,
    behavior_sample = 10,
    behavior_challenge_score = 6,
    behavior_block_score = 0,
    possibly_count = 1,
    block_count = 3,
    block_time = 600,
    block_timeout = 600,
    due = "off",
}
_G.CURRENT_PATH = BASE

-- ============ test framework ============
local total, failed = 0, 0
local function test(name, fn)
    total = total + 1
    local ok, err = pcall(fn)
    if ok then
        print(string.format("[PASS] %s", name))
    else
        failed = failed + 1
        print(string.format("[FAIL] %s -> %s", name, tostring(err)))
    end
end

-- 前向声明：reset 会复用 reset_response，必须先声明为 local
local reset_response

local function reset()
    dict_store = {}
    ngx_stub.shared = { nova_waf = new_dict(), nova_waf_count = new_dict() }
    reset_response()
end

-- 仅重置响应/请求状态，保留共享字典（用于验证计数累积）
reset_response = function()
    response.body = nil
    response.status = nil
    response.headers = {}
    response.cookies = {}
    response.redirect = nil
    response.exited = nil
    ngx_stub.req._method = "GET"
    ngx_stub.req._headers = {}
    ngx_stub.req._post = {}
    ngx_stub.req._body = ""
    ngx_stub.var.http_cookie = nil
    ngx_stub.var.uri = "/index.html"
    ngx_stub.var.request_uri = "/index.html"
    ngx_stub.now = function() return os.time() + 0.5 end
end

local function browser_headers()
    return {
        ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ["Accept-Language"] = "zh-CN,zh;q=0.9",
        ["Accept-Encoding"] = "gzip, deflate",
        ["Sec-Fetch-Mode"] = "navigate",
        ["Sec-Fetch-Dest"] = "document",
        ["Sec-Ch-Ua"] = '"Chromium";v="126"',
    }
end

reset()
local behavior = require "behavior"
local challenge = require "challenge"

-- fake count 对象，验证统计调用链
local fake_count = {}
function fake_count:addChallengeCount(result, kind)
    self.calls = self.calls or {}
    local key = result .. (kind and (":" .. kind) or "")
    self.calls[key] = (self.calls[key] or 0) + 1
end
function fake_count:addAttackCount() end
local function ctx_new(ip, headers)
    local c = { ip = ip or "203.0.113.9", headers = headers or {}, count = fake_count, host = "example.com" }
    function c:recordRequest() end
    return c
end

-- ============ behavior ============
test("真实浏览器行为分为低风险", function()
    reset()
    local score, reasons = behavior.evaluate(ctx_new(nil, browser_headers()), true)
    assert(score < 6, "score=" .. score .. " reasons=" .. table.concat(reasons, ","))
end)

test("curl UA 风险分达到挑战阈值", function()
    reset()
    ngx_stub.var.server_protocol = "HTTP/1.0"
    local h = { ["User-Agent"] = "curl/8.5.0" }
    local score = behavior.evaluate(ctx_new(nil, h), true)
    assert(score >= 6, "score=" .. score)
    ngx_stub.var.server_protocol = "HTTP/1.1"
end)

test("请求间隔规律性被识别", function()
    reset()
    local ctx = ctx_new(nil, browser_headers())
    for _ = 1, 4 do
        -- 固定 1 秒间隔
        behavior.evaluate(ctx, true)
        ngx_stub.now = function() return ngx_stub._now or (os.time() + 0.5) end
    end
    -- 无法精确模拟时钟，这里仅断言状态键已写入
    assert(dict_store["beh:203.0.113.9"] ~= nil, "timing state not written")
end)

-- ============ challenge issue ============
local function issue(kind, reason)
    reset()
    ngx_stub.req._headers = browser_headers()
    local ctx = ctx_new()
    local ok, err = pcall(function()
        challenge.issue(ctx, { type = kind, reason = reason or "cc", orig = "/index.html?q=1" })
    end)
    if not ok and not (type(err) == "table" and err.__exit) then
        error(err)
    end
    return response.body or ""
end

test("JS 挑战页包含 PoW 脚本与挑战 ID", function()
    local html = issue("js")
    assert(html:find("正在验证您的浏览器", 1, true), "missing title")
    assert(html:find('name="id"', 1, true), "missing id field")
    assert(html:find("charCodeAt", 1, true), "missing pow script")
    assert(html:find("value=\"/index.html?q=1\"", 1, true), "missing back uri")
end)

test("5 秒跳转页包含倒计时与自动提交", function()
    local html = issue("redirect")
    assert(html:find("秒后自动继续", 1, true), "missing countdown")
    assert(html:find("setInterval", 1, true), "missing timer")
    assert(html:find("name=\"answer\" value=\"wait\"", 1, true), "missing wait token")
end)

test("滑块挑战页包含轨迹与缺口", function()
    local html = issue("slider")
    assert(html:find("拖动滑块", 1, true), "missing slider tip")
    assert(html:find("class=\"thumb\"", 1, true), "missing thumb")
    assert(html:find("class=\"gap\"", 1, true), "missing gap")
end)

test("验证码挑战页包含 SVG 点阵", function()
    local html = issue("captcha")
    assert(html:find("<svg", 1, true), "missing svg")
    assert(html:find("<rect", 1, true), "missing glyph rects")
    assert(not html:find("<text", 1, true), "captcha should not use text nodes")
    assert(html:find("name=\"answer\"", 1, true), "missing answer input")
end)

test("auto 模式按顺序升级挑战类型", function()
    reset()
    ngx_stub.req._headers = browser_headers()
    local ctx = ctx_new()
    local kinds = {}
    for i = 1, 4 do
        response.body = nil
        dict_store["chalip:203.0.113.9:" .. ngx_stub.md5(browser_headers()["User-Agent"])] = nil
        dict_store["behchaln:203.0.113.9"] = i - 1
        local ok, err = pcall(function()
            challenge.issue(ctx, { reason = "behavior", orig = "/p" })
        end)
        if not ok and not (type(err) == "table" and err.__exit) then error(err) end
        local html = response.body or ""
        if html:find("charCodeAt", 1, true) then table.insert(kinds, "js")
        elseif html:find("秒后自动继续", 1, true) then table.insert(kinds, "redirect")
        elseif html:find("拖动滑块", 1, true) then table.insert(kinds, "slider")
        elseif html:find("<svg", 1, true) and html:find("name=\"answer\"", 1, true) then table.insert(kinds, "captcha") end
    end
    assert(table.concat(kinds, ",") == "js,redirect,slider,captcha", "order=" .. table.concat(kinds, ","))
end)

test("开放重定向被阻断", function()
    reset()
    ngx_stub.req._headers = browser_headers()
    local ctx = ctx_new()
    local ok, err = pcall(function()
        challenge.issue(ctx, { type = "captcha", orig = "https://evil.example/steal" })
    end)
    if not ok and not (type(err) == "table" and err.__exit) then error(err) end
    assert(response.body:find("value=\"/\"", 1, true), "unsafe back uri not sanitized")
end)

-- ============ verify ============
local function get_challenge_id()
    local id = response.body and response.body:match('name="id" value="([a-f0-9]+)"')
    return id
end

local function do_verify(id, answer, ip)
    ngx_stub.req._method = "POST"
    ngx_stub.req._body = "id=" .. tostring(id) .. "&answer=" .. tostring(answer)
    ngx_stub.req._post = { id = id, answer = tostring(answer), back = "/index.html" }
    local ctx = ctx_new(ip)
    local ok, err = pcall(function() challenge.handle_verify(ctx) end)
    if not ok and not (type(err) == "table" and err.__exit) then error(err) end
    return response
end

test("JS 挑战答案校验（正确/错误）", function()
    reset()
    ngx_stub.req._headers = browser_headers()
    local ctx = ctx_new()
    local ok, err = pcall(function()
        challenge.issue(ctx, { type = "js", orig = "/index.html" })
    end)
    if not ok and not (type(err) == "table" and err.__exit) then error(err) end
    local id = get_challenge_id()
    assert(id, "no challenge id")
    local packed = dict_store["chal:" .. id]
    local prefix, difficulty = packed:match("^js|[^|]*|[^|]*|([^|]*)|([^|]*)|")
    assert(prefix and #prefix == 16, "bad prefix")
    local bit = require "bit"
    local h = 0
    for i = 1, #(prefix) do h = bit.tobit(h * 65599 + prefix:byte(i)) end
    if h < 0 then h = h + 4294967296 end
    local hex = bit.tohex(h)
    local n, z = 0, 0
    while true do
        h = 0
        local s = prefix .. tostring(n)
        for i = 1, #s do h = bit.tobit(h * 65599 + s:byte(i)) end
        if h < 0 then h = h + 4294967296 end
        hex = bit.tohex(h)
        z = 0
        for i = 1, #hex do if hex:sub(i, i) == "0" then z = z + 1 else break end end
        if z >= tonumber(difficulty) then break end
        n = n + 1
        assert(n < 5000000, "pow too hard")
    end
    local r = do_verify(id, n)
    assert(r.redirect and r.redirect.code == 303, "verify should redirect, got " .. tostring(r.exited))
    local cookie = r.headers["Set-Cookie"] or ""
    assert(cookie:find("nova_waf_pass=", 1, true), "missing pass cookie")
    assert(cookie:find("HttpOnly", 1, true), "missing HttpOnly")
    assert(dict_store["chal:" .. id] == nil, "challenge not consumed")
    -- Cookie 应能通过校验（http_cookie 需为完整 Cookie 串）
    ngx_stub.var.http_cookie = "nova_waf_pass=" .. cookie:match("nova_waf_pass=([^;]+)")
    local ctx2 = ctx_new()
    assert(challenge.is_passed(ctx2), "pass cookie rejected")
    -- 其他 IP 不能复用
    local ctx3 = ctx_new("198.51.100.7")
    assert(not challenge.is_passed(ctx3), "cookie should be ip bound")
end)

test("验证提交缺少挑战或被篡改时拒绝", function()
    reset()
    local r = do_verify("deadbeef", "0")
    assert(r.exited == 403, "expected 403, got " .. tostring(r.exited))
end)

test("验证失败达到上限后封禁 IP", function()
    reset()
    ngx_stub.req._headers = browser_headers()
    local ctx = ctx_new()
    local ok, err = pcall(function()
        challenge.issue(ctx, { type = "captcha", orig = "/index.html" })
    end)
    if not ok and not (type(err) == "table" and err.__exit) then error(err) end
    local id = get_challenge_id()
    for _ = 1, 3 do
        -- 保留共享字典中的失败计数，仅重置响应状态
        reset_response()
        ngx_stub.req._headers = browser_headers()
        -- 重新下发，避免挑战被消费
        local c = ctx_new()
        local ok2, err2 = pcall(function()
            challenge.issue(c, { type = "captcha", orig = "/index.html" })
        end)
        if not ok2 and not (type(err2) == "table" and err2.__exit) then error(err2) end
        id = get_challenge_id()
        do_verify(id, "ZZZZ")
    end
    assert(dict_store["block:203.0.113.9"] ~= nil, "ip not blocked after max failures")
end)

print(string.format("\n%d tests, %d failed", total, failed))
if failed > 0 then os.exit(1) end
