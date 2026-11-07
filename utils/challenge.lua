-- CC 人机挑战模块
-- 提供四类挑战：JS 工作量证明、5 秒等待跳转、滑块、SVG 字符验证码。
-- 通过后签发绑定客户端 IP 的签名 Cookie，在有效期内跳过 CC/行为检测（规则检测仍然生效）。
--
-- 端点（由 waf.lua 的 access 阶段直接处理，无需修改 nginx 配置）：
--   POST /_waf_challenge/verify  提交挑战答案
--
-- 安全约定：
--   1. 挑战答案只保存在共享字典中，页面仅下发随机挑战 ID，防止直接读取答案；
--   2. Cookie 由服务端签名，绑定 IP 与过期时间，客户端无法伪造；
--   3. 跳转目标必须是本站相对路径，阻断开放重定向；
--   4. 挑战页禁用缓存与外部资源，CSP 仅允许内联脚本/样式。
local _M = {}

local bit = require "bit"

local DICT_NAME = "nova_waf"
local VERIFY_URI = "/_waf_challenge/verify"
local COOKIE_NAME = "nova_waf_pass"

local CHAL_PREFIX = "chal:"
local CHAL_IP_PREFIX = "chalip:"     -- 同 IP+UA 复用挑战，避免刷新页面无限创建
local CHAL_ISSUE_PREFIX = "chalissue:" -- 单 IP 下发频率限制
local CHAL_TTL = 300              -- 挑战 ID 有效期（秒）
local FAIL_PREFIX = "chalfail:"   -- 挑战失败计数
local CC_COUNTER_PREFIX = "chaln:"      -- CC 触发后的挑战升级计数
local BEH_COUNTER_PREFIX = "behchaln:"  -- 行为触发后的挑战升级计数
local SECRET_KEY = "__waf_challenge_secret"

local function cfg(name, default)
    local v = WAF_CONFIG and WAF_CONFIG[name]
    if v == nil or v == "" then
        return default
    end
    return v
end

local function cfg_num(name, default)
    return tonumber(cfg(name, default)) or default
end

local function behavior_header(ctx, name)
    local ok, mod = pcall(require, "behavior")
    if ok and mod and mod.header then
        return mod.header(ctx, name)
    end
    local h = ctx and ctx.headers
    if type(h) == "table" then
        local v = h[name]
        if type(v) == "table" then return v[1] end
        return v
    end
    return nil
end

local function trim(s)
    if type(s) ~= "string" then return "" end
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local function shared()
    return ngx and ngx.shared and ngx.shared[DICT_NAME] or nil
end

-- 挑战签名密钥：优先使用配置，其次由首个 Worker 写入共享字典，保证多 Worker 一致
local SECRET_CACHE = nil
local function secret()
    if SECRET_CACHE then
        return SECRET_CACHE
    end
    local s = cfg("challenge_secret", "")
    if s ~= "" then
        SECRET_CACHE = s
        return s
    end
    local dict = shared()
    if not dict then
        return "nova-waf-challenge-fallback"
    end
    local cached = dict:get(SECRET_KEY)
    if cached then
        SECRET_CACHE = cached
        return cached
    end
    local generated = ngx.md5(
        tostring(ngx.now()) .. tostring(ngx.worker.pid()) ..
        tostring(math.random(1, 2147483646)) .. tostring(ngx.var and ngx.var.request_id or "")
    )
    dict:add(SECRET_KEY, generated, 0)
    -- 并发下 add 可能失败，以字典中的值为准
    local final = dict:get(SECRET_KEY) or generated
    SECRET_CACHE = final
    return final
end

local function random_hex(bytes)
    local t = {}
    for i = 1, bytes do
        t[i] = string.format("%02x", math.random(0, 255))
    end
    return table.concat(t)
end

local function new_challenge_id()
    local seed = tostring(ngx.now()) .. random_hex(16) ..
        tostring(ngx.var and ngx.var.request_id or "") .. tostring(ngx.worker.pid())
    return ngx.md5(seed)
end

-- HTML 转义，防止把请求数据反射进页面造成 XSS
local HTML_ESCAPE_MAP = { ['&'] = '&amp;', ['<'] = '&lt;', ['>'] = '&gt;', ['"'] = '&quot;', ["'"] = '&#39;' }
local function html_escape(s)
    if s == nil then return "" end
    return (string.gsub(tostring(s), "[&<>\"']", HTML_ESCAPE_MAP))
end

-- 仅接受本站相对路径，拒绝协议、协议相对 URL、反斜杠、CRLF 与控制字符
local function safe_back_uri(uri)
    if type(uri) ~= "string" or #uri == 0 or #uri > 2048 then
        return "/"
    end
    if uri:sub(1, 1) ~= "/" or uri:sub(1, 2) == "//" then
        return "/"
    end
    -- 逐字节检查：拒绝反斜杠、控制字符与 DEL（Lua 模式不直接支持 \r/\n/\0 转义）
    for i = 1, #uri do
        local b = uri:byte(i)
        if b == 92 or b < 32 or b == 127 then
            return "/"
        end
    end
    return uri
end

-- ============ 通行 Cookie ============

-- 双层哈希构造 MAC：外层以 secret 前缀覆盖整体，内层绑定 IP/过期时间，
-- 避免单层 md5(secret..msg) 受到长度扩展攻击。
local function signature(ip, exp, rand)
    local inner = ngx.md5(secret() .. "|" .. tostring(ip or "") .. "|" .. tostring(exp))
    return ngx.md5(secret() .. "|" .. tostring(rand) .. "|" .. inner)
end

local function read_cookie()
    local v = ngx.var and ngx.var["cookie_" .. COOKIE_NAME]
    if v and v ~= "" then
        return v
    end
    local raw = ngx.var and ngx.var.http_cookie
    if type(raw) == "string" then
        local found = raw:match("^%s*" .. COOKIE_NAME .. "=([^;]+)")
        if not found then
            found = raw:match(";%s*" .. COOKIE_NAME .. "=([^;]+)")
        end
        if found then
            return found
        end
    end
    return nil
end

-- 校验通行 Cookie 是否有效（签名 + IP 绑定 + 过期时间）
function _M.is_passed(ctx)
    local value = read_cookie()
    if not value then
        return false
    end
    local exp, rand, sig = value:match("^(%d+)%.([a-f0-9]+)%.([a-f0-9]+)$")
    if not exp then
        return false
    end
    exp = tonumber(exp)
    local now = ngx.time()
    if not exp or exp < now or exp > now + 86400 * 7 then
        return false
    end
    local expect = signature(ctx.ip, exp, rand)
    return expect == sig
end

-- 通过挑战后签发 Cookie
local function pass_cookie(ctx)
    local ttl = math.max(60, cfg_num("cc_challenge_ttl", 1800))
    local exp = ngx.time() + ttl
    local rand = random_hex(8)
    local value = tostring(exp) .. "." .. rand .. "." .. signature(ctx.ip, exp, rand)
    local cookie = COOKIE_NAME .. "=" .. value .. "; Path=/; Max-Age=" .. ttl .. "; HttpOnly; SameSite=Lax"
    if ngx.var and ngx.var.scheme == "https" then
        cookie = cookie .. "; Secure"
    end
    return cookie
end

-- ============ 挑战类型选择 ============

local VALID_TYPES = { js = true, redirect = true, slider = true, captcha = true }

local function parse_order(raw)
    local order = {}
    for part in tostring(raw or ""):gmatch("[^,]+") do
        part = trim(part):lower()
        if VALID_TYPES[part] then
            order[#order + 1] = part
        end
    end
    if #order == 0 then
        order = { "js", "redirect", "slider", "captcha" }
    end
    return order
end

local function choose_type(ctx, opts)
    opts = opts or {}
    -- 人机挑战总开关关闭时不下发任何挑战，由调用方回退为 429/403
    if trim(cfg("cc_challenge", "auto")):lower() == "off" then
        return nil
    end
    if opts.type and VALID_TYPES[opts.type] then
        return opts.type
    end

    local mode = trim(cfg("cc_challenge", "auto")):lower()
    if VALID_TYPES[mode] then
        return mode
    end

    -- auto：按已下发次数逐级升级；计数在真正创建新挑战时递增
    local order = parse_order(cfg("cc_challenge_order", "js,redirect,slider,captcha"))
    local dict = shared()
    if not dict then
        return order[1]
    end
    local prefix = (opts.reason == "behavior") and BEH_COUNTER_PREFIX or CC_COUNTER_PREFIX
    local count = tonumber(dict:get(prefix .. tostring(ctx.ip or "unknown"))) or 0
    local idx = math.min(count + 1, #order)
    return order[idx]
end

-- 记录一次真实下发（用于 auto 模式逐级升级），并刷新窗口
local function bump_challenge_level(ctx, reason)
    local dict = shared()
    if not dict then
        return
    end
    local prefix = (reason == "behavior") and BEH_COUNTER_PREFIX or CC_COUNTER_PREFIX
    local window = math.max(60, cfg_num("cc_challenge_fail_time", 600))
    local key = prefix .. tostring(ctx.ip or "unknown")
    dict:incr(key, 1, 0, window)
    dict:expire(key, window)
end

-- ============ 字符验证码（内置 5x7 点阵，以 SVG 矩形绘制） ============

local GLYPHS = {
    ["2"] = { "01110", "10001", "00001", "00010", "00100", "01000", "11111" },
    ["3"] = { "11111", "00001", "00010", "00110", "00001", "10001", "01110" },
    ["4"] = { "00010", "00110", "01010", "10010", "11111", "00010", "00010" },
    ["5"] = { "11111", "10000", "11110", "00001", "00001", "10001", "01110" },
    ["6"] = { "00110", "01000", "10000", "11110", "10001", "10001", "01110" },
    ["7"] = { "11111", "00001", "00010", "00100", "01000", "01000", "01000" },
    ["8"] = { "01110", "10001", "10001", "01110", "10001", "10001", "01110" },
    ["9"] = { "01110", "10001", "10001", "01111", "00001", "00010", "01100" },
    ["A"] = { "01110", "10001", "10001", "11111", "10001", "10001", "10001" },
    ["B"] = { "11110", "10001", "10001", "11110", "10001", "10001", "11110" },
    ["C"] = { "01110", "10001", "10000", "10000", "10000", "10001", "01110" },
    ["D"] = { "11110", "10001", "10001", "10001", "10001", "10001", "11110" },
    ["E"] = { "11111", "10000", "10000", "11110", "10000", "10000", "11111" },
    ["F"] = { "11111", "10000", "10000", "11110", "10000", "10000", "10000" },
    ["G"] = { "01110", "10001", "10000", "10111", "10001", "10001", "01111" },
    ["H"] = { "10001", "10001", "10001", "11111", "10001", "10001", "10001" },
    ["J"] = { "00111", "00010", "00010", "00010", "00010", "10010", "01100" },
    ["K"] = { "10001", "10010", "10100", "11000", "10100", "10010", "10001" },
    ["L"] = { "10000", "10000", "10000", "10000", "10000", "10000", "11111" },
    ["M"] = { "10001", "11011", "10101", "10101", "10001", "10001", "10001" },
    ["N"] = { "10001", "11001", "10101", "10011", "10001", "10001", "10001" },
    ["P"] = { "11110", "10001", "10001", "11110", "10000", "10000", "10000" },
    ["Q"] = { "01110", "10001", "10001", "10001", "10101", "10010", "01101" },
    ["R"] = { "11110", "10001", "10001", "11110", "10100", "10010", "10001" },
    ["S"] = { "01111", "10000", "10000", "01110", "00001", "00001", "11110" },
    ["T"] = { "11111", "00100", "00100", "00100", "00100", "00100", "00100" },
    ["U"] = { "10001", "10001", "10001", "10001", "10001", "10001", "01110" },
    ["V"] = { "10001", "10001", "10001", "10001", "10001", "01010", "00100" },
    ["W"] = { "10001", "10001", "10001", "10101", "10101", "11011", "10001" },
    ["X"] = { "10001", "10001", "01010", "00100", "01010", "10001", "10001" },
    ["Y"] = { "10001", "10001", "01010", "00100", "00100", "00100", "00100" },
    ["Z"] = { "11111", "00001", "00010", "00100", "01000", "10000", "11111" },
}
local CAPTCHA_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

local function random_captcha(len)
    local out = {}
    for i = 1, len do
        local idx = math.random(1, #CAPTCHA_CHARS)
        out[i] = CAPTCHA_CHARS:sub(idx, idx)
    end
    return table.concat(out)
end

-- 生成 SVG 验证码：每个字符以点阵矩形绘制（非文本节点），并叠加旋转与干扰线
local function build_captcha_svg(code)
    local parts = {}
    local width, height = 176, 64
    local colors = { "#1f2937", "#1d4ed8", "#7c3aed", "#b91c1c", "#047857", "#b45309" }

    parts[#parts + 1] = string.format(
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="captcha">',
        width, height, width, height)
    parts[#parts + 1] = string.format('<rect width="%d" height="%d" fill="#f8fafc" rx="8"/>', width, height)

    -- 干扰线
    for _ = 1, 5 do
        local x1, y1 = math.random(0, width), math.random(0, height)
        local x2, y2 = math.random(0, width), math.random(0, height)
        parts[#parts + 1] = string.format(
            '<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1" opacity="0.25"/>',
            x1, y1, x2, y2, colors[math.random(1, #colors)])
    end

    local cell = 5
    local char_w = cell * 5
    local gap = 4
    local start_x = math.floor((width - (#code * (char_w + gap)) + gap) / 2)
    local base_y = math.floor((height - cell * 7) / 2)

    for i = 1, #code do
        local glyph = GLYPHS[code:sub(i, i)]
        if glyph then
            local angle = math.random(-14, 14)
            local cx = start_x + (i - 1) * (char_w + gap) + char_w / 2
            local cy = base_y + cell * 7 / 2
            local color = colors[math.random(1, #colors)]
            local rects = {}
            for row = 1, 7 do
                local line = glyph[row]
                for col = 1, 5 do
                    if line:sub(col, col) == "1" then
                        local x = start_x + (i - 1) * (char_w + gap) + (col - 1) * cell
                        local y = base_y + (row - 1) * cell
                        rects[#rects + 1] = string.format(
                            '<rect x="%d" y="%d" width="%d" height="%d" rx="1"/>', x, y, cell - 1, cell - 1)
                    end
                end
            end
            parts[#parts + 1] = string.format(
                '<g fill="%s" transform="rotate(%d %d %d)">%s</g>',
                color, angle, math.floor(cx), math.floor(cy), table.concat(rects))
        end
    end

    -- 干扰点
    for _ = 1, 24 do
        parts[#parts + 1] = string.format(
            '<circle cx="%d" cy="%d" r="1" fill="%s" opacity="0.35"/>',
            math.random(0, width), math.random(0, height), colors[math.random(1, #colors)])
    end

    parts[#parts + 1] = '</svg>'
    return table.concat(parts)
end

-- ============ 页面模板 ============

local PAGE_HEAD = [==[
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>安全验证</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;background:linear-gradient(135deg,#eef2ff 0%,#f8fafc 45%,#e0f2fe 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.box{background:#fff;border-radius:14px;box-shadow:0 10px 40px rgba(15,23,42,.12);max-width:480px;width:100%;padding:34px 32px;text-align:center}
.icon{width:52px;height:52px;margin:0 auto 18px;background:#eff6ff;border-radius:50%;display:flex;align-items:center;justify-content:center}
.icon svg{width:28px;height:28px;fill:#2563eb}
h1{font-size:19px;color:#0f172a;font-weight:600;margin-bottom:8px}
.desc{font-size:13px;color:#64748b;line-height:1.7;margin-bottom:22px}
.err{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;border-radius:8px;padding:9px 12px;font-size:13px;margin-bottom:18px}
.bar{height:5px;background:#e2e8f0;border-radius:99px;overflow:hidden;margin:22px 0 10px}
.bar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,#3b82f6,#06b6d4);border-radius:99px;transition:width .25s linear}
.tip{font-size:12px;color:#94a3b8;margin-top:14px}
.btn{width:100%;padding:12px;border:none;border-radius:9px;background:#2563eb;color:#fff;font-size:15px;font-weight:500;cursor:pointer;transition:background .2s}
.btn:hover{background:#1d4ed8}
.btn:disabled{background:#93c5fd;cursor:not-allowed}
input[type=text]{width:100%;padding:12px 14px;border:1px solid #cbd5e1;border-radius:9px;font-size:16px;letter-spacing:2px;text-align:center;text-transform:uppercase;outline:none;margin-top:16px}
input[type=text]:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.captcha{display:flex;justify-content:center;margin:6px 0 2px;user-select:none}
.track{position:relative;height:48px;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:10px;margin-top:18px;overflow:hidden}
.track .fill{position:absolute;left:0;top:0;bottom:0;width:0;background:#dbeafe}
.track .gap{position:absolute;top:6px;width:40px;height:34px;border-radius:6px;background:#fff;box-shadow:inset 0 0 0 2px #93c5fd;display:flex;align-items:center;justify-content:center;color:#93c5fd;font-size:12px}
.thumb{position:absolute;left:0;top:5px;width:42px;height:36px;border-radius:7px;background:linear-gradient(180deg,#60a5fa,#2563eb);box-shadow:0 3px 8px rgba(37,99,235,.35);cursor:grab;display:flex;align-items:center;justify-content:center;touch-action:none}
.thumb:active{cursor:grabbing}
.thumb svg{width:18px;height:18px;fill:#fff}
.footer{margin-top:20px;font-size:12px;color:#94a3b8}
</style>
</head>
<body>
<div class="box">
<div class="icon"><svg viewBox="0 0 24 24"><path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 15-4-4 1.41-1.41L11 13.17l5.59-5.59L18 9l-7 7z"/></svg></div>
]==]

local PAGE_FOOT = [==[
<div class="footer">Nova WAF 人机验证 · 本页面不会收集您的隐私数据</div>
</div>
</body>
</html>
]==]

local function page_wrap(title, desc, body)
    return PAGE_HEAD .. '<h1>' .. html_escape(title) .. '</h1><p class="desc">' ..
        html_escape(desc) .. '</p>' .. body .. PAGE_FOOT
end

local function error_banner(message)
    if not message or message == "" then
        return ""
    end
    return '<div class="err">' .. html_escape(message) .. '</div>'
end

local VERIFY_FORM_OPEN = '<form method="POST" action="/_waf_challenge/verify" autocomplete="off">'

-- JS 挑战：客户端做哈希工作量证明后提交，拦截不执行 JS 的脚本客户端
local function render_js(id, back, prefix, difficulty, err)
    local body = error_banner(err) ..
        '<p class="desc" style="margin-bottom:6px">正在验证您的浏览器，请稍候…</p>' ..
        '<div class="bar"><i id="p"></i></div>' ..
        '<p class="tip" id="tip">正在进行安全检查</p>' ..
        VERIFY_FORM_OPEN ..
        '<input type="hidden" name="id" value="' .. id .. '">' ..
        '<input type="hidden" name="back" value="' .. html_escape(back) .. '">' ..
        '<input type="hidden" name="answer" id="ans" value="">' ..
        '</form>' ..
        '<script>(function(){' ..
        'var P=' .. string.format("%q", prefix) .. ',D=' .. tostring(difficulty) .. ',N=0,ans=document.getElementById("ans"),bar=document.getElementById("p"),tip=document.getElementById("tip");' ..
        'function h(s){var x=0;for(var i=0;i<s.length;i++){x=(s.charCodeAt(i)+(x<<6)+(x<<16)-x)|0}return x>>>0}' ..
        'function pad(v){var s=v.toString(16);while(s.length<8){s="0"+s}return s}' ..
        'setTimeout(function(){var t=Date.now();for(;;){var z=0,x=pad(h(P+N));while(z<8&&x.charAt(z)==="0"){z++}if(z>=D){break}N++;if(N>5000000){tip.textContent="验证失败，请刷新重试";return}}' ..
        'ans.value=String(N);bar.style.width="100%";tip.textContent="验证通过，正在进入…";' ..
        'setTimeout(function(){document.forms[0].submit()},120)},80);' ..
        '})();</script>'
    return page_wrap("安全验证", "检测到访问频率异常，请完成一次快速验证。", body)
end

-- 5 秒跳转：等待固定时长后自动提交，显著降低脚本请求速率
local function render_redirect(id, back, delay, err)
    local body = error_banner(err) ..
        '<p class="desc" style="margin-bottom:6px">正在检查您的网络环境，请勿关闭页面。</p>' ..
        '<div class="bar"><i id="p" style="width:0"></i></div>' ..
        '<p class="tip"><span id="s">' .. tostring(delay) .. '</span> 秒后自动继续</p>' ..
        VERIFY_FORM_OPEN ..
        '<input type="hidden" name="id" value="' .. id .. '">' ..
        '<input type="hidden" name="back" value="' .. html_escape(back) .. '">' ..
        '<input type="hidden" name="answer" value="wait">' ..
        '</form>' ..
        '<script>(function(){' ..
        'var total=' .. tostring(delay) .. ',left=total,p=document.getElementById("p"),s=document.getElementById("s");' ..
        'var t=setInterval(function(){left--;if(left<0){left=0}s.textContent=left;p.style.width=(((total-left)/total)*100)+"%";' ..
        'if(left<=0){clearInterval(t);document.forms[0].submit()}},1000);' ..
        '})();</script>'
    return page_wrap("安全验证", "系统正在确认本次访问是否来自真实浏览器。", body)
end

-- 滑块挑战：拖动拼图对齐缺口，答案（目标位置百分比）仅保存在服务端
local function render_slider(id, back, target, err)
    local body = error_banner(err) ..
        '<p class="desc" style="margin-bottom:4px">拖动滑块，使拼图对齐缺口。</p>' ..
        '<div class="track" id="track">' ..
        '<div class="fill" id="fill"></div>' ..
        '<div class="gap" id="gap" style="left:calc(' .. tostring(target) .. '% - 20px)"></div>' ..
        '<div class="thumb" id="thumb"><svg viewBox="0 0 24 24"><path d="M8 5l8 7-8 7V5z"/></svg></div>' ..
        '</div>' ..
        VERIFY_FORM_OPEN ..
        '<input type="hidden" name="id" value="' .. id .. '">' ..
        '<input type="hidden" name="back" value="' .. html_escape(back) .. '">' ..
        '<input type="hidden" name="answer" id="ans" value="">' ..
        '<button type="submit" class="btn" id="btn" style="margin-top:18px" disabled>验证</button>' ..
        '</form>' ..
        '<script>(function(){' ..
        'var track=document.getElementById("track"),thumb=document.getElementById("thumb"),fill=document.getElementById("fill"),ans=document.getElementById("ans"),btn=document.getElementById("btn"),drag=false,max=0;' ..
        -- 缺口中心固定落在 target%，滑块中心与之对齐；提交值为滑块中心的百分比
        'function pct(){var w=track.clientWidth;var c=parseFloat(thumb.style.left||"0")+21;return w>0?Math.round(c/w*100):0}' ..
        'function set(x){if(x<0)x=0;if(x>max)x=max;thumb.style.left=x+"px";fill.style.width=(x+21)+"px";ans.value=pct()}' ..
        'function pos(e){var r=track.getBoundingClientRect();var cx=(e.touches?e.touches[0].clientX:e.clientX);return cx-r.left-21}' ..
        'function start(e){drag=true;max=track.clientWidth-42;set(pos(e));e.preventDefault()}' ..
        'function move(e){if(!drag)return;set(pos(e));e.preventDefault()}' ..
        'function end(){if(!drag)return;drag=false;btn.disabled=false}' ..
        'thumb.addEventListener("mousedown",start);document.addEventListener("mousemove",move);document.addEventListener("mouseup",end);' ..
        'thumb.addEventListener("touchstart",start,{passive:false});document.addEventListener("touchmove",move,{passive:false});document.addEventListener("touchend",end);' ..
        'window.addEventListener("resize",function(){max=track.clientWidth-42});' ..
        'max=track.clientWidth-42;' ..
        '})();</script>'
    return page_wrap("安全验证", "请完成滑块验证以继续访问。", body)
end

-- 字符验证码
local function render_captcha(id, back, svg, err)
    local body = error_banner(err) ..
        '<p class="desc" style="margin-bottom:4px">请输入下图中的字符（不区分大小写）。</p>' ..
        '<div class="captcha">' .. svg .. '</div>' ..
        VERIFY_FORM_OPEN ..
        '<input type="hidden" name="id" value="' .. id .. '">' ..
        '<input type="hidden" name="back" value="' .. html_escape(back) .. '">' ..
        '<input type="text" name="answer" maxlength="8" placeholder="输入验证码" required autofocus>' ..
        '<button type="submit" class="btn" style="margin-top:14px">验证并继续</button>' ..
        '</form>'
    return page_wrap("安全验证", "为防止自动化程序滥用，请完成验证码。", body)
end

-- 失败/过期提示页
local function render_message(title, desc, back)
    local body = '<p class="desc">' .. html_escape(desc) .. '</p>' ..
        '<a class="btn" style="display:block;text-decoration:none;line-height:20px" href="' ..
        html_escape(safe_back_uri(back)) .. '">重新访问</a>'
    return page_wrap(title, "", body)
end

-- ============ 下发挑战 ============

local function send_page(html, status)
    ngx.status = status or 403
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["X-Robots-Tag"] = "noindex, nofollow"
    ngx.header["Content-Security-Policy"] =
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; " ..
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ngx.say(html)
    ngx.exit(ngx.status)
end

-- 前向声明：issue 内部需要解析已存挑战以复用
local parse_challenge

-- 下发挑战页；返回 issued, created：
--   issued  = true 表示挑战页已输出（函数内部已 ngx.exit）
--   created = true 表示新建了挑战（用于日志/统计节流，复用时为 false）
-- opts: { type, reason = "cc"|"behavior", error, back, orig }
function _M.issue(ctx, opts)
    opts = opts or {}
    local kind = choose_type(ctx, opts)
    if not kind then
        return false, false
    end

    local dict = shared()
    if not dict then
        return false, false
    end

    local ip = tostring(ctx.ip or "")
    local ua = behavior_header(ctx, "user-agent") or ""
    local ip_key = CHAL_IP_PREFIX .. ip .. ":" .. ngx.md5(ua)
    local back = safe_back_uri(opts.orig or (ngx.var and ngx.var.request_uri) or "/")

    -- 复用同 IP + 同 UA 未过期的挑战：防止攻击者高频刷新页面把共享字典打满
    local now = ngx.now()
    local id, data1, data2, issued_at
    local existing_id = opts.error == nil and dict:get(ip_key) or nil
    if existing_id then
        local existing = parse_challenge(dict:get(CHAL_PREFIX .. existing_id))
        if existing and existing.kind == kind and existing.ip == ip
            and (now - existing.ts) < (CHAL_TTL - 10) then
            id = existing_id
            data1 = existing.data1
            data2 = existing.data2
            issued_at = existing.ts
        end
    end

    local created = false
    if not id then
        -- 单 IP 下发频率限制：超过上限时不再新发挑战（调用方回退 429/403）
        local issue_key = CHAL_ISSUE_PREFIX .. ip
        local issue_window = math.max(30, cfg_num("cc_challenge_fail_time", 600))
        local issue_max = math.max(3, cfg_num("cc_challenge_issue_max", 20))
        local issue_count = dict:incr(issue_key, 1, 0, issue_window) or 1
        dict:expire(issue_key, issue_window)
        if issue_count > issue_max then
            ngx.log(ngx.WARN, "challenge issue limit reached: ", ip, " count=", issue_count)
            return false, false
        end

        id = new_challenge_id()
        issued_at = now
        data1, data2 = "", ""
        if kind == "js" then
            data1 = random_hex(8)
            data2 = tostring(math.max(1, math.min(6, cfg_num("cc_challenge_pow", 3))))
        elseif kind == "slider" then
            data1 = tostring(math.random(28, 82))
        elseif kind == "captcha" then
            data1 = random_captcha(4)
        elseif kind == "redirect" then
            data1 = tostring(math.max(1, cfg_num("cc_challenge_delay", 5)))
        end

        -- 存储格式：type|ip|issued_at|data1|data2|orig
        local packed = table.concat({
            kind, ip, string.format("%.3f", issued_at), data1, data2, back
        }, "|")
        dict:set(CHAL_PREFIX .. id, packed, CHAL_TTL)
        dict:set(ip_key, id, CHAL_TTL)
        ctx.count:addChallengeCount("issued", kind)
        bump_challenge_level(ctx, opts.reason)
        created = true
    end

    local html
    if kind == "js" then
        html = render_js(id, back, data1, tonumber(data2), opts.error)
    elseif kind == "redirect" then
        html = render_redirect(id, back, tonumber(data1), opts.error)
    elseif kind == "slider" then
        html = render_slider(id, back, tonumber(data1), opts.error)
    else
        html = render_captcha(id, back, build_captcha_svg(data1), opts.error)
    end

    send_page(html, 403)
    return true, created
end

-- ============ 处理验证提交 ============

local function parse_challenge_impl(raw)
    if type(raw) ~= "string" then
        return nil
    end
    local kind, ip, ts, data1, data2, orig =
        string.match(raw, "^([^|]*)|([^|]*)|([^|]*)|([^|]*)|([^|]*)|(.*)$")
    if not kind then
        return nil
    end
    return {
        kind = kind,
        ip = ip,
        ts = tonumber(ts) or 0,
        data1 = data1 or "",
        data2 = data2 or "",
        orig = orig or "/",
    }
end
-- 把前向声明绑定到真实实现（issue 通过该 upvalue 调用）
parse_challenge = parse_challenge_impl

-- 无符号 32 位 SDBM 哈希（与页面内 JS 实现一致）
local function sdbm(s)
    local h = 0
    for i = 1, #s do
        h = bit.tobit(h * 65599 + s:byte(i))
    end
    if h < 0 then
        h = h + 4294967296
    end
    return bit.tohex(h)
end

local function leading_zeros(hex)
    local z = 0
    for i = 1, #hex do
        if hex:sub(i, i) == "0" then
            z = z + 1
        else
            break
        end
    end
    return z
end

local function verify_answer(chal, answer)
    if chal.kind == "js" then
        if not answer or answer == "" or #answer > 32 or not answer:match("^%d+$") then
            return false
        end
        local difficulty = tonumber(chal.data2) or 3
        return leading_zeros(sdbm(chal.data1 .. answer)) >= difficulty
    elseif chal.kind == "redirect" then
        local delay = tonumber(chal.data1) or 5
        -- 允许 0.75 秒的时钟/网络误差
        return (ngx.now() - chal.ts) >= (delay - 0.75)
    elseif chal.kind == "slider" then
        local target = tonumber(chal.data1) or 50
        local value = tonumber(answer)
        if not value then
            return false
        end
        return math.abs(value - target) <= 4
    elseif chal.kind == "captcha" then
        if not answer or #answer > 8 then
            return false
        end
        return answer:upper() == chal.data1
    end
    return false
end

local function verify_request_uri()
    return VERIFY_URI
end
_M.verify_uri = verify_request_uri()

function _M.is_verify_request(uri)
    return uri == VERIFY_URI
end

-- 处理验证提交，函数内部会 ngx.exit，不会返回
function _M.handle_verify(ctx)
    local method = ngx.req.get_method()
    if method ~= "POST" then
        ngx.header["Allow"] = "POST"
        send_page(render_message("请求无效", "验证请求必须使用 POST 方法。", "/"), 405)
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local body_file = ngx.req.get_body_file()
        if body_file then
            local f = io.open(body_file, "rb")
            if f then
                body = f:read("*a")
                f:close()
            end
        end
    end
    if not body or #body > 4096 then
        send_page(render_message("请求无效", "验证请求内容异常，请重新访问。", "/"), 403)
    end

    local args = ngx.req.get_post_args(20)
    local id = args and args.id
    local answer = args and args.answer
    local back = args and args.back
    if type(id) == "table" then id = id[1] end
    if type(answer) == "table" then answer = answer[1] end
    if type(back) == "table" then back = back[1] end

    local dict = shared()
    local key = type(id) == "string" and id:match("^[a-f0-9]+$") and (CHAL_PREFIX .. id) or nil
    local raw = key and dict and dict:get(key)
    local chal = parse_challenge(raw)

    if not chal or chal.ip ~= tostring(ctx.ip or "") then
        ctx.count:addChallengeCount("failed", "expired")
        send_page(render_message("验证已过期", "验证码已失效，请返回原页面重新访问。", back), 403)
    end

    if not verify_answer(chal, tostring(answer or "")) then
        -- 达到失败上限后直接封禁，阻断暴力尝试
        local fail_window = math.max(60, cfg_num("cc_challenge_fail_time", 600))
        local max_fail = math.max(1, cfg_num("cc_challenge_max_fail", 5))
        local fail_key = FAIL_PREFIX .. tostring(ctx.ip or "unknown")
        local fails = dict:incr(fail_key, 1, 0, fail_window) or 1
        dict:expire(fail_key, fail_window)
        ctx.count:addChallengeCount("failed", chal.kind)

        if fails >= max_fail then
            dict:delete(key)
            dict:set("block:" .. tostring(ctx.ip or ""), 1, fail_window)
            ctx:recordRequest("Challenge Failure", "")
            ctx.count:addAttackCount("Challenge Failure", ctx.ip, ctx.host, ngx.var.request_uri)
            send_page(render_message("访问已限制", "验证失败次数过多，请稍后再试。", chal.orig), 403)
        end

        -- 未达上限：重新下发同类型挑战，保留错误提示（复用状态由 issue 内部处理）
        local reissued = _M.issue(ctx, {
            type = chal.kind,
            reason = "cc",
            error = "验证失败，请重试。",
            orig = chal.orig,
        })
        if not reissued then
            send_page(render_message("验证失败", "请返回原页面重新访问。", chal.orig), 403)
        end
    end

    -- 验证通过：清理失败计数、挑战升级计数与 CC 窗口，签发通行 Cookie
    dict:delete(key)
    dict:delete(FAIL_PREFIX .. tostring(ctx.ip or "unknown"))
    local ip_key = tostring(ctx.ip or "unknown")
    dict:delete(CC_COUNTER_PREFIX .. ip_key)
    dict:delete(BEH_COUNTER_PREFIX .. ip_key)
    dict:delete("cc:" .. ip_key)
    dict:delete("beh:" .. ip_key)
    dict:delete("behc:" .. ip_key)
    ctx.count:addChallengeCount("passed", chal.kind)

    ngx.header["Set-Cookie"] = pass_cookie(ctx)
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["X-Robots-Tag"] = "noindex, nofollow"
    local target = safe_back_uri(chal.orig)
    if target == "/" then
        target = safe_back_uri(back)
    end
    ngx.redirect(target, 303)
end

return _M
