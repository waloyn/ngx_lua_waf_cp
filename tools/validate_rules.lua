-- WAF 规则离线校验工具
-- 检查 rules/*.lua 的：文件可加载性、pattern 编译、position 合法性
-- 用法：perl -x E:/WebSite/openresty/resty tools/validate_rules.lua [waf根目录]
-- 退出码：0 全部通过；1 存在错误
-- 背景：2026-11-03 审查发现 upload.lua 10 条规则因 Lua 长字符串截断导致正则编译失败、
--       被引擎静默忽略（ngx.re.match 编译失败只返回 nil）。luac -p 无法发现这类问题，故加此校验。
local BASE = "E:/WebSite/openresty/waf/"
if type(arg) == "table" and type(arg[1]) == "string" and arg[1] ~= "" then
    BASE = arg[1]
end
if BASE:sub(-1) ~= "/" then BASE = BASE .. "/" end

local VALID_POSITIONS = { uri = true, body = true, cookie = true, ["user-agent"] = true, headers = true }

local function list_rule_files(dir)
    local files = {}
    local is_windows = package.config:sub(1, 1) == "\\"
    local cmd = is_windows and ('dir "' .. dir:gsub("/", "\\") .. '" /b /a-d') or ('ls -1 "' .. dir .. '"')
    local iter = io.popen(cmd)
    if iter then
        for f in iter:lines() do
            f = f:gsub("[\r\n]+", "")
            if f:match("%.lua$") then table.insert(files, f) end
        end
        iter:close()
    end
    table.sort(files)
    return files
end

local errors, warnings, total = 0, 0, 0
for _, file in ipairs(list_rule_files(BASE .. "rules/")) do
    local chunk, lerr = loadfile(BASE .. "rules/" .. file)
    if not chunk then
        print(string.format("[FAIL] %s: 无法加载: %s", file, tostring(lerr)))
        errors = errors + 1
    else
        local ok, mod = pcall(chunk)
        if not ok or type(mod) ~= "table" then
            print(string.format("[FAIL] %s: 加载异常: %s", file, tostring(mod)))
            errors = errors + 1
        else
            for part in string.gmatch(mod.position or "", "([^,]+)") do
                part = part:match("^%s*(.-)%s*$"):lower()
                if not VALID_POSITIONS[part] then
                    print(string.format("[WARN] %s: 未知 position '%s'（该规则将静默失效）", file, part))
                    warnings = warnings + 1
                end
            end
            local n = 0
            for i, item in ipairs(mod.rules or {}) do
                n = n + 1
                total = total + 1
                local p = tostring(item.pattern or ""):match("^%s*(.-)%s*$")
                if p == "" then
                    print(string.format("[FAIL] %s #%d (%s): pattern 为空", file, i, tostring(item.name)))
                    errors = errors + 1
                else
                    local _, _, rerr = ngx.re.find("validate", p, "isjo")
                    if rerr then
                        print(string.format("[FAIL] %s #%d (%s): 编译失败: %s", file, i, tostring(item.name), tostring(rerr)))
                        errors = errors + 1
                    end
                end
            end
            print(string.format("[ OK ] %s: %d 条规则", file, n))
        end
    end
end

print(string.format("\n合计 %d 条规则：错误 %d，警告 %d", total, errors, warnings))
if errors > 0 then
    os.exit(1)
end
