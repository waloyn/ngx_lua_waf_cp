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

-- Windows 控制台默认使用 ANSI 代码页（简体中文为 936）。UTF-8 中文直接写入会乱码，
-- 且末字节可能被当成双字节字符的首字节而吞掉后面的换行，所以输出到控制台时转换编码；
-- 重定向到文件或管道时保持 UTF-8。
local function make_say()
    local stdout = io.stdout
    local function plain(s)
        stdout:write(s, "\n")
        stdout:flush()
    end

    if package.config:sub(1, 1) ~= "\\" then
        return plain
    end

    local ok, ffi = pcall(require, "ffi")
    if not ok then
        return plain
    end

    local kernel32 = ffi.load("kernel32")
    ffi.cdef[[
        void *GetStdHandle(unsigned int nStdHandle);
        int GetConsoleMode(void *hConsoleHandle, unsigned int *lpMode);
        unsigned int GetConsoleOutputCP(void);
        int MultiByteToWideChar(unsigned int CodePage, unsigned long dwFlags,
            const char *lpMultiByteStr, int cbMultiByte,
            uint16_t *lpWideCharStr, int cchWideChar);
        int WideCharToMultiByte(unsigned int CodePage, unsigned long dwFlags,
            const uint16_t *lpWideCharStr, int cchWideChar,
            char *lpMultiByteStr, int cbMultiByte,
            const char *lpDefaultChar, int *lpUsedDefaultChar);
    ]]

    local handle = kernel32.GetStdHandle(-11) -- STD_OUTPUT_HANDLE
    local mode = ffi.new("unsigned int[1]")
    if kernel32.GetConsoleMode(handle, mode) == 0 then
        return plain -- 输出已重定向
    end

    local cp = kernel32.GetConsoleOutputCP()
    if cp == 0 or cp == 65001 then
        return plain -- 控制台已经使用 UTF-8
    end

    local function to_console_cp(s)
        local n = kernel32.MultiByteToWideChar(65001, 0, s, #s, nil, 0)
        if n <= 0 then return s end
        local w = ffi.new("uint16_t[?]", n)
        if kernel32.MultiByteToWideChar(65001, 0, s, #s, w, n) <= 0 then
            return s
        end
        local m = kernel32.WideCharToMultiByte(cp, 0, w, n, nil, 0, nil, nil)
        if m <= 0 then return s end
        local b = ffi.new("char[?]", m)
        if kernel32.WideCharToMultiByte(cp, 0, w, n, b, m, nil, nil) <= 0 then
            return s
        end
        return ffi.string(b, m)
    end

    return function(s)
        stdout:write(to_console_cp(s), "\n")
        stdout:flush()
    end
end

local say = make_say()

if type(ngx) ~= "table" or type(ngx.re) ~= "table" or type(ngx.re.find) ~= "function" then
    say("错误：需要在 OpenResty resty 环境中运行（ngx.re 不可用）")
    os.exit(1)
end

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

local function report(file, n, file_errors, file_warnings, details)
    if file_errors == 0 and file_warnings == 0 then
        say(string.format("[ OK ] %s: %d 条规则", file, n))
        return
    end

    local tag = file_errors > 0 and "FAIL" or "WARN"
    if n then
        say(string.format("[%s] %s: %d 条规则，错误 %d，警告 %d",
            tag, file, n, file_errors, file_warnings))
    else
        say(string.format("[%s] %s", tag, file))
    end
    for _, msg in ipairs(details) do
        say("  " .. msg)
    end
end

for _, file in ipairs(list_rule_files(BASE .. "rules/")) do
    local file_errors, file_warnings = 0, 0
    local details = {}
    local chunk, lerr = loadfile(BASE .. "rules/" .. file)
    if not chunk then
        file_errors = file_errors + 1
        details[#details + 1] = "无法加载: " .. tostring(lerr)
        report(file, nil, file_errors, file_warnings, details)
    else
        local ok, mod = pcall(chunk)
        if not ok or type(mod) ~= "table" then
            file_errors = file_errors + 1
            details[#details + 1] = "加载异常: " .. tostring(mod)
            report(file, nil, file_errors, file_warnings, details)
        elseif type(mod.rules) ~= "table" then
            file_errors = file_errors + 1
            details[#details + 1] = "rules 字段缺失或不是 table"
            report(file, nil, file_errors, file_warnings, details)
        else
            for part in string.gmatch(tostring(mod.position or ""), "([^,]+)") do
                part = part:match("^%s*(.-)%s*$"):lower()
                if not VALID_POSITIONS[part] then
                    file_warnings = file_warnings + 1
                    details[#details + 1] = string.format("未知 position '%s'（该规则将静默失效）", part)
                end
            end

            local n = 0
            for i, item in ipairs(mod.rules) do
                n = n + 1
                if type(item) ~= "table" then
                    file_errors = file_errors + 1
                    details[#details + 1] = string.format("#%d: 规则项不是 table", i)
                else
                    local p = tostring(item.pattern or ""):match("^%s*(.-)%s*$")
                    if p == "" then
                        file_errors = file_errors + 1
                        details[#details + 1] = string.format("#%d (%s): pattern 为空", i, tostring(item.name))
                    else
                        local _, _, rerr = ngx.re.find("validate", p, "isjo")
                        if rerr then
                            file_errors = file_errors + 1
                            details[#details + 1] = string.format("#%d (%s): 编译失败: %s", i, tostring(item.name), tostring(rerr))
                        end
                    end
                end
            end

            total = total + n
            report(file, n, file_errors, file_warnings, details)
        end
    end

    errors = errors + file_errors
    warnings = warnings + file_warnings
end

say(string.format("\n合计 %d 条规则：错误 %d，警告 %d", total, errors, warnings))
if errors > 0 then
    os.exit(1)
end
