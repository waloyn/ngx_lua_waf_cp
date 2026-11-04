-- WAF 规则命中率与基准覆盖度测试工具
-- 评估 rules/*.lua 各规则在攻击载荷与合法载荷下的检出率、规则激活度及盲区
-- 用法：perl -x E:/WebSite/openresty/resty tools/test_rule_hit_rate.lua [选项]
-- 选项：
--   --help, -h          显示帮助信息
--   --type <name>       仅测试指定分类规则（例如 --type sqli）
--   --detail, -d        显示每条规则命中明细及 0 命中盲区规则清单
--   --uncovered, -u     仅展示 0 命中的盲区规则清单
--   --file <path>       加载额外的外部 JSON 测试载荷

local BASE = "E:/WebSite/openresty/waf/"
if type(arg) == "table" and type(arg[1]) == "string" and arg[1] ~= "" and not arg[1]:match("^%-") then
    BASE = arg[1]
end
if BASE:sub(-1) ~= "/" then BASE = BASE .. "/" end

-- 设置 package.path
package.path = BASE .. "?.lua;"
    .. BASE .. "rules/?.lua;"
    .. BASE .. "utils/?.lua;"
    .. BASE .. "tools/?.lua;"
    .. package.path

-- Windows 控制台代码页自适应（避免控制台 ANSI/CP936 乱码）
local function make_say()
    local stdout = io.stdout
    local function plain(s)
        stdout:write(s or "", "\n")
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
        return plain -- 已重定向到文件或管道
    end

    local cp = kernel32.GetConsoleOutputCP()
    if cp == 0 or cp == 65001 then
        return plain -- 控制台已是 UTF-8
    end

    local function to_console_cp(s)
        if not s or s == "" then return "" end
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
        stdout:write(to_console_cp(s or ""), "\r\n")
        stdout:flush()
    end
end

local say = make_say()

-- 检查 OpenResty resty 环境
if type(ngx) ~= "table" or type(ngx.re) ~= "table" or type(ngx.re.find) ~= "function" then
    say("错误：需要在 OpenResty resty 环境中运行（ngx.re 不可用）")
    say("运行示例：perl -x E:/WebSite/openresty/resty tools/test_rule_hit_rate.lua")
    os.exit(1)
end

-- 解析命令行选项
local opt_type = nil
local opt_detail = false
local opt_uncovered = false
local opt_file = nil

if type(arg) == "table" then
    local i = 1
    while i <= #arg do
        local a = arg[i]
        if a == "--help" or a == "-h" then
            say("WAF 规则命中率与基准覆盖度测试工具")
            say("用法：perl -x E:/WebSite/openresty/resty tools/test_rule_hit_rate.lua [选项]")
            say("选项：")
            say("  -h, --help            显示本帮助信息")
            say("  --type <module>       仅测试指定分类规则 (如 sqli, xss, cmd, ssrf 等)")
            say("  -d, --detail          展示各规则具体命中频次明细及 0 命中盲区清单")
            say("  -u, --uncovered       仅展示各模块未被覆盖的 0 命中规则清单")
            say("  --file <path>         外挂指定 JSON 格式测试用例文件")
            os.exit(0)
        elseif a == "--type" then
            i = i + 1
            opt_type = arg[i]
        elseif a == "--detail" or a == "-d" then
            opt_detail = true
        elseif a == "--uncovered" or a == "-u" then
            opt_uncovered = true
        elseif a == "--file" then
            i = i + 1
            opt_file = arg[i]
        end
        i = i + 1
    end
end

-- 遍历规则文件列表
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

-- 加载基准测试用例库
local ok_payloads, payload_suite = pcall(require, "test_payloads")
if not ok_payloads or type(payload_suite) ~= "table" then
    say("错误：无法加载基准测试用例库 test_payloads.lua: " .. tostring(payload_suite))
    os.exit(1)
end

-- 加载外部 JSON 载荷（如有）
if opt_file then
    local f, err = io.open(opt_file, "r")
    if not f then
        say("警告：无法打开外部载荷文件: " .. tostring(err))
    else
        local content = f:read("*all")
        f:close()
        local ok_json, cjson = pcall(require, "cjson.safe")
        if ok_json and cjson then
            local extra = cjson.decode(content)
            if type(extra) == "table" then
                for mod_name, suite in pairs(extra) do
                    payload_suite[mod_name] = payload_suite[mod_name] or { attacks = {}, legitimate = {} }
                    if type(suite.attacks) == "table" then
                        for _, a in ipairs(suite.attacks) do
                            table.insert(payload_suite[mod_name].attacks, a)
                        end
                    end
                    if type(suite.legitimate) == "table" then
                        for _, l in ipairs(suite.legitimate) do
                            table.insert(payload_suite[mod_name].legitimate, l)
                        end
                    end
                end
                say("成功合并外部载荷文件: " .. opt_file)
            end
        end
    end
end

-- 加载并编译 rules
local rule_modules = {}
local total_rules_count = 0

for _, file in ipairs(list_rule_files(BASE .. "rules/")) do
    local mod_key = file:match("^([%w_]+)%.lua$")
    if mod_key and (not opt_type or opt_type == mod_key) then
        local chunk, lerr = loadfile(BASE .. "rules/" .. file)
        if chunk then
            local ok, mod = pcall(chunk)
            if ok and type(mod) == "table" and type(mod.rules) == "table" then
                local positions = {}
                for part in string.gmatch(tostring(mod.position or ""), "([^,]+)") do
                    part = part:match("^%s*(.-)%s*$"):lower()
                    if part ~= "" then table.insert(positions, part) end
                end

                local items = {}
                for i, r in ipairs(mod.rules) do
                    local pat = tostring(r.pattern or ""):match("^%s*(.-)%s*$")
                    items[i] = {
                        index = i,
                        name = r.name or ("Rule #" .. i),
                        pattern = pat,
                        confidence = tonumber(r.confidence) or 1,
                        hit_count = 0,
                        hit_samples = {}
                    }
                    total_rules_count = total_rules_count + 1
                end

                rule_modules[mod_key] = {
                    file = file,
                    name = mod.name or mod_key,
                    desc = mod.desc or "",
                    level = mod.level or "medium",
                    positions = positions,
                    rules = items
                }
            end
        end
    end
end

-- 构造测试上下文 checkData（严格与 waf.lua 对齐）
local function build_check_data(pos_target, payload)
    local checkData = {}
    local pos = (pos_target or "uri"):lower()
    if pos == "uri" then
        table.insert(checkData, { pos = "uri", is_header = false, text = payload })
    elseif pos == "body" then
        table.insert(checkData, { pos = "body", is_header = false, text = payload })
    elseif pos == "cookie" then
        table.insert(checkData, { pos = "cookie", is_header = true, text = "cookie: " .. payload })
    elseif pos == "user-agent" then
        table.insert(checkData, { pos = "user-agent", is_header = true, text = "user-agent: " .. payload })
    else
        table.insert(checkData, { pos = pos, is_header = true, text = pos .. ": " .. payload })
    end
    return checkData
end

-- 检查某个 checkData 集合是否触发特定模块规则，并更新规则命中状态
-- 参数 audit_all: 为 true 时测试所有规则的触发能力（统计覆盖度）；为 false 时模拟首个命中
local function match_module_rules(mod, checkData, sample, is_attack)
    local hits = {}
    for _, item in ipairs(checkData) do
        local hit_pos = nil
        for _, p in ipairs(mod.positions) do
            if item.pos == p or (p == "headers" and item.is_header) then
                hit_pos = item.pos
                break
            end
        end

        if hit_pos then
            for _, r in ipairs(mod.rules) do
                if r.pattern ~= "" then
                    local from, to = ngx.re.find(item.text, r.pattern, "isjo")
                    if from then
                        r.hit_count = r.hit_count + 1
                        table.insert(r.hit_samples, {
                            pos = hit_pos,
                            note = sample.note,
                            is_attack = is_attack,
                            payload = sample.payload
                        })
                        table.insert(hits, {
                            rule_name = r.name,
                            pos = hit_pos,
                            confidence = r.confidence
                        })
                    end
                end
            end
        end
    end
    return hits
end

-- 执行全量测试并收集统计数据
local stats = {}
local global_total_attacks = 0
local global_detected_attacks = 0
local global_total_legit = 0
local global_fp_legit = 0

-- 确保按规则名称排序
local sorted_keys = {}
for k in pairs(rule_modules) do table.insert(sorted_keys, k) end
table.sort(sorted_keys)

for _, mod_key in ipairs(sorted_keys) do
    local mod = rule_modules[mod_key]
    local suite = payload_suite[mod_key] or { attacks = {}, legitimate = {} }

    local attack_list = suite.attacks or {}
    local legit_list = suite.legitimate or {}

    local detected_count = 0
    local missed_attacks = {}

    -- 1. 正向攻击样本测试（Detection Rate）
    for _, sample in ipairs(attack_list) do
        local test_pos = sample.pos
        if not test_pos or test_pos == "" then
            test_pos = mod.positions[1] or "uri"
        end
        local checkData = build_check_data(test_pos, sample.payload)
        local hits = match_module_rules(mod, checkData, sample, true)
        if #hits > 0 then
            detected_count = detected_count + 1
        else
            table.insert(missed_attacks, sample)
        end
    end

    -- 2. 负向良性样本测试（False Positive Rate）
    local fp_count = 0
    local fp_samples = {}
    for _, sample in ipairs(legit_list) do
        local test_pos = sample.pos or mod.positions[1] or "uri"
        local checkData = build_check_data(test_pos, sample.payload)
        local hits = match_module_rules(mod, checkData, sample, false)
        if #hits > 0 then
            fp_count = fp_count + 1
            table.insert(fp_samples, { sample = sample, hits = hits })
        end
    end

    -- 3. 统计规则激活覆盖率（Rule Coverage）
    local activated_rules = 0
    local zero_hit_rules = {}
    for _, r in ipairs(mod.rules) do
        if r.hit_count > 0 then
            activated_rules = activated_rules + 1
        else
            table.insert(zero_hit_rules, r)
        end
    end

    stats[mod_key] = {
        name = mod.name,
        total_rules = #mod.rules,
        activated_rules = activated_rules,
        rule_coverage = #mod.rules > 0 and (activated_rules / #mod.rules * 100) or 0,
        total_attacks = #attack_list,
        detected_attacks = detected_count,
        detection_rate = #attack_list > 0 and (detected_count / #attack_list * 100) or 0,
        total_legit = #legit_list,
        fp_count = fp_count,
        fp_rate = #legit_list > 0 and (fp_count / #legit_list * 100) or 0,
        zero_hit_rules = zero_hit_rules,
        missed_attacks = missed_attacks,
        fp_samples = fp_samples
    }

    global_total_attacks = global_total_attacks + #attack_list
    global_detected_attacks = global_detected_attacks + detected_count
    global_total_legit = global_total_legit + #legit_list
    global_fp_legit = global_fp_legit + fp_count
end

-- 字符终端显示宽度测算（ASCII 计 1 列，中文字符与全角符号计 2 列）
local function get_display_width(s)
    s = tostring(s or "")
    local w = 0
    local i = 1
    local len = #s
    while i <= len do
        local byte = s:byte(i)
        if byte < 128 then
            w = w + 1
            i = i + 1
        elseif byte >= 192 and byte < 224 then
            w = w + 2
            i = i + 2
        elseif byte >= 224 and byte < 240 then
            w = w + 2
            i = i + 3
        elseif byte >= 240 then
            w = w + 2
            i = i + 4
        else
            i = i + 1
        end
    end
    return w
end

local function pad_width(s, target_width, align_right)
    s = tostring(s or "")
    local dw = get_display_width(s)
    local pad_len = math.max(0, target_width - dw)
    if pad_len == 0 then return s end
    local spaces = string.rep(" ", pad_len)
    if align_right then
        return spaces .. s
    else
        return s .. spaces
    end
end

local function format_row(c1, c2, c3, c4, c5, c6)
    return string.format("| %s | %s | %s | %s | %s | %s |",
        pad_width(c1, 14, false),
        pad_width(c2, 24, false),
        pad_width(c3, 12, true),
        pad_width(c4, 13, true),
        pad_width(c5, 18, true),
        pad_width(c6, 12, true))
end

local sep_line = "+----------------+--------------------------+--------------+---------------+--------------------+--------------+"
local title_text = "WAF 规则命中率与基准覆盖度测试报表"
local title_pad_left = math.floor((103 - get_display_width(title_text)) / 2)
local title_line = string.format("|%s%s%s|",
    string.rep(" ", title_pad_left),
    title_text,
    string.rep(" ", 103 - title_pad_left - get_display_width(title_text)))

say("\n" .. sep_line)
say(title_line)
say(sep_line)
say(format_row("模块标识", "规则名称", "规则覆盖率", "激活/总规则", "攻击检出率 (TP)", "误报数 (FP)"))
say(sep_line)

local global_total_rules = 0
local global_activated_rules = 0

for _, mod_key in ipairs(sorted_keys) do
    local s = stats[mod_key]
    global_total_rules = global_total_rules + s.total_rules
    global_activated_rules = global_activated_rules + s.activated_rules

    local cov_str = string.format("%5.1f%%", s.rule_coverage)
    local act_str = string.format("%2d / %-2d", s.activated_rules, s.total_rules)
    local det_str = string.format("%2d/%-2d (%5.1f%%)", s.detected_attacks, s.total_attacks, s.detection_rate)
    local fp_str = string.format("%d / %d", s.fp_count, s.total_legit)

    say(format_row(mod_key, s.name, cov_str, act_str, det_str, fp_str))
end

say(sep_line)

local global_rule_cov = global_total_rules > 0 and (global_activated_rules / global_total_rules * 100) or 0
local global_det_rate = global_total_attacks > 0 and (global_detected_attacks / global_total_attacks * 100) or 0
local global_fp_rate = global_total_legit > 0 and (global_fp_legit / global_total_legit * 100) or 0

say(format_row("【全局汇总】",
    string.format("%d 个模块", #sorted_keys),
    string.format("%5.1f%%", global_rule_cov),
    string.format("%d / %d", global_activated_rules, global_total_rules),
    string.format("%d/%d (%5.1f%%)", global_detected_attacks, global_total_attacks, global_det_rate),
    string.format("%d / %d", global_fp_legit, global_total_legit)))
say(sep_line .. "\n")

-- 打印未命中的盲区规则清单 (0 命中)
local total_uncovered = global_total_rules - global_activated_rules
say(string.format(">>> 【规则盲区审计】未激活规则 (0 命中): 共 %d 条", total_uncovered))
if total_uncovered > 0 then
    if not opt_detail and not opt_uncovered then
        say("    (提示：使用 -d 或 --detail 选项可查看所有未覆盖规则及 pattern 明细)")
    else
        for _, mod_key in ipairs(sorted_keys) do
            local s = stats[mod_key]
            if #s.zero_hit_rules > 0 then
                say(string.format("\n  [%s] %s (未命中 %d 条):", mod_key, s.name, #s.zero_hit_rules))
                for _, r in ipairs(s.zero_hit_rules) do
                    local pat_preview = r.pattern:gsub("[\r\n\t]+", " ")
                    if #pat_preview > 60 then pat_preview = pat_preview:sub(1, 57) .. "..." end
                    say(string.format("    - #%-2d [%s] (置信度 %d): %s", r.index, r.name, r.confidence, pat_preview))
                end
            end
        end
    end
else
    say("    太棒了！所有规则均被基准测试用例成功激活覆盖。")
end

-- 详细模式：展示漏报样本与误报样本
if opt_detail then
    say("\n>>> 【样本命中与误报审计】")
    local has_missed = false
    for _, mod_key in ipairs(sorted_keys) do
        local s = stats[mod_key]
        if #s.missed_attacks > 0 then
            has_missed = true
            say(string.format("  [漏报告警] 模块 %s 有 %d 个攻击样本未被任何规则捕获:", mod_key, #s.missed_attacks))
            for _, m in ipairs(s.missed_attacks) do
                say(string.format("    * [%s] 说明: %s | 载荷: %s", m.pos or "uri", m.note or "", m.payload))
            end
        end
        if #s.fp_samples > 0 then
            say(string.format("  [误报告警] 模块 %s 有 %d 个合法样本误触规则:", mod_key, #s.fp_samples))
            for _, fp in ipairs(s.fp_samples) do
                local rule_names = {}
                for _, h in ipairs(fp.hits) do table.insert(rule_names, h.rule_name) end
                say(string.format("    * 样本: %s | 误触规则: %s", fp.sample.payload, table.concat(rule_names, ", ")))
            end
        end
    end
    if not has_missed and global_fp_legit == 0 then
        say("  未发现任何漏报或误报情况，基准测试用例全部准确命中！")
    end
end

-- 打印最活跃规则 (TOP 5 命中频次)
if opt_detail then
    say("\n>>> 【高频防御规则 TOP 5】")
    local all_rules = {}
    for _, mod in pairs(rule_modules) do
        for _, r in ipairs(mod.rules) do
            if r.hit_count > 0 then
                table.insert(all_rules, {
                    module = mod.name,
                    name = r.name,
                    count = r.hit_count
                })
            end
        end
    end
    table.sort(all_rules, function(a, b) return a.count > b.count end)
    for i = 1, math.min(5, #all_rules) do
        local r = all_rules[i]
        say(string.format("  %d. [%s - %s]: 累计命中 %d 次", i, r.module, r.name, r.count))
    end
end

say("")
