local _M = {}
local cjson = require "cjson.safe"
local cache = require "cache"
local logger = require "logger"
local localFile = require "localFile"
local ipUtil = require "ip"
local countMod = require "count"

-- 攻击目标与类型映射字典（对齐安全分析报告）
local TARGET_MAPPING = {
    ["SQL注入攻击"] = "数据",
    ["SQL盲注攻击探测"] = "数据",
    ["NoSQL注入"] = "数据",
    ["XML外部实体注入"] = "数据",
    ["跨站脚本攻击(XSS)"] = "应用",
    ["SSRF漏洞攻击"] = "应用",
    ["SSTI模板注入"] = "应用",
    ["Spring框架漏洞攻击"] = "应用",
    ["特殊字符URL访问"] = "应用",
    ["远程代码执行漏洞攻击"] = "服务器",
    ["命令注入"] = "服务器",
    ["反序列化漏洞攻击"] = "服务器",
    ["DNS重绑定攻击"] = "服务器",
    ["文件包含漏洞攻击"] = "文件",
    ["敏感目录访问"] = "文件",
    ["敏感文件探测"] = "文件",
    ["可疑文件访问"] = "文件",
    ["恶意文件上传"] = "文件",
    ["Unknown扫描"] = "其他",
    ["CC攻击"] = "其他",
    ["其他攻击"] = "其他"
}

local empty_array_mt = cjson.empty_array_mt
local function ensure_array(t)
    if type(t) == "table" and #t == 0 and empty_array_mt then
        setmetatable(t, empty_array_mt)
    end
    return t
end

-- 解析查询周期涵盖的日期列表与过滤小时
local function getPeriodDates(p, now_ts, baseLogsPath)
    local dates = {}
    local filter_hour = nil
    local period_label = "启动至今"

    if p == "hour" then
        table.insert(dates, os.date("%Y-%m-%d", now_ts))
        local ct = os.date("*t", now_ts)
        filter_hour = ct and ct.hour or 0
        period_label = "当前小时"
    elseif p == "day" then
        table.insert(dates, os.date("%Y-%m-%d", now_ts))
        period_label = "今日"
    elseif p == "week" then
        for i = 0, 6 do
            table.insert(dates, os.date("%Y-%m-%d", now_ts - (i * 86400)))
        end
        period_label = "7 天"
    elseif p == "month" then
        for i = 0, 29 do
            table.insert(dates, os.date("%Y-%m-%d", now_ts - (i * 86400)))
        end
        period_label = "30 天"
    else -- "process"
        local is_windows = package.config:sub(1, 1) == "\\"
        local cmd
        if is_windows then
            cmd = 'dir /b /ad "' .. baseLogsPath:gsub("/", "\\") .. '" 2>nul'
        else
            cmd = 'ls -1 "' .. baseLogsPath .. '" 2>/dev/null'
        end
        local p_handle = io.popen(cmd)
        if p_handle then
            for line in p_handle:lines() do
                local d = line:match("(%d%d%d%d%-%d%d%-%d%d)")
                if d then
                    table.insert(dates, d)
                end
            end
            p_handle:close()
        end
        if #dates == 0 then
            for i = 0, 29 do
                table.insert(dates, os.date("%Y-%m-%d", now_ts - (i * 86400)))
            end
        end
        period_label = "启动至今"
    end
    return dates, filter_hour, period_label
end

-- 扫描指定日期列表的WAF攻击日志文件，深度聚合安全态势指标与明细
local function scanPeriodLogs(dates, filter_hour, baseLogsPath)
    local log_records = {}
    local log_vuln_count = 0
    local log_cc_count = 0
    local log_type_counts = {}
    local log_target_counts = { ["数据"] = 0, ["应用"] = 0, ["服务器"] = 0, ["文件"] = 0, ["其他"] = 0 }
    local log_geo_counts = {}
    local log_vuln_hourly = {}
    local log_cc_hourly = {}
    for i = 0, 23 do
        log_vuln_hourly[i] = 0
        log_cc_hourly[i] = 0
    end
    local log_attacker_ips = {}
    local log_vuln_ips = {}
    local log_cc_ips = {}
    local log_domains = {}
    local first_vuln = nil
    local last_attack = nil

    for _, date_str in ipairs(dates) do
        local day_dir = baseLogsPath .. "/" .. date_str
        local files = localFile.getFiles(day_dir)
        if files and #files > 0 then
            for _, fn in ipairs(files) do
                if fn:match("%.log$") then
                    local fh = io.open(day_dir .. "/" .. fn, "r")
                    if fh then
                        for line in fh:lines() do
                            local item = cjson.decode(line)
                            if item and item.attack_type then
                                local req_time = item.request_time or ""
                                local h = tonumber(req_time:match("%s(%d%d):")) or 0
                                if not filter_hour or h == filter_hour then
                                    local cat_name, cat_key, target, is_cc = countMod.classifyAttack(item.attack_type, item.request_uri)
                                    local host = (item.headers and item.headers.host) or fn:gsub("%.log$", "")
                                    local ip = item.ip or "unknown"
                                    local loc = item.ip_location or ipUtil.getIPLocation(ip)
                                    local country = loc:match("^([^-]+)") or loc
                                    if country == "内网IP" then country = "局域网" end

                                    log_domains[host] = true
                                    log_type_counts[cat_name] = (log_type_counts[cat_name] or 0) + 1
                                    log_target_counts[target] = (log_target_counts[target] or 0) + 1
                                    log_geo_counts[country] = (log_geo_counts[country] or 0) + 1

                                    if is_cc then
                                        log_cc_count = log_cc_count + 1
                                        log_cc_hourly[h] = (log_cc_hourly[h] or 0) + 1
                                        log_cc_ips[ip] = (log_cc_ips[ip] or 0) + 1
                                    else
                                        log_vuln_count = log_vuln_count + 1
                                        log_vuln_hourly[h] = (log_vuln_hourly[h] or 0) + 1
                                        log_vuln_ips[ip] = (log_vuln_ips[ip] or 0) + 1
                                        if not first_vuln or (req_time ~= "" and req_time < first_vuln.time) then
                                            first_vuln = {
                                                time = req_time,
                                                ip = ip,
                                                location = loc,
                                                type = cat_name
                                            }
                                        end
                                    end
                                    log_attacker_ips[ip] = (log_attacker_ips[ip] or 0) + 1

                                    if not last_attack or (req_time ~= "" and req_time > last_attack.time) then
                                        last_attack = {
                                            time = req_time,
                                            ip = ip,
                                            location = loc,
                                            type = cat_name
                                        }
                                    end

                                    table.insert(log_records, {
                                        host = host,
                                        attack_type = item.attack_type or cat_name,
                                        type = item.attack_type or cat_name,
                                        category = cat_name,
                                        raw_type = item.attack_type or cat_name,
                                        target = target,
                                        ip = ip,
                                        location = loc,
                                        url = item.request_uri or item.url or item.uri or "/",
                                        uri = item.request_uri or item.url or item.uri or "/",
                                        request_uri = item.request_uri or item.url or item.uri or "/",
                                        payload = (item.request_data ~= "" and item.request_data) or item.data or item.post_data or "",
                                        request_data = item.request_data or "",
                                        time = req_time,
                                        method = item.http_method or "GET",
                                        raw = item
                                    })
                                end
                            end
                        end
                        fh:close()
                    end
                end
            end
        end
    end

    return {
        records = log_records,
        vuln_count = log_vuln_count,
        cc_count = log_cc_count,
        type_counts = log_type_counts,
        target_counts = log_target_counts,
        geo_counts = log_geo_counts,
        vuln_hourly = log_vuln_hourly,
        cc_hourly = log_cc_hourly,
        attacker_ips = log_attacker_ips,
        vuln_ips = log_vuln_ips,
        cc_ips = log_cc_ips,
        domains = log_domains,
        first_vuln = first_vuln,
        last_attack = last_attack
    }
end

-- 保存后需要立即生效的名单文件（IP 黑名单 / IP 白名单 / Host 白名单）
local HOT_RELOAD_FILES = { blackIp = true, whiteIp = true, whitehost = true }

-- 名单热更新：把名单文件的磁盘变更广播给所有 worker（由 init.lua 提供的全局函数，基于 nova_waf 共享字典版本号）
local function signalListsChanged()
    if notify_lists_changed then
        notify_lists_changed()
    else
        ngx.log(ngx.WARN, "notify_lists_changed is unavailable, list changes take effect only after reload")
    end
end

-- 校验规则文件名（严格白名单：仅允许字母、数字、下划线并以 .lua 结尾，阻断 ../ 与 Windows 反斜杠 \ 穿越）
local function isValidRuleFile(ruleFile)
    if type(ruleFile) ~= "string" then
        return false
    end
    return ruleFile:match("^[a-zA-Z0-9_]+%.lua$") ~= nil
end

-- 在空环境沙箱中预校验规则 Lua 源码（防 RCE 注入与语法损坏）
local function validateRuleCode(code)
    if type(code) ~= "string" or #code == 0 or #code > 262144 then
        return false, "Invalid rule content size"
    end
    local fn, err = loadstring(code, "rule_sandbox")
    if not fn then
        return false, "Lua syntax error: " .. tostring(err)
    end
    if setfenv then
        setfenv(fn, {})
    end
    local ok, res = pcall(fn)
    if not ok or type(res) ~= "table" or type(res.rules) ~= "table" then
        return false, "Rule must return a table containing a 'rules' list"
    end
    for idx, item in ipairs(res.rules) do
        if type(item) ~= "table" or type(item.pattern) ~= "string" then
            return false, "Invalid rule item at index " .. idx
        end
        local trimmed = item.pattern:match("^%s*(.-)%s*$")
        local _, re_err = ngx.re.match("", trimmed, "isjo")
        if re_err then
            return false, "Invalid regex at index " .. idx .. ": " .. tostring(re_err)
        end
    end
    return true
end

-- 内部辅助：合并一条统计计数至 stats 结构（统一操作系统 unknown/Unknown 大小写并累加）
local function mergeStatKey(stats, ip_counts, attacker_ip_counts, vuln_ip_counts, cc_ip_counts, geo_counts, key, val)
    val = tonumber(val) or 0
    if val == 0 then return end

    local sub_key = key:match("^count_(.+)$") or key:match("^hourly_(.+)$")
    if not sub_key then return end

    if sub_key == "reqCount" then
        stats.total_requests = stats.total_requests + val
        return
    end

    if sub_key == "reqDenyCount" then
        stats.blocked_requests = stats.blocked_requests + val
        return
    end

    if sub_key == "attack_vuln_total" then
        stats.vuln_requests = stats.vuln_requests + val
        return
    end

    if sub_key == "attack_cc_total" then
        stats.cc_requests = stats.cc_requests + val
        return
    end

    -- 统计操作系统分布（合并 unknown 与 Unknown，统一格式为 Unknown）
    local os_match = sub_key:match("^os_(.+)$")
    if os_match then
        if os_match:lower() == "unknown" then
            os_match = "Unknown"
        end
        stats.os_distribution[os_match] = (stats.os_distribution[os_match] or 0) + val
        return
    end

    -- 统计状态码分布
    local status_match = sub_key:match("^status_(%d+)$")
    if status_match then
        stats.status_distribution[status_match] = (stats.status_distribution[status_match] or 0) + val
        return
    end

    -- 统计域名访问分布
    local host_match = sub_key:match("^host_(.+)$")
    if host_match then
        stats.host_distribution[host_match] = (stats.host_distribution[host_match] or 0) + val
        return
    end

    -- 统计细化攻击分类名称
    local atkname_match = sub_key:match("^atkname_(.+)$") or sub_key:match("^attack_cat_(.+)$")
    if atkname_match then
        stats.attack_types_detail[atkname_match] = (stats.attack_types_detail[atkname_match] or 0) + val
        return
    end

    -- 统计攻击目标分类 (数据/应用/服务器/文件/其他)
    local target_match = sub_key:match("^target_(.+)$")
    if target_match then
        stats.attack_targets[target_match] = (stats.attack_targets[target_match] or 0) + val
        return
    end

    -- 统计攻击来源地理分布
    local geo_match = sub_key:match("^attack_geo_(.+)$")
    if geo_match then
        geo_counts[geo_match] = (geo_counts[geo_match] or 0) + val
        return
    end

    -- 统计每小时请求数
    local req_h = sub_key:match("^requests_hour_(%d+)$")
    if req_h then
        local h = tonumber(req_h)
        if h and h >= 0 and h <= 23 then
            stats.attack_trend.total[h + 1] = (stats.attack_trend.total[h + 1] or 0) + val
        end
        return
    end

    -- 统计每小时漏洞攻击数
    local vuln_h = sub_key:match("^vuln_hour_(%d+)$")
    if vuln_h then
        local h = tonumber(vuln_h)
        if h and h >= 0 and h <= 23 then
            stats.attack_trend.vuln[h + 1] = (stats.attack_trend.vuln[h + 1] or 0) + val
        end
        return
    end

    -- 统计每小时CC攻击数
    local cc_h = sub_key:match("^cc_hour_(%d+)$")
    if cc_h then
        local h = tonumber(cc_h)
        if h and h >= 0 and h <= 23 then
            stats.attack_trend.cc[h + 1] = (stats.attack_trend.cc[h + 1] or 0) + val
        end
        return
    end

    -- 攻击者IP统计
    local atkip = sub_key:match("^attacker_ip_(.+)$")
    if atkip then
        attacker_ip_counts[atkip] = (attacker_ip_counts[atkip] or 0) + val
        return
    end

    local vulnip = sub_key:match("^vuln_ip_(.+)$")
    if vulnip then
        vuln_ip_counts[vulnip] = (vuln_ip_counts[vulnip] or 0) + val
        return
    end

    local ccip = sub_key:match("^cc_ip_(.+)$")
    if ccip then
        cc_ip_counts[ccip] = (cc_ip_counts[ccip] or 0) + val
        return
    end

    -- 统计攻击类型分布 (旧格式兼容: attack_sqli, attack_xss, etc.)
    local attack_match = sub_key:match("^attack_(.+)$")
    if attack_match then
        stats.attack_types[attack_match] = (stats.attack_types[attack_match] or 0) + val
        return
    end

    -- 统计IP访问
    local ip_match = sub_key:match("^ip_(.+)$")
    if ip_match then
        ip_counts[ip_match] = (ip_counts[ip_match] or 0) + val
        return
    end
end

-- 内部辅助：整理并最终化仪表盘全部指标与类目
local function finalizeStats(stats, ip_counts, attacker_ip_counts, vuln_ip_counts, cc_ip_counts, geo_counts, log_res, period_label)
    -- 1. 访问 IP Top 20 排序
    for ip, count in pairs(ip_counts) do
        table.insert(stats.top_ips, { ip = ip, count = count })
    end
    table.sort(stats.top_ips, function(a, b) return a.count > b.count end)
    if #stats.top_ips > 20 then
        local top20 = {}
        for i = 1, 20 do
            top20[i] = stats.top_ips[i]
        end
        stats.top_ips = top20
    end
    ensure_array(stats.top_ips)

    -- 2. 合并日志分析得到的高精度数据
    if log_res then
        if log_res.vuln_count > 0 or log_res.cc_count > 0 then
            stats.vuln_requests = math.max(stats.vuln_requests, log_res.vuln_count)
            stats.cc_requests = math.max(stats.cc_requests, log_res.cc_count)

            for cat, cnt in pairs(log_res.type_counts) do
                stats.attack_types_detail[cat] = math.max(stats.attack_types_detail[cat] or 0, cnt)
            end

            for tgt, cnt in pairs(log_res.target_counts) do
                stats.attack_targets[tgt] = math.max(stats.attack_targets[tgt] or 0, cnt)
            end

            for geo, cnt in pairs(log_res.geo_counts) do
                geo_counts[geo] = math.max(geo_counts[geo] or 0, cnt)
            end

            for h = 0, 23 do
                if (stats.attack_trend.vuln[h + 1] or 0) == 0 and (log_res.vuln_hourly[h] or 0) > 0 then
                    stats.attack_trend.vuln[h + 1] = log_res.vuln_hourly[h]
                end
                if (stats.attack_trend.cc[h + 1] or 0) == 0 and (log_res.cc_hourly[h] or 0) > 0 then
                    stats.attack_trend.cc[h + 1] = log_res.cc_hourly[h]
                end
            end

            for ip, cnt in pairs(log_res.attacker_ips) do
                attacker_ip_counts[ip] = math.max(attacker_ip_counts[ip] or 0, cnt)
            end
            for ip, cnt in pairs(log_res.vuln_ips) do
                vuln_ip_counts[ip] = math.max(vuln_ip_counts[ip] or 0, cnt)
            end
            for ip, cnt in pairs(log_res.cc_ips) do
                cc_ip_counts[ip] = math.max(cc_ip_counts[ip] or 0, cnt)
            end
        end
    end

    -- 3. 补全攻击数与拦截率
    if stats.vuln_requests == 0 and stats.cc_requests == 0 and stats.blocked_requests > 0 then
        local cc_attacks = stats.attack_types["cc"] or 0
        stats.cc_requests = cc_attacks
        stats.vuln_requests = math.max(0, stats.blocked_requests - cc_attacks)
    end

    local total_detected_attacks = stats.vuln_requests + stats.cc_requests
    if total_detected_attacks == 0 then
        total_detected_attacks = stats.blocked_requests
    end

    if stats.blocked_requests < total_detected_attacks then
        stats.blocked_requests = total_detected_attacks
    end
    if stats.total_requests < stats.blocked_requests then
        stats.total_requests = stats.blocked_requests
    end

    if stats.total_requests > 0 then
        stats.block_rate = string.format("%.2f%%", (stats.blocked_requests / stats.total_requests) * 100)
    else
        stats.block_rate = "0%"
    end

    -- 4. 汇总总攻击时序曲线
    for i = 1, 24 do
        local sum_h = (stats.attack_trend.vuln[i] or 0) + (stats.attack_trend.cc[i] or 0)
        if (stats.attack_trend.total[i] or 0) < sum_h then
            stats.attack_trend.total[i] = sum_h
        end
    end

    -- 5. 统计攻击者去重 IP 数量及类型数
    local all_ip_cnt, v_ip_cnt, c_ip_cnt = 0, 0, 0
    for _ in pairs(attacker_ip_counts) do all_ip_cnt = all_ip_cnt + 1 end
    for _ in pairs(vuln_ip_counts) do v_ip_cnt = v_ip_cnt + 1 end
    for _ in pairs(cc_ip_counts) do c_ip_cnt = c_ip_cnt + 1 end
    if all_ip_cnt == 0 then
        for ip, cnt in pairs(vuln_ip_counts) do
            attacker_ip_counts[ip] = (attacker_ip_counts[ip] or 0) + cnt
        end
        for ip, cnt in pairs(cc_ip_counts) do
            attacker_ip_counts[ip] = (attacker_ip_counts[ip] or 0) + cnt
        end
        all_ip_cnt = 0
        for _ in pairs(attacker_ip_counts) do all_ip_cnt = all_ip_cnt + 1 end
    end
    stats.attack_ips_count = all_ip_cnt
    stats.attacker_ips_count = all_ip_cnt
    stats.vuln_ips_count = v_ip_cnt
    stats.cc_ips_count = c_ip_cnt

    local at_cnt = 0
    for _ in pairs(stats.attack_types_detail) do at_cnt = at_cnt + 1 end
    stats.attack_types_count = at_cnt

    -- 6. 域名数量统计
    local domain_cnt = 0
    for _ in pairs(stats.host_distribution) do domain_cnt = domain_cnt + 1 end
    if domain_cnt == 0 and log_res and log_res.domains then
        for _ in pairs(log_res.domains) do domain_cnt = domain_cnt + 1 end
    end
    stats.domain_count = domain_cnt > 0 and domain_cnt or 1

    -- 7. 黑名单查询集合
    local black_set = {}
    local bl = _M.getBlackList()
    for _, bip in ipairs(bl) do black_set[bip] = true end

    -- 8. 恶意 IP 列表生成
    local function buildIpRank(map, total_cnt, default_type)
        local list = {}
        for ip, count in pairs(map) do
            local pct = total_cnt > 0 and string.format("%.3f%%", (count / total_cnt) * 100) or "0%"
            local loc = ipUtil.getIPLocation(ip)
            local ip_t = default_type
            if not ip_t then
                if vuln_ip_counts[ip] and cc_ip_counts[ip] then
                    ip_t = "混合攻击"
                elseif cc_ip_counts[ip] then
                    ip_t = "CC攻击"
                else
                    ip_t = "漏洞攻击"
                end
            end
            table.insert(list, {
                ip = ip,
                count = count,
                location = loc,
                percent = pct,
                type = ip_t,
                is_blocked = (black_set[ip] == true)
            })
        end
        table.sort(list, function(a, b) return a.count > b.count end)
        for idx, item in ipairs(list) do
            item.rank = idx
        end
        return ensure_array(list)
    end

    stats.malicious_ips = {
        all = buildIpRank(attacker_ip_counts, total_detected_attacks, nil),
        vuln = buildIpRank(vuln_ip_counts, stats.vuln_requests, "漏洞攻击"),
        cc = buildIpRank(cc_ip_counts, stats.cc_requests, "CC攻击")
    }

    -- 9. 攻击类型排行榜
    stats.attack_types_list = {}
    for name, val in pairs(stats.attack_types_detail) do
        local pct = total_detected_attacks > 0 and string.format("%.2f%%", (val / total_detected_attacks) * 100) or "0%"
        table.insert(stats.attack_types_list, {
            name = name,
            value = val,
            percent = pct,
            target = TARGET_MAPPING[name] or "其他"
        })
    end
    table.sort(stats.attack_types_list, function(a, b) return a.value > b.value end)
    ensure_array(stats.attack_types_list)

    -- 10. 攻击源地理分布列表
    stats.attack_geo = {}
    for name, val in pairs(geo_counts) do
        local pct = total_detected_attacks > 0 and string.format("%.2f%%", (val / total_detected_attacks) * 100) or "0%"
        table.insert(stats.attack_geo, {
            name = name,
            value = val,
            percent = pct
        })
    end
    table.sort(stats.attack_geo, function(a, b) return a.value > b.value end)
    ensure_array(stats.attack_geo)

    -- 11. 雷达图数据与指标组装
    local max_target_val = 10
    for _, v in pairs(stats.attack_targets) do
        if v > max_target_val then max_target_val = v end
    end
    stats.attack_targets_radar = {
        labels = ensure_array({ "数据", "其他", "应用", "服务器", "文件" }),
        values = ensure_array({
            stats.attack_targets["数据"] or 0,
            stats.attack_targets["其他"] or 0,
            stats.attack_targets["应用"] or 0,
            stats.attack_targets["服务器"] or 0,
            stats.attack_targets["文件"] or 0
        }),
        max = max_target_val
    }

    -- 12. 提取峰值时段与最高频攻击源
    local top_vuln_ip, top_vuln_count, top_vuln_loc, top_vuln_pct = "-", 0, "-", "0%"
    if #stats.malicious_ips.vuln > 0 then
        local topItem = stats.malicious_ips.vuln[1]
        top_vuln_ip = topItem.ip
        top_vuln_count = topItem.count
        top_vuln_loc = topItem.location
        top_vuln_pct = topItem.percent
    end

    local peak_v_h, peak_v_cnt = 0, 0
    for h = 0, 23 do
        local v = stats.attack_trend.vuln[h + 1] or 0
        if v > peak_v_cnt then
            peak_v_cnt = v
            peak_v_h = h
        end
    end

    local peak_c_h, peak_c_cnt = 0, 0
    for h = 0, 23 do
        local c = stats.attack_trend.cc[h + 1] or 0
        if c > peak_c_cnt then
            peak_c_cnt = c
            peak_c_h = h
        end
    end

    -- 13. 高危攻击明细记录
    if log_res and log_res.records then
        table.sort(log_res.records, function(a, b) return (a.time or "") > (b.time or "") end)
        for i = 1, math.min(#log_res.records, 100) do
            local r = log_res.records[i]
            r.id = i
            r.is_blocked = (black_set[r.ip] == true)
            table.insert(stats.recent_attacks, r)
        end
    end
    ensure_array(stats.recent_attacks)

    ensure_array(stats.attack_trend.hours)
    ensure_array(stats.attack_trend.vuln)
    ensure_array(stats.attack_trend.cc)
    ensure_array(stats.attack_trend.total)

    -- 14. 态势简报 (时间序列)
    stats.security_summary = {
        domain_count = stats.domain_count,
        time_period = period_label,
        total_attacks = stats.blocked_requests,
        last_attack_time = (log_res and log_res.last_attack and log_res.last_attack.time) or "-",
        duration = "实时持续监控中",
        vuln_ip_count = stats.vuln_ips_count,
        vuln_attack_count = stats.vuln_requests,
        first_vuln_time = (log_res and log_res.first_vuln and log_res.first_vuln.time) or "-",
        first_vuln_ip = (log_res and log_res.first_vuln and log_res.first_vuln.ip) or "-",
        first_vuln_location = (log_res and log_res.first_vuln and log_res.first_vuln.location) or "-",
        first_vuln_type = (log_res and log_res.first_vuln and log_res.first_vuln.type) or "-",
        top_vuln_ip = top_vuln_ip,
        top_vuln_location = top_vuln_loc,
        top_vuln_count = top_vuln_count,
        top_vuln_percent = top_vuln_pct,
        peak_vuln_hour = peak_v_cnt > 0 and string.format("%02d点", peak_v_h) or "-",
        peak_vuln_count = peak_v_cnt,
        cc_ip_count = stats.cc_ips_count,
        cc_attack_count = stats.cc_requests,
        peak_cc_hour = peak_c_cnt > 0 and string.format("%02d点", peak_c_h) or "-",
        peak_cc_count = peak_cc_cnt
    }

    return stats
end

-- 获取统计数据（默认：今日；支持快捷筛选项：hour / day / week / month / process）
function _M.getStats(period)
    local countCache = require("cache"):new("nova_waf_count")
    local p = (period or "day"):lower()
    if p == "" or p == "today" then
        p = "day"
    elseif p == "all" or p == "total" or p == "process" then
        p = "process"
    elseif p == "7d" then
        p = "week"
    elseif p == "30d" then
        p = "month"
    end

    local base_path = (WAF_CONFIG and WAF_CONFIG["log_path"]) or (CURRENT_PATH .. "../logs/waf")
    local now_ts = ngx.time()
    local dates_to_scan, filter_hour, period_label = getPeriodDates(p, now_ts, base_path)

    local stats = {
        total_requests = 0,
        blocked_requests = 0,
        vuln_requests = 0,
        cc_requests = 0,
        blocked_ips = (BLACK_IPS and #BLACK_IPS) or 0,
        attacker_ips_count = 0,
        vuln_ips_count = 0,
        cc_ips_count = 0,
        attack_types_count = 0,
        domain_count = 0,
        block_rate = "0%",
        os_distribution = {},
        status_distribution = {},
        host_distribution = {},
        attack_types = {},          -- key -> count
        attack_types_detail = {},   -- name -> count
        attack_types_list = ensure_array({}),     -- array of { name, value, percent, target }
        attack_targets = {
            ["数据"] = 0,
            ["应用"] = 0,
            ["服务器"] = 0,
            ["文件"] = 0,
            ["其他"] = 0
        },
        attack_trend = {
            hours = ensure_array({}),
            vuln = ensure_array({}),
            cc = ensure_array({}),
            total = ensure_array({})
        },
        attack_geo = ensure_array({}),            -- array of { name, value, percent }
        top_ips = ensure_array({}),               -- access IP top 20
        malicious_ips = {
            all = ensure_array({}),
            vuln = ensure_array({}),
            cc = ensure_array({})
        },
        security_summary = {},
        recent_attacks = ensure_array({}),
        period = p,
        report_time = os.date("%Y-%m-%d %H:%M:%S", now_ts)
    }

    for i = 0, 23 do
        table.insert(stats.attack_trend.hours, string.format("%02d:00", i))
        stats.attack_trend.vuln[i + 1] = 0
        stats.attack_trend.cc[i + 1] = 0
        stats.attack_trend.total[i + 1] = 0
    end

    local ip_counts = {}
    local attacker_ip_counts = {}
    local vuln_ip_counts = {}
    local cc_ip_counts = {}
    local geo_counts = {}

    -- 1. 当前小时统计
    if p == "hour" then
        countCache:getAllPrefixKeys("hourly_", function(key)
            local val = tonumber(countCache:cacheGet(key)) or 0
            mergeStatKey(stats, ip_counts, attacker_ip_counts, vuln_ip_counts, cc_ip_counts, geo_counts, key, val)
        end)
        local direct_req = tonumber(countCache:cacheGet("hourly_reqCount")) or 0
        if stats.total_requests < direct_req then stats.total_requests = direct_req end
        local direct_deny = tonumber(countCache:cacheGet("hourly_reqDenyCount")) or 0
        if stats.blocked_requests < direct_deny then stats.blocked_requests = direct_deny end

        local log_res = scanPeriodLogs(dates_to_scan, filter_hour, base_path)
        return finalizeStats(stats, ip_counts, attacker_ip_counts, vuln_ip_counts, cc_ip_counts, geo_counts, log_res, period_label)
    end

    -- 2. 进程启动以来的总计（默认项，永不按小时清空）
    if p == "process" then
        countCache:getAllPrefixKeys("count_", function(key)
            local val = tonumber(countCache:cacheGet(key)) or 0
            mergeStatKey(stats, ip_counts, attacker_ip_counts, vuln_ip_counts, cc_ip_counts, geo_counts, key, val)
        end)
        local direct_req = tonumber(countCache:cacheGet("count_reqCount")) or 0
        if stats.total_requests < direct_req then stats.total_requests = direct_req end
        local direct_deny = tonumber(countCache:cacheGet("count_reqDenyCount")) or 0
        if stats.blocked_requests < direct_deny then stats.blocked_requests = direct_deny end

        local log_res = scanPeriodLogs(dates_to_scan, nil, base_path)
        return finalizeStats(stats, ip_counts, attacker_ip_counts, vuln_ip_counts, cc_ip_counts, geo_counts, log_res, period_label)
    end

    -- 3. 按日/周/月聚合（读取归档磁盘 JSON + 内存中当前小时数据）
    local num_days = (p == "week" and 7) or (p == "month" and 30) or 1
    local count_dir = base_path .. "/count/"

    for i = 0, num_days - 1 do
        local date_str = os.date("%Y-%m-%d", now_ts - (i * 86400))
        local day_dir = count_dir .. date_str
        for h = 0, 23 do
            local fn = string.format("%s/%02d.json", day_dir, h)
            local f = io.open(fn, "r")
            if not f then
                fn = string.format("%s/%d.json", day_dir, h)
                f = io.open(fn, "r")
            end
            if f then
                local content = f:read("*a")
                f:close()
                if content and content ~= "" then
                    for block in content:gmatch("%b{}") do
                        local obj = cjson.decode(block)
                        if type(obj) == "table" then
                            for k, v in pairs(obj) do
                                mergeStatKey(stats, ip_counts, attacker_ip_counts, vuln_ip_counts, cc_ip_counts, geo_counts, k, v)
                            end
                        end
                    end
                end
            end
        end
    end

    -- 加上当前小时内存中未落盘的动态计数
    countCache:getAllPrefixKeys("hourly_", function(key)
        local val = tonumber(countCache:cacheGet(key)) or 0
        mergeStatKey(stats, ip_counts, attacker_ip_counts, vuln_ip_counts, cc_ip_counts, geo_counts, key, val)
    end)
    local direct_req = tonumber(countCache:cacheGet("hourly_reqCount")) or 0
    if stats.total_requests < direct_req then stats.total_requests = direct_req end
    local direct_deny = tonumber(countCache:cacheGet("hourly_reqDenyCount")) or 0
    if stats.blocked_requests < direct_deny then stats.blocked_requests = direct_deny end

    local log_res = scanPeriodLogs(dates_to_scan, nil, base_path)
    return finalizeStats(stats, ip_counts, attacker_ip_counts, vuln_ip_counts, cc_ip_counts, geo_counts, log_res, period_label)
end

-- 获取攻击类型分布（使用已定义的 nova_waf_count 共享内存字典）
function _M.getAttackDistribution()
    local countCache = require("cache"):new("nova_waf_count")
    local distribution = {
        sqli  = tonumber(countCache:cacheGet("count_attack_sqli")) or 0,
        xss   = tonumber(countCache:cacheGet("count_attack_xss")) or 0,
        cc    = tonumber(countCache:cacheGet("count_attack_cc")) or 0,
        cmd   = tonumber(countCache:cacheGet("count_attack_cmd")) or 0,
        other = tonumber(countCache:cacheGet("count_attack_other")) or 0
    }
    return distribution
end

-- 获取请求趋势数据（使用已定义的 nova_waf_count 共享内存字典）
function _M.getRequestTrend()
    local countCache = require("cache"):new("nova_waf_count")
    local trend = {}
    for i = 0, 23 do
        local key = string.format("count_requests_hour_%d", i)
        trend[i + 1] = tonumber(countCache:cacheGet(key)) or 0
    end
    return trend
end

-- 获取IP黑名单
function _M.getBlackList()
    local blacklist = {}
    local file = io.open(CURRENT_PATH .. "conf.d/blackIp", "r")
    if file then
        for line in file:lines() do
            line = line:gsub("[\r\n]+", "")
            if line ~= "" then
                table.insert(blacklist, line)
            end
        end
        file:close()
    end
    return blacklist
end

-- 重载WAF配置
function _M.reloadConfig()
    local success = true
    local message = "配置重载成功"

    local ok, err = pcall(function()
        -- 清理规则模块缓存（同时清理 short name 与 rules. 前缀名，确保 load_rules 读取最新磁盘内容）
        local rulesPath = CURRENT_PATH .. "rules/"
        local files = localFile.getFiles(rulesPath)
        for _, file in ipairs(files) do
            local rule = file:match("^([%w_]+)%.lua$")
            if rule then
                package.loaded[rule] = nil
                package.loaded["rules." .. rule] = nil
            end
        end

        -- 重新执行当前 Worker 的配置与规则加载函数（不调用 flush_all 以保留已封禁攻击者状态）
        if load_config then load_config() end
        if load_ips then load_ips() end
        if load_hosts then load_hosts() end
        if load_rules then load_rules() end
        if load_debug then load_debug() end

        -- 尝试通知 Nginx Master 重载（同步所有 Worker 进程）
        local prefix = ngx.config.prefix()
        local is_windows = package.config:sub(1, 1) == "\\"
        local reload_cmd
        if is_windows and prefix then
            local win_prefix = prefix:gsub("/", "\\"):gsub("\\+$", "")
            reload_cmd = 'cd /d "' .. win_prefix .. '" && nginx -s reload'
        else
            reload_cmd = "nginx -s reload"
        end
        local reload_res = os.execute(reload_cmd)
        if not (reload_res == true or reload_res == 0) then
            ngx.log(ngx.WARN, "nginx -s reload returned non-zero (in-process config reloaded): ", tostring(reload_res))
        end
    end)

    if not ok then
        success = false
        message = "配置重载失败: " .. (err or "未知错误")
        ngx.log(ngx.ERR, "Failed to reload WAF config: ", err)
    end

    return success, message
end

-- 添加IP到黑名单
function _M.addToBlackList(ip)
    if type(ip) ~= "string" or ip:find("[\r\n]") then
        return false
    end
    local file = io.open(CURRENT_PATH .. "conf.d/blackIp", "a")
    if file then
        file:write(ip .. "\n")
        file:close()
        signalListsChanged()
        return true
    end
    return false
end

-- 从黑名单移除IP
function _M.removeFromBlackList(ip)
    local blacklist = _M.getBlackList()
    local file = io.open(CURRENT_PATH .. "conf.d/blackIp", "w")
    if file then
        for _, v in ipairs(blacklist) do
            if v ~= ip then
                file:write(v .. "\n")
            end
        end
        file:close()
        signalListsChanged()
        return true
    end
    return false
end

-- 获取IP白名单
function _M.getWhiteList()
    local whitelist = {}
    local file = io.open(CURRENT_PATH .. "conf.d/whiteIp", "r")
    if file then
        for line in file:lines() do
            line = line:gsub("[\r\n]+", "")
            if line ~= "" then
                table.insert(whitelist, line)
            end
        end
        file:close()
    end
    return whitelist
end

-- 添加IP到白名单
function _M.addToWhiteList(ip)
    if type(ip) ~= "string" or ip:find("[\r\n]") then
        return false
    end
    local file = io.open(CURRENT_PATH .. "conf.d/whiteIp", "a")
    if file then
        file:write(ip .. "\n")
        file:close()
        signalListsChanged()
        return true
    end
    return false
end

-- 从白名单移除IP
function _M.removeFromWhiteList(ip)
    local whitelist = _M.getWhiteList()
    local file = io.open(CURRENT_PATH .. "conf.d/whiteIp", "w")
    if file then
        for _, v in ipairs(whitelist) do
            if v ~= ip then
                file:write(v .. "\n")
            end
        end
        file:close()
        signalListsChanged()
        return true
    end
    return false
end

-- 获取规则配置
function _M.getRules()
    local rules = {}
    local rulesPath = CURRENT_PATH .. "rules/"
    local files = localFile.getFiles(rulesPath)

    for _, file in ipairs(files) do
        if isValidRuleFile(file) then
            local ruleName = file:match("^([a-zA-Z0-9_]+)%.lua$")
            if ruleName then
                -- 安全地加载规则模块
                local ok, ruleModule = pcall(require, "rules." .. ruleName)
                if not ok or type(ruleModule) ~= "table" then
                    ok, ruleModule = pcall(require, ruleName)
                end
                if ok and type(ruleModule) == "table" then
                    local configKey = "exp_" .. ruleName
                    local enabled = WAF_CONFIG and WAF_CONFIG[configKey] ~= "off"

                    rules[ruleName] = {
                        file = file,
                        name = ruleModule.name or ruleName,
                        desc = ruleModule.desc or "",
                        level = ruleModule.level or "medium",
                        position = ruleModule.position or "uri,body",
                        enabled = enabled
                    }
                else
                    ngx.log(ngx.WARN, "Failed to load rule module: ", ruleName)
                end
            end
        end
    end

    return rules
end

-- 获取单个规则文件内容
function _M.getRuleContent(ruleFile)
    if not isValidRuleFile(ruleFile) then
        ngx.log(ngx.WARN, "Rejected invalid rule file name: ", tostring(ruleFile))
        return nil
    end
    local file = io.open(CURRENT_PATH .. "rules/" .. ruleFile, "r")
    if file then
        local content = file:read("*a")
        file:close()
        return content
    end
    return nil
end

-- 更新规则配置（含文件名白名单校验与空环境沙箱语法/结构预检）
function _M.updateRule(ruleFile, ruleContent)
    if not isValidRuleFile(ruleFile) then
        ngx.log(ngx.WARN, "Rejected invalid rule file name on update: ", tostring(ruleFile))
        return false
    end
    local valid, err = validateRuleCode(ruleContent)
    if not valid then
        ngx.log(ngx.ERR, "Rejected unsafe or invalid rule content for ", ruleFile, ": ", err)
        return false
    end
    local file = io.open(CURRENT_PATH .. "rules/" .. ruleFile, "w")
    if file then
        file:write(ruleContent)
        file:close()
        return true
    end
    return false
end

-- 读取配置文件
function _M.readFile(fileName)
    -- 只允许读取conf.d目录下的特定文件
    local allowedFiles = {
        blackIp = true,
        whiteIp = true,
        whitehost = true,
        ["waf.conf"] = true
    }

    if not allowedFiles[fileName] then
        return nil
    end

    local file = io.open(CURRENT_PATH .. "conf.d/" .. fileName, "r")
    if file then
        local content = file:read("*a")
        file:close()
        return content
    end
    return nil
end

-- 更新规则状态
function _M.switchRule(ruleFile, enabled)
    if not isValidRuleFile(ruleFile) then
        ngx.log(ngx.ERR, "Invalid rule file name: ", tostring(ruleFile))
        return false
    end
    local ruleName = ruleFile:match("^([a-zA-Z0-9_]+)%.lua$")
    if not ruleName then
        ngx.log(ngx.ERR, "Invalid rule file name: ", ruleFile)
        return false
    end

    ngx.log(ngx.INFO, "Switching rule: ", ruleName, " to ", enabled and "on" or "off")

    -- 读取waf.conf文件
    local wafConfPath = CURRENT_PATH .. "conf.d/waf.conf"
    local file = io.open(wafConfPath, "r")
    if not file then
        ngx.log(ngx.ERR, "Failed to open waf.conf for reading")
        return false
    end

    local content = file:read("*a")
    file:close()

    -- 构建查找的规则配置项
    local ruleKey = "exp_" .. ruleName
    local newValue = enabled and "\"on\"" or "\"off\""

    -- 替换规则状态
    local pattern = "(" .. ruleKey .. ")%s*=%s*[\"']?[^\"'\r\n]*[\"']?"
    local count = 0
    local newContent = string.gsub(content, pattern, function()
        count = count + 1
        return ruleKey .. " = " .. newValue
    end)

    if count == 0 then
        ngx.log(ngx.WARN, "Config key not found: ", ruleKey, ", appending to file")
        newContent = content .. "\n" .. ruleKey .. " = " .. newValue .. "\n"
    else
        ngx.log(ngx.INFO, "Updated ", count, " occurrence(s) of ", ruleKey)
    end

    -- 写回文件
    file = io.open(wafConfPath, "w")
    if not file then
        ngx.log(ngx.ERR, "Failed to open waf.conf for writing")
        return false
    end

    file:write(newContent)
    file:close()

    if WAF_CONFIG then
        WAF_CONFIG[ruleKey] = enabled and "on" or "off"
    end

    return true
end

-- 保存配置文件
function _M.saveFile(fileName, content)
    -- 只允许保存conf.d目录下的特定文件
    local allowedFiles = {
        blackIp = true,
        whiteIp = true,
        whitehost = true,
        ["waf.conf"] = true
    }

    if not allowedFiles[fileName] or type(content) ~= "string" then
        return false
    end

    local file = io.open(CURRENT_PATH .. "conf.d/" .. fileName, "w")
    if file then
        file:write(content)
        file:close()
        -- IP 黑白名单 / Host 白名单保存后广播热更新，所有 worker 下一次请求即生效；waf.conf 仍需重载
        if HOT_RELOAD_FILES[fileName] then
            signalListsChanged()
        end
        return true
    end
    return false
end

-- 获取系统日志（校验日期格式、复用 sanitizeHost 清洗域名，并倒序返回最新 limit 条记录）
function _M.getLogs(host, date, limit)
    if type(date) ~= "string" or not date:match("^%d%d%d%d%-%d%d%-%d%d$") then
        ngx.log(ngx.WARN, "Invalid log query date: ", tostring(date))
        return {}
    end
    limit = tonumber(limit) or 100
    if limit < 1 then limit = 1 elseif limit > 1000 then limit = 1000 end

    local ipUtil = require("ip")
    local countMod = require("count")
    local baseLogsPath = (WAF_CONFIG and WAF_CONFIG["log_path"]) or (CURRENT_PATH .. "../logs/waf")
    local files_to_read = {}

    if not host or host == "" or host == "all" then
        local dayDir = baseLogsPath .. "/" .. date
        local files = localFile.getFiles(dayDir)
        if files and #files > 0 then
            for _, fn in ipairs(files) do
                if fn:match("%.log$") then
                    table.insert(files_to_read, dayDir .. "/" .. fn)
                end
            end
        end
    else
        local safeHost = logger.sanitizeHost(host)
        table.insert(files_to_read, baseLogsPath .. "/" .. date .. "/" .. safeHost .. ".log")
    end

    local all_records = {}
    for _, logFilePath in ipairs(files_to_read) do
        local file = io.open(logFilePath, "r")
        if file then
            for line in file:lines() do
                if line ~= "" then
                    local ok, logData = pcall(cjson.decode, line)
                    if ok and logData then
                        if logData.ip then
                            logData.ip_location = ipUtil.getIPLocation(logData.ip)
                        end
                        if countMod and countMod.classifyAttack and logData.attack_type then
                            local cat_name = countMod.classifyAttack(logData.attack_type, logData.request_uri)
                            logData.category_name = cat_name
                        end
                        table.insert(all_records, logData)
                    end
                end
            end
            file:close()
        end
    end

    table.sort(all_records, function(a, b) return (a.request_time or "") > (b.request_time or "") end)

    local content = {}
    local count = math.min(#all_records, limit)
    for i = 1, count do
        table.insert(content, cjson.encode(all_records[i]))
    end
    return content
end

return _M
