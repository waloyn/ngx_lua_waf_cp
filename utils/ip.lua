-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local _M = {}

local pairs = pairs
local ipairs = ipairs
local tonumber = tonumber
local type = type
local find = string.find
local sub = string.sub
local insert = table.insert
local ngxmatch = ngx and ngx.re and ngx.re.match

-- MaxMind GeoIP2 数据库实例
local geo = nil
local geo_init_tried = false

-- 受信 CDN 节点 IP/CIDR 解析缓存，避免每次请求重复解析配置字符串
local cached_cdn_ips_str = nil
local cached_cdn_ips_parsed = nil

-- 主流公网 CDN 专属真实 IP 头部清单（按权威性与优先级排序）
-- 阿里 ESA 边缘节点会将真实客户端 IP 写入 Ali-CDN-Real-IP，客户端无法伪造
local CDN_PROPRIETARY_HEADERS = {
    "ali-cdn-real-ip",     -- 阿里 ESA (Edge Security Acceleration) / 阿里云 CDN / 全站加速
    "cf-connecting-ip",    -- Cloudflare
    "true-client-ip",      -- Cloudflare Enterprise / Akamai
    "eo-client-ip",        -- 腾讯云 EdgeOne / CDN
}

-- 常见通用反向代理请求头清单
local PROXY_STANDARD_HEADERS = {
    "x-real-ip",
    "x-forwarded-for",
    "x-client-ip",
    "wl-proxy-client-ip",
}

-- 去除字符串两端空白字符的 trim 函数
local function trim(s)
    if type(s) ~= "string" then return "" end
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

_M.trim = trim

-- 校验是否为合法的标准 IPv4 地址（0.0.0.0 ~ 255.255.255.255，拒绝前导0与超出范围的数值）
function _M.isValidIPv4(ip)
    if type(ip) ~= "string" or #ip < 7 or #ip > 15 then
        return false
    end
    local o1, o2, o3, o4 = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not o1 or not o2 or not o3 or not o4 then
        return false
    end
    -- 避免前导 0 带来的歧义，例如 01.02.03.04
    if (#o1 > 1 and o1:sub(1, 1) == "0") or
       (#o2 > 1 and o2:sub(1, 1) == "0") or
       (#o3 > 1 and o3:sub(1, 1) == "0") or
       (#o4 > 1 and o4:sub(1, 1) == "0") then
        return false
    end
    o1, o2, o3, o4 = tonumber(o1), tonumber(o2), tonumber(o3), tonumber(o4)
    if not o1 or not o2 or not o3 or not o4 then
        return false
    end
    if o1 > 255 or o2 > 255 or o3 > 255 or o4 > 255 then
        return false
    end
    return true
end

-- 校验是否为合法的 IPv6 地址
function _M.isValidIPv6(ip)
    if type(ip) ~= "string" or #ip < 2 or #ip > 45 then
        return false
    end
    -- 必须包含冒号
    if not find(ip, ":", 1, true) then
        return false
    end
    -- 仅允许十六进制字符和冒号（以及末尾可能的 IPv4 映射形式）
    if not ip:match("^[a-fA-F0-9:]+$") and not ip:match("^[a-fA-F0-9:]+:%d+%.%d+%.%d+%.%d+$") then
        return false
    end
    -- "::" 压缩最多只能出现一次
    local _, double_colon_count = ip:gsub("::", "")
    if double_colon_count > 1 then
        return false
    end
    return true
end

-- 校验是否为合法有效 IP (IPv4 或 IPv6)
function _M.isValidIP(ip)
    return _M.isValidIPv4(ip) or _M.isValidIPv6(ip)
end

-- 清洗并验证单个 IP 字符串（支持剥离端口号、方括号及单双引号）
function _M.cleanAndValidateIP(raw)
    if type(raw) ~= "string" or #raw == 0 then
        return nil
    end
    raw = trim(raw)
    -- 去除可能包裹的单双引号
    raw = raw:gsub('^["\'](.-)["\']$', "%1")
    raw = trim(raw)
    if #raw == 0 or raw:lower() == "unknown" then
        return nil
    end

    -- 检查 IPv6 带方括号和端口: [2001:db8::1]:8080
    local ipv6_port = raw:match("^%[([a-fA-F0-9:]+)%]:%d+$")
    if ipv6_port and _M.isValidIPv6(ipv6_port) then
        return ipv6_port
    end

    -- 检查 IPv6 方括号形式: [2001:db8::1]
    local ipv6_bracket = raw:match("^%[([a-fA-F0-9:]+)%]$")
    if ipv6_bracket and _M.isValidIPv6(ipv6_bracket) then
        return ipv6_bracket
    end

    -- 检查 IPv4 带端口: 1.2.3.4:8080
    local ipv4_port = raw:match("^(%d+%.%d+%.%d+%.%d+):%d+$")
    if ipv4_port and _M.isValidIPv4(ipv4_port) then
        return ipv4_port
    end

    -- 标准 IPv4 或 IPv6
    if _M.isValidIP(raw) then
        return raw
    end

    return nil
end

-- 提取首个合法 IP（兼容 table 类型的同名多 Header、逗号分隔链及端口去除）
function _M.extractFirstIP(raw)
    if type(raw) == "table" then
        for i = 1, #raw do
            local cand = _M.extractFirstIP(raw[i])
            if cand then
                return cand
            end
        end
        return nil
    end
    if type(raw) ~= "string" or #raw == 0 then
        return nil
    end
    -- 若包含逗号分隔链（如 X-Forwarded-For），依次寻找首个合法 IP
    if find(raw, ",", 1, true) then
        for part in raw:gmatch("([^,]+)") do
            local cand = _M.cleanAndValidateIP(part)
            if cand then
                return cand
            end
        end
        return nil
    end
    return _M.cleanAndValidateIP(raw)
end

-- 兼容本地别名
local extractFirstIP = _M.extractFirstIP

-- 安全读取 HTTP 请求头值（优先尝试 ngx.var 原生变量，其次尝试 headers table）
local function getHeaderValue(headerName, headers)
    if not headerName or headerName == "" then
        return nil
    end
    local lowerName = headerName:lower()
    -- 1. 尝试从 ngx.var 中直接读取（例如 http_ali_cdn_real_ip）
    if ngx and ngx.var then
        local varName = "http_" .. lowerName:gsub("-", "_")
        local val = ngx.var[varName]
        if val and val ~= "" then
            return val
        end
    end
    -- 2. 尝试从 headers table 中读取
    if headers and type(headers) == "table" then
        local val = headers[lowerName] or headers[headerName]
        if val and val ~= "" then
            return val
        end
    end
    return nil
end

-- 解析 IP/CIDR 列表字符串为 { ips = set, cidrs = list }
function _M.parseIpList(raw)
    if type(raw) ~= "string" or #raw == 0 then
        return nil
    end
    local ips = {}
    local cidrs = {}
    local count = 0
    for item in raw:gmatch("[^,\r\n]+") do
        item = trim(item)
        if item ~= "" and not item:find("^#") then
            if find(item, "/", 1, true) then
                local range = _M.parseCidrRange(item)
                if range then
                    insert(cidrs, range)
                    count = count + 1
                end
            elseif _M.isValidIP(item) then
                ips[item] = true
                count = count + 1
            end
        end
    end
    if count == 0 then
        return nil
    end
    return { ips = ips, cidrs = cidrs }
end

-- 判断 IP 是否在已解析的列表中
function _M.isIpInList(ip, parsedList)
    if not ip or not parsedList then
        return false
    end
    if parsedList.ips and parsedList.ips[ip] then
        return true
    end
    if parsedList.cidrs and #parsedList.cidrs > 0 then
        return _M.isIpInCidrs(ip, parsedList.cidrs)
    end
    return false
end

-- 检查 IP 是否属于配置的受信任 CDN 节点 IP/CIDR 范围（带缓存）
function _M.isIpInConfiguredCdn(ip, cdn_ips_str)
    if not ip or not cdn_ips_str or cdn_ips_str == "" then
        return false
    end
    if cached_cdn_ips_str ~= cdn_ips_str then
        cached_cdn_ips_parsed = _M.parseIpList(cdn_ips_str)
        cached_cdn_ips_str = cdn_ips_str
    end
    return _M.isIpInList(ip, cached_cdn_ips_parsed)
end

-- 获取客户端真实 IP（兼容阿里 ESA 等主流 CDN、内网反向代理以及自定义 CDN 请求头）
function _M.getClientIP(headers)
    local remote_addr = (ngx and ngx.var and ngx.var.remote_addr) or "unknown"
    remote_addr = trim(remote_addr)

    local cdn_mode = WAF_CONFIG and (WAF_CONFIG["cdn_mode"] == "on" or WAF_CONFIG["cdn_mode"] == "true")
    local trust_proxy = WAF_CONFIG and (WAF_CONFIG["trust_proxy"] == "on" or WAF_CONFIG["trust_proxy"] == "true")
    local cdn_header = WAF_CONFIG and WAF_CONFIG["cdn_header"]
    local cdn_ips_config = WAF_CONFIG and WAF_CONFIG["cdn_ips"]

    -- 未启用 CDN 模式也未启用代理信任时，保持严格防御模式，不信任任何转发头以防伪造绕过
    if not cdn_mode and not trust_proxy then
        return remote_addr
    end

    local is_private = _M.isPrivateIP(remote_addr)
    local has_cdn_ips = cdn_ips_config and trim(cdn_ips_config) ~= ""
    local is_in_cdn_ips = has_cdn_ips and _M.isIpInConfiguredCdn(remote_addr, cdn_ips_config)

    -- 若显式配置了受信任 CDN IP 段，公网直连来源必须命中该网段（内网代理不受此限制）
    if has_cdn_ips and not is_private and not is_in_cdn_ips then
        return remote_addr
    end

    -- 按需获取请求头 table
    local req_headers = headers
    if not req_headers and ngx and ngx.req and ngx.req.get_headers then
        local ok, h = pcall(ngx.req.get_headers)
        if ok and type(h) == "table" then
            req_headers = h
        end
    end

    -- 1. 优先使用用户自定义的 CDN 真实 IP 请求头（若配置）
    if cdn_header and trim(cdn_header) ~= "" then
        local val = getHeaderValue(cdn_header, req_headers)
        local real_ip = extractFirstIP(val)
        if real_ip then
            return real_ip
        end
    end

    -- 2. 匹配主流 CDN 专属真实 IP 头部（阿里 ESA 的 Ali-CDN-Real-IP、Cloudflare 的 CF-Connecting-IP 等）
    -- 阿里 ESA 节点会在边缘将真实客户端 IP 写入 Ali-CDN-Real-IP，优先级最高，避免 XFF 链伪造
    for i = 1, #CDN_PROPRIETARY_HEADERS do
        local hname = CDN_PROPRIETARY_HEADERS[i]
        local val = getHeaderValue(hname, req_headers)
        local real_ip = extractFirstIP(val)
        if real_ip then
            return real_ip
        end
    end

    -- 3. 通用代理转发头（X-Forwarded-For / X-Real-IP / X-Client-IP / WL-Proxy-Client-IP）
    -- 仅当直接来源是内网代理、命中受信 CDN 网段、或开启了 cdn_mode 时才解析通用代理头，防止普通外网攻击者伪造 XFF
    if is_private or is_in_cdn_ips or cdn_mode then
        for i = 1, #PROXY_STANDARD_HEADERS do
            local hname = PROXY_STANDARD_HEADERS[i]
            local val = getHeaderValue(hname, req_headers)
            local real_ip = extractFirstIP(val)
            if real_ip then
                return real_ip
            end
        end
    end

    return remote_addr
end

-- 是否内网IP
function _M.isPrivateIP(ip)
    if not ip then
        return false
    end

    -- Check for loopback IPs and localhost
    if ip == '127.0.0.1' or ip == '::1' or ip == 'localhost' then
        return true
    end

    -- Check for IPv4 private IP ranges
    if ngxmatch then
        local ipv4_match = ngxmatch(ip, '^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$', 'isjo')
        if ipv4_match then
            local a, b, c, d = tonumber(ipv4_match[1]), tonumber(ipv4_match[2]), tonumber(ipv4_match[3]), tonumber(ipv4_match[4])
            if a == 10 then
                return true
            elseif a == 172 and b >= 16 and b <= 31 then
                return true
            elseif a == 192 and b == 168 then
                return true
            elseif a == 100 and b >= 64 and b <= 127 then  -- Carrier-Grade NAT (CGNAT)
                return true
            elseif a == 169 and b == 254 then  -- Link-local address
                return true
            end
        end

        -- Check for IPv6 private IP ranges (unique local addresses)
        local ipv6_match = ngxmatch(ip, '^([a-fA-F0-9:]+)$', 'isjo')
        if ipv6_match then
            if ngxmatch(ip, '^fc[0-9a-fA-F]{2}::', 'isjo') or ngxmatch(ip, '^fd[0-9a-fA-F]{2}::', 'isjo') then
                return true
            end
        end
    else
        -- 兼容非 OpenResty 环境（如测试脚本或离线运行时 ngx.re.match 为空）
        local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if a and b and c and d then
            a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
            if a == 10 then
                return true
            elseif a == 172 and b >= 16 and b <= 31 then
                return true
            elseif a == 192 and b == 168 then
                return true
            elseif a == 100 and b >= 64 and b <= 127 then
                return true
            elseif a == 169 and b == 254 then
                return true
            end
        end
        if ip:match("^[a-fA-F0-9:]+$") then
            local lower_ip = ip:lower()
            if lower_ip:match("^fc[0-9a-f0-9][0-9a-f0-9]:") or lower_ip:match("^fd[0-9a-f0-9][0-9a-f0-9]:") then
                return true
            end
        end
    end

    return false
end

local bit = require("bit")

function _M.ip2number(ip)
    if type(ip) ~= "string" then
        return nil
    end
    local o1, o2, o3, o4 = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    o1, o2, o3, o4 = tonumber(o1), tonumber(o2), tonumber(o3), tonumber(o4)
    if not o1 or not o2 or not o3 or not o4 then
        return nil
    end
    if o1 > 255 or o2 > 255 or o3 > 255 or o4 > 255 then
        return nil
    end
    return 16777216 * o1 + 65536 * o2 + 256 * o3 + o4
end

function _M.number2ip(number)
    local o1 = math.floor(number / 16777216) % 256
    local o2 = math.floor(number / 65536) % 256
    local o3 = math.floor(number / 256) % 256
    local o4 = number % 256
    return string.format("%d.%d.%d.%d", o1, o2, o3, o4)
end

-- 解析 CIDR 为数值区间（O(1) 空间，支持 /0 ~ /32 任意网段，避免展开成百万级字符串导致 OOM）
function _M.parseCidrRange(cidr)
    if type(cidr) ~= "string" then
        return nil
    end
    local ip, prefix_str = cidr:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
    local prefix = tonumber(prefix_str)
    if not ip or not prefix or prefix < 0 or prefix > 32 then
        return nil
    end
    local ip_num = _M.ip2number(ip)
    if not ip_num then
        return nil
    end
    local size = 2 ^ (32 - prefix)
    local start_ip = math.floor(ip_num / size) * size
    local end_ip = start_ip + size - 1
    return {
        cidr = cidr,
        start_ip = start_ip,
        end_ip = end_ip,
        count = size
    }
end

-- 判断 IP 是否落在任一 CIDR 数值区间内
function _M.isIpInCidrs(ip, cidrRanges)
    if not ip or not cidrRanges or #cidrRanges == 0 then
        return false
    end
    local ip_num = _M.ip2number(ip)
    if not ip_num then
        return false
    end
    for i = 1, #cidrRanges do
        local r = cidrRanges[i]
        if ip_num >= r.start_ip and ip_num <= r.end_ip then
            return true
        end
    end
    return false
end

-- 兼容保留：仅对小网段（>= /24）展开单 IP 列表，防止大网段触发 OOM
function _M.parseCidr(cidr)
    local range = _M.parseCidrRange(cidr)
    if not range then
        return {}
    end
    if range.count > 256 then
        if ngx and ngx.log and ngx.WARN then
            ngx.log(ngx.WARN, "parseCidr: CIDR block too large to expand into individual IPs: ", cidr)
        end
        return {}
    end
    local ips = {}
    for i = 0, range.count - 1 do
        insert(ips, _M.number2ip(range.start_ip + i))
    end
    return ips
end

-- 初始化 GeoIP2 数据库
local function initGeoIP()
    if geo_init_tried then
        return geo
    end
    geo_init_tried = true

    local ok, maxminddb = pcall(require, "resty.maxminddb")
    if not ok then
        if ngx and ngx.log and ngx.WARN then
            ngx.log(ngx.WARN, "lua-resty-maxminddb not installed, IP geolocation disabled")
        end
        return nil
    end

    local mmdb_path = CURRENT_PATH .. "conf.d/GeoLite2-Country.mmdb"
    local f = io.open(mmdb_path, "rb")
    if not f then
        if ngx and ngx.log and ngx.WARN then
            ngx.log(ngx.WARN, "GeoIP2 mmdb not found, geolocation disabled: ", mmdb_path)
        end
        return nil
    end
    f:close()

    local ok_init, init_err = pcall(function()
        if not maxminddb.initted() then
            maxminddb.init(mmdb_path)
        end
    end)
    if not ok_init then
        if ngx and ngx.log and ngx.ERR then
            ngx.log(ngx.ERR, "GeoIP2 init failed (libmaxminddb FFI error), geolocation disabled: ", init_err)
        end
        return nil
    end

    local ok_check, initted = pcall(maxminddb.initted)
    if not ok_check or not initted then
        if ngx and ngx.log and ngx.WARN then
            ngx.log(ngx.WARN, "Failed to init GeoLite2-Country.mmdb")
        end
        return nil
    end

    geo = maxminddb
    if ngx and ngx.log and ngx.INFO then
        ngx.log(ngx.INFO, "GeoIP2 database loaded successfully")
    end
    return geo
end

-- 根据 IP 获取国家/地区信息
function _M.getIPLocation(ip)
    if not ip or ip == "" or ip == "unknown" then
        return "未知"
    end
    
    -- 内网 IP 直接返回
    if _M.isPrivateIP(ip) then
        return "内网IP"
    end
    
    local db = initGeoIP()
    if not db then
        return "未知"
    end
    
    -- 使用 maxminddb.lookup(ip) 查询
    local ok, res, err = pcall(function()
        return db.lookup(ip)
    end)
    
    if not ok or not res then
        return "未知"
    end

    -- 尝试获取中文国家名，如果没有则使用英文
    local country_name = nil
    if res.country and res.country.names then
        country_name = res.country.names["zh-CN"] or res.country.names["en"]
    end
    -- 尝试获取中文地区名，如果没有则使用英文
    local region_name = nil
    if res.city and res.city.names then
        region_name = res.city.names["zh-CN"] or res.city.names["en"]
    end    
    if region_name then
        if country_name then
            country_name = country_name .. "-" .. region_name
        else
            country_name = region_name
        end
    end
    return country_name or "未知"
end

return _M
