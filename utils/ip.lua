-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local _M = {}

local pairs = pairs
local ipairs = ipairs
local tonumber = tonumber
local find = string.find
local sub = string.sub
local ngxmatch = ngx.re.match

local insert = table.insert

-- MaxMind GeoIP2 数据库实例
local geo = nil
local geo_init_tried = false
-- 去除字符串两端空白字符的 trim 函数
local function trim(s)
    if type(s) ~= "string" then return "" end
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

-- 提取首个非空 IP（兼容 table 类型的同名多 Header 与逗号分隔链）
local function extractFirstIP(raw)
    if type(raw) == "table" then
        raw = raw[1]
    end
    if type(raw) ~= "string" or #raw == 0 then
        return nil
    end
    local idx = find(raw, ",", 1, true)
    if idx and idx > 0 then
        raw = sub(raw, 1, idx - 1)
    end
    raw = trim(raw)
    if #raw > 0 then
        return raw
    end
    return nil
end

function _M.getClientIP()
    local remote_addr = ngx.var.remote_addr or "unknown"

    -- 仅当显式开启 trust_proxy 且直接来源为内网/本机受信任代理时，才解析代理转发头，防止客户端伪造 X-Forwarded-For 绕过 WAF
    if WAF_CONFIG and WAF_CONFIG["trust_proxy"] == "on" and _M.isPrivateIP(remote_addr) then
        local headers = ngx.req.get_headers()
        local forwarded = extractFirstIP(ngx.var.http_x_forwarded_for)
            or extractFirstIP(headers["X-Forwarded-For"])
            or extractFirstIP(headers["x-real-ip"])
        if forwarded then
            return forwarded
        end
    end

    return trim(remote_addr)
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
        ngx.log(ngx.WARN, "parseCidr: CIDR block too large to expand into individual IPs: ", cidr)
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
        ngx.log(ngx.WARN, "lua-resty-maxminddb not installed, IP geolocation disabled")
        return nil
    end

    local mmdb_path = CURRENT_PATH .. "conf.d/GeoLite2-Country.mmdb"
    local f = io.open(mmdb_path, "rb")
    if not f then
        ngx.log(ngx.WARN, "GeoIP2 mmdb not found, geolocation disabled: ", mmdb_path)
        return nil
    end
    f:close()

    local ok_init, init_err = pcall(function()
        if not maxminddb.initted() then
            maxminddb.init(mmdb_path)
        end
    end)
    if not ok_init then
        ngx.log(ngx.ERR, "GeoIP2 init failed (libmaxminddb FFI error), geolocation disabled: ", init_err)
        return nil
    end

    local ok_check, initted = pcall(maxminddb.initted)
    if not ok_check or not initted then
        ngx.log(ngx.WARN, "Failed to init GeoLite2-Country.mmdb")
        return nil
    end

    geo = maxminddb
    ngx.log(ngx.INFO, "GeoIP2 database loaded successfully")
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