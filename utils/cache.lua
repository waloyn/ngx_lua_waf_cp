local _M = {}
_M.__index = _M

-- 构造函数
function _M:new(cacheName)
    if not cacheName then
        cacheName = "nova_waf"
    end
    local t = {
        cache = ngx.shared[cacheName],
    }
    
    setmetatable(t, self)
    return t
end

-- 设置键值对，并指定过期时间（可选）
function _M:cacheSet(key, value, expireTime)
    local ok, err = self.cache:set(key, value, expireTime)
    if not ok then
        ngx.log(ngx.ERR, "failed to set key: " .. key .. " ", err)
    end
    return ok, err
end

-- 增加键的值（滑动窗口：每次 incr 后显式刷新 TTL）
-- 注：dict:incr 的 init_ttl 仅在 key 不存在时生效，已存在时不刷 TTL。
-- 此处通过 expire 在 incr 后重置 TTL，恢复 cacheSet(... ttl) 的滑窗语义。
function _M:cacheIncr(key, increment, expireTime)
    local inc = increment or 1
    local value, err = self.cache:incr(key, inc, 0, expireTime)
    if not value then
        ngx.log(ngx.ERR, "failed to incr key: " .. key .. " ", err)
        return value, err
    end
    if expireTime then
        local ok, exp_err = self.cache:expire(key, expireTime)
        if not ok and exp_err and exp_err ~= "not found" then
            ngx.log(ngx.WARN, "failed to refresh TTL for key: " .. key .. " ", exp_err)
        end
    end
    return value, err
end

-- 获取指定键的值
function _M:cacheGet(key)
    local value, err = self.cache:get(key)
    if err then
        ngx.log(ngx.WARN, "failed to get key: " .. key .. " ", err)
    end
    return value, err
end

-- 获取所有指定前缀的key
function _M:getAllPrefixKeys(prefix, callback)
    local keys = self.cache:get_keys(0)
    local keys_processed = 0

    for _, k in ipairs(keys) do
        if k:find("^" .. prefix) then
            callback(k)
            keys_processed = keys_processed + 1
        end
    end

    ngx.log(ngx.INFO, "processed ", keys_processed, " keys with prefix: ", prefix)
    return keys_processed
end

-- 删除指定键值对
function _M:cacheDel(key)
    local ok, err = self.cache:delete(key)
    if not ok then
        ngx.log(ngx.ERR, "failed to delete key: " .. key, err)
    end
    return ok, err
end

return _M
