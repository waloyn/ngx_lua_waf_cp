local _M = {}
local ngx = ngx

-- 用户凭证（实际应用中应该使用数据库或配置文件存储）
local users = {
    admin = {
        password = "admin", -- 实际应用中应该使用加密存储
        role = "admin"
    }
}

-- 生成随机十六进制字符串
local function randomHex(len)
    local bytes = {}
    for i = 1, len do
        bytes[i] = string.format("%02x", math.random(0, 255))
    end
    return table.concat(bytes)
end

-- 生成会话ID（包含随机熵源）
local function generateSessionId()
    return ngx.md5(ngx.now() .. ngx.var.remote_addr .. ngx.worker.pid() .. randomHex(16))
end

-- 生成CSRF Token
local function generateCsrfToken()
    return ngx.md5(randomHex(16) .. ngx.now() .. ngx.worker.pid())
end

-- 验证用户凭证
function _M.authenticate(username, password)
    local user = users[username]
    if user and user.password == password then
        local session_id = generateSessionId()
        local csrf_token = generateCsrfToken()
        ngx.shared.sessions:set(session_id, username, 3600)
        ngx.shared.sessions:set("csrf:" .. session_id, csrf_token, 3600)
        return session_id, csrf_token
    end
    return nil, nil
end

-- 验证会话
function _M.validateSession()
    local session_id = ngx.var.cookie_session_id
    if not session_id then
        return false
    end

    local username = ngx.shared.sessions:get(session_id)
    if not username then
        return false
    end

    return true
end

-- 验证CSRF Token
function _M.validateCsrf()
    local session_id = ngx.var.cookie_session_id
    if not session_id then
        return false
    end
    local stored_token = ngx.shared.sessions:get("csrf:" .. session_id)
    local request_token = ngx.req.get_headers()["X-CSRF-Token"]
    if not stored_token or not request_token then
        return false
    end
    return stored_token == request_token
end

-- 刷新会话和CSRF Token过期时间
function _M.refreshSession()
    local session_id = ngx.var.cookie_session_id
    if session_id then
        local username = ngx.shared.sessions:get(session_id)
        if username then
            ngx.shared.sessions:set(session_id, username, 3600)
            local csrf_token = ngx.shared.sessions:get("csrf:" .. session_id)
            if csrf_token then
                ngx.shared.sessions:set("csrf:" .. session_id, csrf_token, 3600)
            end
        end
    end
end

-- 注销会话
function _M.logout(session_id)
    if session_id then
        ngx.shared.sessions:delete("csrf:" .. session_id)
        ngx.shared.sessions:delete(session_id)
        return true
    end
    return false
end

return _M
