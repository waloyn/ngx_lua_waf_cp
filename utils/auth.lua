local _M = {}
local cjson = require "cjson"
local ngx = ngx

-- 用户凭证（实际应用中应该使用数据库或配置文件存储）
local users = {
    admin = {
        password = "admin", -- 实际应用中应该使用加密存储
        role = "admin"
    }
}

-- 生成会话ID
local function generateSessionId()
    return ngx.md5(ngx.now() .. ngx.var.remote_addr)
end

-- 验证用户凭证
function _M.authenticate(username, password)
    local user = users[username]
    if user and user.password == password then
        local session_id = generateSessionId()
        ngx.shared.sessions:set(session_id, username, 3600) -- 1小时过期
        return session_id
    end
    return nil
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

-- 注销会话
function _M.logout(session_id)
    if session_id then
        ngx.shared.sessions:delete(session_id)
        return true
    end
    return false
end

return _M