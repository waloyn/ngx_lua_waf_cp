local _M = {}
local cjson = require "cjson"
local api = require "api"
local auth = require "auth"

-- 响应JSON数据
local function response(data, code)
    code = code or 200
    ngx.status = code
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say(cjson.encode({
        code = code,
        data = data,
        timestamp = ngx.time()
    }))
    ngx.exit(code)
end

-- 获取POST请求体
local function getRequestBody()
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if not data then
        return nil
    end
    return cjson.decode(data)
end

-- 检查用户认证
local function checkAuth()
    if not auth.validateSession() then
        response({message = "Unauthorized"}, 401)
        return false
    end
    return true
end

-- 路由处理函数
function _M.handle()
    local uri = ngx.var.uri
    local method = ngx.req.get_method()

    -- 登录接口
    if uri == "/api/login" and method == "POST" then
        local data = getRequestBody()
        if not data or not data.username or not data.password then
            response({message = "Invalid request"}, 400)
            return
        end
        local session_id = auth.authenticate(data.username, data.password)
        if session_id then
            ngx.header["Set-Cookie"] = "session_id=" .. session_id .. "; path=/; HttpOnly"
            response({message = "Login successful"})
        else
            response({message = "Invalid credentials"}, 401)
        end
        return
    end

    -- 登出接口
    if uri == "/api/logout" and method == "POST" then
        local session_id = ngx.var.cookie_session_id
        auth.logout(session_id)
        ngx.header["Set-Cookie"] = "session_id=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
        response({message = "Logout successful"})
        return
    end

    -- 检查认证状态
    if string.match(uri, "^/api/") and uri ~= "/api/login" then
        if not checkAuth() then
            return
        end
    end

    -- 统计数据接口
    if uri == "/api/stats" and method == "GET" then
        local stats = api.getStats()
        response(stats)
    elseif uri == "/api/stats/attack_distribution" and method == "GET" then
        local distribution = api.getAttackDistribution()
        response(distribution)
    elseif uri == "/api/stats/request_trend" and method == "GET" then
        local trend = api.getRequestTrend()
        response(trend)

    -- 重载配置接口
    elseif uri == "/api/reload-config" and method == "POST" then
        local success, message = api.reloadConfig()
        response({success = success, message = message})

    -- IP黑名单管理接口
    elseif uri == "/api/blacklist" then
        if method == "GET" then
            local blacklist = api.getBlackList()
            response(blacklist)
        elseif method == "POST" then
            local data = getRequestBody()
            if not data or not data.ip then
                response({message = "Invalid request"}, 400)
                return
            end
            local success = api.addToBlackList(data.ip)
            response({success = success})
        elseif method == "DELETE" then
            local data = getRequestBody()
            if not data or not data.ip then
                response({message = "Invalid request"}, 400)
                return
            end
            local success = api.removeFromBlackList(data.ip)
            response({success = success})
        end

    -- IP白名单管理接口
    elseif uri == "/api/whitelist" then
        if method == "GET" then
            local whitelist = api.getWhiteList()
            response(whitelist)
        elseif method == "POST" then
            local data = getRequestBody()
            if not data or not data.ip then
                response({message = "Invalid request"}, 400)
                return
            end
            local success = api.addToWhiteList(data.ip)
            response({success = success})
        elseif method == "DELETE" then
            local data = getRequestBody()
            if not data or not data.ip then
                response({message = "Invalid request"}, 400)
                return
            end
            local success = api.removeFromWhiteList(data.ip)
            response({success = success})
        end

    -- 规则配置接口
    elseif uri == "/api/rules" then
        if method == "GET" then
            local rules = api.getRules()
            response(rules)
        end
    elseif string.match(uri, "^/api/rules/([^/]+)$") then
        local file = string.match(uri, "^/api/rules/([^/]+)$")
        if method == "GET" then
            local content = api.getRuleContent(file)
            if content then
                response({content = content})
            else
                response({message = "Rule file not found"}, 404)
            end
        elseif method == "PUT" then
            local data = getRequestBody()
            if not data then
                response({message = "Invalid request"}, 400)
                return
            end
            
            if data.enabled ~= nil then
                local success = api.switchRule(file,data.enabled)
                response({success = success})
                return
            end
            if data.content ~= nil then
                local success = api.updateRule(file, data.content)
                response({success = success})
                return
            end
            response({message = "Invalid request"}, 400)
        end

    -- 日志查看接口
    elseif uri == "/api/logs" then
        if method == "GET" then
            local args = ngx.req.get_uri_args()
            local host = args.host or "127.0.0.1"
            local date = args.date or ngx.today()
            local limit = tonumber(args.limit) or 100
            local logs = api.getLogs(host, date, limit)
            response(logs)
        end

    -- 文件读取接口
    elseif uri == "/api/read-file" then
        if method == "GET" then
            local args = ngx.req.get_uri_args()
            if not args.file then
                response({message = "Missing file parameter"}, 400)
                return
            end
            local content = api.readFile(args.file)
            if content then
                response({content = content})
            else
                response({message = "File not found or access denied: " .. args.file}, 404)
            end
        end

    -- 文件保存接口
    elseif uri == "/api/save-file" then
        if method == "POST" then
            local data = getRequestBody()
            if not data or not data.file or not data.content then
                response({message = "Missing file or content parameter"}, 400)
                return
            end
            local success = api.saveFile(data.file, data.content)
            if success then
                response({message = "File saved successfully", success = true})
            else
                response({message = "Failed to save file or access denied"}, 500)
            end
        end

    -- 404错误
    else
        response({message = "Not Found"}, 404)
    end

    -- 刷新会话时间
    if ngx.var.cookie_session_id then
        local username = ngx.shared.sessions:get(ngx.var.cookie_session_id)
        if username then
            ngx.shared.sessions:set(ngx.var.cookie_session_id, username, 3600)
        end
    end
end

return _M