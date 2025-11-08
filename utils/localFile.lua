local _M = {}

-- function _M.ensureDirExists(path)
--     local ok, err = os.execute('mkdir "' .. path .. '"')
--     if not ok then
--         ngx.log(ngx.ERR, "Failed to create directory: ", path, " - ", err)
--         return false
--     end
--     return true
-- end

function _M.ensureDirExists(path)
    -- 判断当前操作系统
    local is_windows = package.config:sub(1, 1) == "\\"
    
    -- 检查路径是否存在
    local function path_exists(p)
        local f = io.open(p, "r")
        if f then
            f:close()
            return true
        else
            return false
        end
    end

    -- 如果路径已存在，直接返回
    if path_exists(path) then
        return true  -- 路径已存在
    end

    -- 创建目录
    local command
    if is_windows then
        command = 'mkdir "' .. path .. '"'
    else
        command = 'mkdir -p "' .. path .. '"'
    end

    -- 执行创建目录的命令
    local result = os.execute(command)
    return result == true or result == 0  -- 成功返回 true
end


function _M.writeFile(path, filename, value)
    local log_path = WAF_CONFIG["log_path"] .. "/" .. path

    -- 确保目录存在
    _M.ensureDirExists(log_path)

    local file_path = log_path .. "/" .. filename
    local file, err = io.open(file_path, "ab")
    if not file then
        ngx.log(ngx.ERR, "Failed to open file for writing: ", file_path, " - ", err)
        return false
    end

    file:write(value)
    file:close()
    return true
end

function _M.getFiles(path)
    local files = {}
    
    -- 确保路径以反斜杠结尾
    if not path:match('\\$') then
        path = path .. '\\'
    end
    
    -- 使用dir命令获取文件列表
    local cmd = 'dir /b /a-d "' .. path .. '"'
    local handle = io.popen(cmd)
    if not handle then
        ngx.log(ngx.ERR, "Failed to execute dir command")
        return files
    end
    
    -- 读取命令输出
    for file in handle:lines() do
        if file ~= "." and file ~= ".." then
            table.insert(files, file)
        end
    end
    
    handle:close()
    return files
end

return _M
