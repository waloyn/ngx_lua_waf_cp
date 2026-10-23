local _M = {}

-- 进程级已创建目录缓存，避免 Windows 下对目录调用 io.open(p, "r") 恒返回 Permission denied 导致每次写文件都派生 cmd.exe
local ensured_dirs = {}

-- 校验路径是否安全（禁止命令注入元字符）
local function isSafePath(path)
    if type(path) ~= "string" or path == "" then
        return false
    end
    if path:find('[&|;`$><"%c]') then
        return false
    end
    return true
end

function _M.ensureDirExists(path)
    if not isSafePath(path) then
        ngx.log(ngx.ERR, "Unsafe directory path rejected: ", tostring(path))
        return false
    end

    local is_windows = package.config:sub(1, 1) == "\\"
    local norm_path = is_windows and path:gsub("/", "\\") or path:gsub("\\", "/")
    norm_path = norm_path:gsub("[\\/]+$", "")

    if ensured_dirs[norm_path] then
        return true
    end

    local command
    if is_windows then
        -- if not exist 避免目录已存在时报错，且仅在首次未命中缓存时执行一次
        command = 'if not exist "' .. norm_path .. '" mkdir "' .. norm_path .. '"'
    else
        command = 'mkdir -p "' .. norm_path .. '"'
    end

    local result = os.execute(command)
    local ok = (result == true or result == 0)
    if ok then
        ensured_dirs[norm_path] = true
    end
    return ok
end

function _M.writeFile(path, filename, value)
    local base_path = (WAF_CONFIG and WAF_CONFIG["log_path"]) or (CURRENT_PATH .. "../logs/waf")
    local log_path = base_path .. "/" .. path

    if not _M.ensureDirExists(log_path) then
        return false
    end

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
    if not isSafePath(path) then
        ngx.log(ngx.ERR, "Unsafe path in getFiles: ", tostring(path))
        return files
    end

    local is_windows = package.config:sub(1, 1) == "\\"
    local cmd
    if is_windows then
        local win_path = path:gsub("/", "\\")
        if not win_path:match("\\$") then
            win_path = win_path .. "\\"
        end
        cmd = 'dir /b /a-d "' .. win_path .. '"'
    else
        cmd = 'ls -1 "' .. path .. '"'
    end

    local handle = io.popen(cmd)
    if not handle then
        ngx.log(ngx.ERR, "Failed to execute directory listing command")
        return files
    end

    for file in handle:lines() do
        file = file:gsub("[\r\n]+", "")
        if file ~= "" and file ~= "." and file ~= ".." then
            table.insert(files, file)
        end
    end

    handle:close()
    return files
end

return _M
