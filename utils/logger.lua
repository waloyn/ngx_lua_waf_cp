local concat = table.concat
local newtab = table.new
local timerat = ngx.timer.at

local _M = {}
local mt = { __index = _M }
local localFile = require "localFile"

-- 清理 host 中的文件名非法字符
-- Windows 非法: \ / : * ? " < > |；其中 `:` 在 NTFS 中会被识别为 ADS 分隔符，
-- 导致 "host:port.log" 被解析为「主文件 host + ADS 流 port.log」，主文件落盘为空，.log 后缀"丢失"。
-- 同时去除首尾空白、首尾的 `.`（Windows 不允许文件名以点或空格结尾；
-- 全是点的 host 如 "." / ".." / "..." 视为非法，回落 unknown）。
local function sanitizeHost(host)
    if not host or host == "" then
        return "unknown"
    end
    local s = ngx.re.gsub(host, [=[[\\/:*?"<>|\x00-\x1f]]=], "_", "jo")
    s = ngx.re.gsub(s, [=[^[.\s]+|[.\s]+$]=], "", "jo")
    if s == "" or s:match("^%.+$") then
        return "unknown"
    end
    return s
end

_M.sanitizeHost = sanitizeHost

-- 模块级实例缓存：相同 host 复用同一 logger，让内部 batching 生效
-- （require 缓存保证该表跨请求存活；多 worker 各自一份，无需共享）
local loggers_by_host = {}

-- 创建/复用日志对象
function _M:new(host)
    host = sanitizeHost(host)
    local cached = loggers_by_host[host]
    if cached then
        return cached
    end
    local t = {
        flush_limit = 4096,                -- 4KB的刷新限制
        flush_timeout = 1,                 -- 1秒的刷新超时

        buffered_size = 0,                 -- 当前缓冲区大小
        buffer_index = 0,                  -- 缓冲区索引
        buffer_data = newtab(20000, 0),    -- 初始化一个新的表来存储缓冲数据

        host = host,                       -- 主机名（已清理非法字符）
        timer = false,                     -- 定时器
    }

    setmetatable(t, mt)
    loggers_by_host[host] = t
    return t
end

-- 将缓冲区数据写入文件
local function writeFile(self, value)
    local day = ngx.today()
    local logPath = day
    local filename = self.host .. ".log"

    localFile.writeFile(logPath, filename, value)
end

-- 刷新缓冲区，将缓冲区数据写入文件（buffer_data 为单 Worker 私有，先快照清空再写盘，避免重入与跨 Worker 误跳过）
local function flushBuffer(self)
    if self.buffered_size == 0 then
        return
    end

    local buffer = concat(self.buffer_data, "", 1, self.buffer_index)
    self.buffered_size = 0
    self.buffer_index = 0
    self.buffer_data = newtab(20000, 0)

    writeFile(self, buffer)
end

-- 刷新当前 Worker 内所有 host 的剩余日志缓冲（供 Worker 退出时调用）
function _M.flushAll()
    for _, loggerInstance in pairs(loggers_by_host) do
        flushBuffer(loggerInstance)
    end
end

-- 定时器回调函数，用于定期刷新缓冲区
local function flushPeriod(premature, self)
    flushBuffer(self)
    self.timer = false
end

-- 将消息写入缓冲区
local function writeBuffer(self, msg, msg_len)
    self.buffer_index = self.buffer_index + 1
    self.buffer_data[self.buffer_index] = msg
    self.buffered_size = self.buffered_size + msg_len
end

-- 启动定时器
local function startTimer(self)
    if not self.timer then
        local ok, err = timerat(self.flush_timeout, flushPeriod, self)
        if not ok then
            ngx.log(ngx.ERR, "failed to create the timer: ", err)
            return
        end
        self.timer = true
    end
end

-- 记录日志
function _M:log(msg)
    msg = tostring(msg)
    local msg_len = #msg
    local len = msg_len + self.buffered_size

    writeBuffer(self, msg, msg_len)

    if len >= self.flush_limit then
        flushBuffer(self)
    else
        startTimer(self)
    end
end

return _M
