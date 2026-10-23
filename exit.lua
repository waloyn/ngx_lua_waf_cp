ngx.log(ngx.INFO, "Nginx Worker is shutting down. Performing cleanup tasks.")

-- 刷新当前 Worker 内残留的异步日志缓冲
local ok_log, logger = pcall(require, "logger")
if ok_log and logger and logger.flushAll then
    pcall(logger.flushAll)
end

-- 使用带 TTL 的原子锁确保仅一个 Worker 将共享内存统计数据归档落盘
local lock_dict = ngx.shared.dict_locks
local LOCK_KEY = "nginx_exit_lock"
if lock_dict and not lock_dict:add(LOCK_KEY, true, 5) then
    return
end

local localCount = require "count"
localCount:new():onExitNginx()
if lock_dict then
    lock_dict:delete(LOCK_KEY)
end
