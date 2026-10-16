# WAF项目分析文档

## 项目概述

这是一个基于 **OpenResty/Nginx + Lua** 实现的 **Web应用防火墙(WAF)** 项目。采用模块化设计，在Nginx请求处理的不同阶段进行安全检测和防护。

## 项目架构

### 核心文件结构

```
├── init.lua              # 初始化配置和规则加载
├── waf.lua               # 主要防护逻辑
├── header.lua            # 响应头处理
├── exit.lua              # 退出清理
├── conf.d/
│   ├── waf.conf         # WAF配置文件
│   ├── http.conf        # Nginx HTTP配置
│   ├── whiteIp          # IP白名单
│   ├── blackIp          # IP黑名单
│   ├── whitehost        # 域名白名单
│   └── 403.html         # 拦截页面
├── utils/
│   ├── cache.lua        # 缓存管理 (滑动窗口 incr+expire)
│   ├── count.lua        # 统计计数
│   ├── decoder.lua      # 载荷解码 (递归 URL + HTML 实体)
│   ├── ip.lua           # IP处理工具 / GeoIP2
│   ├── logger.lua       # 日志记录 (host 实例复用 + 异步)
│   ├── localFile.lua    # 文件读写
│   ├── router.lua       # API路由
│   ├── api.lua          # API接口
│   └── auth.lua         # 认证管理 (会话 + CSRF Token)
└── rules/
    ├── sqli.lua         # SQL注入规则
    ├── xss.lua          # XSS攻击规则
    ├── cmd.lua          # 命令注入规则
    ├── ssrf.lua         # SSRF攻击规则
    ├── xxe.lua          # XXE攻击规则
    ├── path.lua         # 路径遍历规则
    └── ...              # 其他规则文件
```

## 核心功能

### 1. 防护能力

#### 攻击检测类型
- **SQL注入检测** (sqli.lua)
  - SELECT/UNION语句检测
  - 时间盲注检测 (sleep/benchmark)
  - information_schema访问检测
  - 布尔逻辑注入检测

- **XSS跨站脚本攻击** (xss.lua)
  - Script标签注入
  - Iframe/Object/Embed标签
  - JavaScript/VBScript URI
  - 事件处理器注入
  - HTML标签注入

- **命令注入检测** (cmd.lua)
  - PHP/Python/Ruby/Perl/Java命令执行函数
  - Linux/Windows系统命令
  - 敏感文件路径访问

- **其他攻击类型**
  - SSRF攻击检测
  - XXE攻击检测
  - 路径遍历检测
  - 敏感信息泄露检测
  - DNS攻击检测
  - LDAP注入检测

#### CC攻击防护
- 基于时间窗口的访问频率限制
- 可配置访问次数和时间窗口
- 默认: 60秒内100次请求

### 2. 访问控制

#### IP管理
- **白名单**: 完全放行，不进行任何检测
- **黑名单**: 直接拦截访问
- **动态封禁**: 基于攻击行为自动封禁
- **CIDR支持**: 支持IP段配置 (如 192.168.1.0/24)

#### 域名管理
- 域名白名单机制
- 支持完整域名匹配

### 3. 工作模式

```
monitor     # 监控模式 - 仅记录攻击日志，不拦截请求
protection  # 防护模式 - 检测并拦截攻击请求
off         # 关闭模式 - WAF完全关闭
```

### 4. 置信度评分系统

#### 评分机制
- **置信度等级**: 1(低) / 2(中) / 3(高)
- **累计评分**: 多次疑似攻击累加置信度
- **阈值触发**: 超过配置阈值后拦截

#### 配置参数
```
possibly_timeout = 300    # 疑似攻击统计时间窗口(秒)
possibly_count = 1        # 触发拦截的置信度阈值
block_count = 3           # 恶意行为次数阈值
block_time = 600          # 恶意行为检测时间窗口(秒)
block_timeout = 600       # IP封禁时长(秒)
```

### 5. 动态封禁策略

#### 封禁逻辑
1. 检测到疑似攻击 → 累加置信度
2. 置信度超过阈值 → 记录攻击次数
3. 攻击次数超过阈值 → 封禁IP
4. 重复攻击 → 延长封禁时间(倍数增长)

#### 封禁时长计算
```lua
封禁时长 = block_timeout × 攻击次数
```

## 请求处理流程

```
┌─────────────────────────────────────────────────────────────┐
│                      Nginx 请求到达                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  init_by_lua_file (init.lua)                                │
│  - 加载配置文件 (waf.conf)                                   │
│  - 加载IP黑白名单                                            │
│  - 加载域名白名单                                            │
│  - 加载攻击检测规则                                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  access_by_lua_file (waf.lua)                               │
│                                                             │
│  1. 检查WAF模式 (off/monitor/protection)                     │
│  2. 检查IP白名单 → 放行                                      │
│  3. 检查域名白名单 → 放行                                     │
│  4. 检查IP黑名单 → 拦截                                       │
│  5. 检查IP是否被封禁 → 拦截                                   │
│  6. 检查CC攻击 → 拦截                                        │
│  7. 检查请求体大小 → 拦截                                     │
│  8. 规则匹配检测:                                            │
│     - URL解码 (多层解码防绕过)                                │
│     - URI检测                                                │
│     - Header检测                                             │
│     - Body检测                                               │
│     - Cookie检测                                             │
│  9. 匹配到攻击 → 记录日志 + 拦截/放行                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  header_filter_by_lua_file (header.lua)                     │
│  - 统计响应状态码                                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  exit_worker_by_lua_file (exit.lua)                         │
│  - 保存统计数据到磁盘                                        │
│  - 清理缓存                                                  │
└─────────────────────────────────────────────────────────────┘
```

## 核心机制详解

### 1. 多层URL解码

防止攻击者通过多次编码绕过检测。归一化逻辑独立在 `utils/decoder.lua`：

```lua
-- waf.lua 在 access 阶段对 uri/header/body 调用
local decoder = require "decoder"
local normalized = decoder.unescape(input, max_decode_count)
-- 内部两阶段递归至稳定或达上限：
-- 1) URL 解码  : ngx.unescape_uri 反复展开 %XX、%25XX 等多层编码
-- 2) HTML 实体: 支持 &#NNN;(十进制) / &#xNN;(十六进制) / &name;(命名实体)
--    >255 码点编为 UTF-8；递归超过 decode_max_count 视为恶意嵌套，返回 nil → 拦截
```

注意：因为引擎已递归解码标准 `%XX`,规则中**不应**再写 `%2f`、`%c0%af` 这类字面百分编码;
非标准 IIS Unicode 编码(`%u2215` 等)和解码后字节(`\xc0\xaf`)可以正常匹配。

### 2. 规则匹配引擎

#### 规则结构
```lua
{
    name = "规则名称",
    desc = "规则描述",
    level = "high/medium/low",
    position = "uri,body,cookie",  -- 检测位置(CSV)
    rules = {
        {
            pattern = "正则表达式",
            name = "特征名称",
            confidence = 3  -- 置信度
        }
    }
}
```

#### 数据格式与 position 约定
- `position` 合法取值: **`uri` / `body` / `cookie` / `user-agent`**, 由 `init.lua` 白名单校验,未知值记 WARN。
- 引擎在 access 阶段把待检测数据拼为带前缀的字符串入 `checkData`:
  - `"uri: <decoded_uri>"`
  - `"body: <decoded_body>"`
  - `"<header_name>: <decoded_value>"`(逐 header 值入,避免 join 后跨值误命中)
- 匹配前先用 `data:sub(1, #p) == p` 做前缀过滤,命中再走 `ngx.re.match(data, pattern, "isjo")`。
- 规则文件由 `init_by_lua_file` 阶段一次性加载: pattern trim、positions 切分,引擎自身派生独立结构,不写回规则对象。

#### 匹配流程
1. 遍历 checkData(uri / 各 header / body)
2. 对每条 data: 遍历 RULE_FILES → 命中 position 前缀 → 遍历 pattern 列表
3. 命中 → 累加置信度(`possibly`)
4. 累计置信度/攻击次数超阈值 → 封禁 IP

### 3. 缓存机制

使用 `ngx.shared.DICT` 实现高性能共享内存缓存:

```lua
-- 缓存字典
nova_waf        # 50MB - 主缓存(IP封禁、攻击计数等)
nova_waf_count  # 10MB - 统计数据
dict_locks      # 5MB  - 分布式锁
sessions        # 1MB  - 会话管理
```

#### 缓存键设计
```
block:{ip}          # IP封禁状态
possibly:{ip}       # 疑似攻击置信度
attack:{ip}         # 攻击次数
attackCount:{ip}    # 历史攻击计数
cc:{ip}             # CC攻击计数 (滑动窗口)
csrf:{session_id}   # CSRF Token (管理后台)
```

#### 滑动窗口计数
`utils/cache.lua` 的 `cacheIncr(key, inc, ttl)` 采用 `shared:incr(...) + shared:expire(...)`,在原子递增的基础上每次显式刷新 TTL,
保证 CC 防护(60s 内 100 次)和 possibly 累加都遵循"最近 N 秒内累计"的滑动窗口语义,而非"自首次起 N 秒"的固定窗口。

### 4. 日志系统

#### 异步缓冲写入
- 缓冲区大小: 4KB
- 刷新超时: 1 秒
- 按域名和日期分类存储
- 同 host 的 logger 实例**模块级复用**,跨请求共享 buffer,batching 真正生效
- `Waf:recordRequest` 通过 `ngx.timer.at(0, ...)` 把磁盘 IO 推出 access 热路径
- 文件名取自 Host header,经 `sanitizeHost` 清理 NTFS 非法字符(`\ / : * ? " < > |`)与首尾点,纯点 host 回落 `unknown`

#### 编码安全
- JSON 编码使用 `cjson.safe`: 遇到非法 UTF-8 字节返回 nil+err,不会 raise 中断攻击处理
- 403 拦截页模板用 function 形式 `gsub` + `htmlEscape`,避免替换串中的 `%` 元字符污染或反射 XSS

#### 日志格式 (JSON)
```json
{
    "request_id": "唯一请求ID",
    "attack_type": "攻击类型",
    "ip": "客户端IP",
    "request_time": "请求时间",
    "http_method": "HTTP方法",
    "request_uri": "请求URI",
    "request_protocol": "协议版本",
    "request_data": "请求数据",
    "user_agent": "用户代理",
    "headers": {}
}
```

### 5. 统计分析

#### 统计维度
- 总请求数 / 拦截请求数
- 操作系统分布
- 访问域名分布
- 来源分析 (Referer)
- IP来源分析
- 响应状态码分布
- 爬虫识别

#### 数据存储
- 实时数据: 共享内存
- 历史数据: 按小时保存为JSON文件
  ```
  count/20241108/01.json
  count/20241108/02.json
  ```

## 管理后台

### 安全机制
- **会话 ID**: `md5(ngx.now() + remote_addr + worker.pid + randomHex(16))`,存 `sessions` shared dict
- **Cookie 属性**: `HttpOnly; SameSite=Strict`,HTTPS 时动态附加 `Secure`
- **CSRF Token**: 登录响应 `data.csrf_token`,POST/PUT/DELETE 必须携带 `X-CSRF-Token` header(`/api/login` 豁免)
- **随机种子**: `init.lua` 中 `math.randomseed(ngx.now() * 1000 + ngx.worker.pid())`,每 worker 独立

### API接口 (端口9520)

#### 认证接口
- `POST /api/login` - 用户登录
- `POST /api/logout` - 用户登出

#### 统计接口
- `GET /api/stats` - 获取统计数据
- `GET /api/stats/attack_distribution` - 攻击分布
- `GET /api/stats/request_trend` - 请求趋势

#### 配置管理
- `POST /api/reload-config` - 重载配置

#### IP管理
- `GET /api/blacklist` - 获取黑名单
- `POST /api/blacklist` - 添加黑名单
- `DELETE /api/blacklist` - 删除黑名单
- `GET /api/whitelist` - 获取白名单
- `POST /api/whitelist` - 添加白名单
- `DELETE /api/whitelist` - 删除白名单

#### 规则管理
- `GET /api/rules` - 获取规则列表
- `GET /api/rules/{file}` - 获取规则内容
- `PUT /api/rules/{file}` - 更新规则/开关规则

#### 日志查询
- `GET /api/logs?host=&date=&limit=` - 查询日志

#### 文件操作
- `GET /api/read-file?file=` - 读取文件
- `POST /api/save-file` - 保存文件

## 配置说明

### waf.conf 主要配置项

```ini
# 工作模式
mode = "protection"  # monitor/protection/off

# 调试模式
debug = "on"  # on/off

# 日志路径
log_path = "e:/website/openresty/logs/waf"

# 置信度配置
possibly_timeout = 300    # 疑似攻击统计时间(秒)
possibly_count = 1        # 触发拦截的置信度阈值

# 封禁配置
block_timeout = 600       # IP封禁时长(秒)
block_count = 3           # 触发封禁的攻击次数
block_time = 600          # 攻击次数统计时间(秒)

# 规则开关
exp_backup = "on"         # 备份路径检测
exp_bot = "on"            # 恶意机器人检测
exp_cmd = "on"            # 命令注入检测
exp_deserialize = "on"    # 反序列化攻击检测规则
exp_dns = "on"            # DNS攻击检测
exp_ldap = "on"           # LDAP注入检测
exp_nosql = "on"          # NoSQL注入检测规则
exp_path = "on"           # 路径遍历检测
exp_sensitive = "on"      # 敏感信息检测
exp_spring = "on"         # Spring Boot检测规则
exp_sqli = "on"           # SQL注入检测
exp_ssrf = "on"           # SSRF攻击检测
exp_ssti = "on"           # SSTI模板注入检测规则
exp_upload = "on"         # 文件上传检测规则
exp_xss = "on"            # XSS攻击检测
exp_xxe = "on"            # XXE攻击检测


# 请求限制
body_max_size = 52428800  # 请求体最大大小(字节) 50MB
decode_max_count = 10     # 最大解码次数

# CC防护
cc_defence = "on"         # CC攻击防护开关
cc_limit = 100            # 访问频率限制
cc_seconds = 60           # 时间窗口(秒)

# 其他功能
inject_trap = "on"        # 诱捕功能
statistics = "on"         # 统计功能
```

## 技术特点

### 优势
1. **高性能**: 基于OpenResty，使用Lua JIT编译
2. **低延迟**: 共享内存缓存，避免外部存储访问
3. **模块化**: 规则文件独立，易于扩展和维护
4. **灵活配置**: 支持多种工作模式和细粒度规则控制
5. **智能防护**: 置信度评分系统，减少误报
6. **动态封禁**: 自适应封禁时长，有效防止持续攻击
7. **完整日志**: JSON格式日志，便于分析和审计
8. **可视化管理**: Web管理后台，操作便捷

### 防绕过机制
1. 多层URL解码(递归至稳定,超 `decode_max_count` 视为恶意)
2. HTML实体解码(十进制 `&#NNN;` / 十六进制 `&#xNN;` / 命名实体 / 非 ASCII 编 UTF-8)
3. 大小写不敏感匹配(`ngx.re.match` 的 `i` flag)
4. 正则表达式深度匹配
5. 多位置检测(URI/Header/Body/Cookie/User-Agent),header 多值逐值入,避免 join 误命中
6. body 落盘兜底:大 body 写到 `client_body_temp_path` 时,WAF 回读文件而非放过
7. headers 无 100 上限(`get_headers(0)`),消除"发 >100 个 header 绕过"的盲区

## 部署环境

- **平台**: Windows
- **Web服务器**: OpenResty (Nginx + Lua)
- **安装路径**: `e:/website/openresty/`
- **WAF路径**: `e:/website/openresty/waf/`
- **日志路径**: `e:/website/openresty/logs/waf/`
- **管理端口**: 9520

## 集成方式

在 Nginx 配置中引入:

```nginx
# http.conf
lua_shared_dict nova_waf 50m;
lua_shared_dict nova_waf_count 10m;
lua_shared_dict dict_locks 5m;
lua_shared_dict sessions 1m;

lua_package_path "e:/website/openresty/waf/?.lua;;";
lua_package_cpath "e:/website/openresty/waf/?.so;;";

init_by_lua_file "e:/website/openresty/waf/init.lua";
access_by_lua_file "e:/website/openresty/waf/waf.lua";
header_filter_by_lua_file "e:/website/openresty/waf/header.lua";
exit_worker_by_lua_file "e:/website/openresty/waf/exit.lua";
```

## 总结

这是一个功能完善的企业级WAF解决方案，具备:
- ✅ 实时攻击检测和防护
- ✅ 灵活的配置和规则管理
- ✅ 智能的置信度评分系统
- ✅ 动态IP封禁机制
- ✅ 完整的日志和统计分析
- ✅ 可视化管理后台
- ✅ 高性能和低延迟

适用于需要Web应用安全防护的各类场景。
