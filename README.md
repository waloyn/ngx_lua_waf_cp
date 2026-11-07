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
├── rules/
│   ├── sqli.lua         # SQL注入规则
│   ├── xss.lua          # XSS攻击规则
│   ├── cmd.lua          # 命令注入规则
│   ├── ssrf.lua         # SSRF攻击规则
│   ├── xxe.lua          # XXE攻击规则
│   ├── path.lua         # 路径遍历规则
│   ├── spring.lua       # Spring 漏洞利用与端点规则
│   ├── ldap.lua         # LDAP 与 JNDI 注入规则
│   └── ...              # 其他规则文件 (共 16 类)
└── tools/
    ├── validate_rules.lua     # 规则离线编译与语法规范校验工具
    ├── test_rule_hit_rate.lua  # 规则命中率与覆盖度基准测试工具
    └── test_payloads.lua      # 16 类攻防基准测试用例库 (attacks / legitimate)
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
  - PHP/Python/Ruby/Perl/Java命令执行函数与代码执行
  - Linux/Windows系统命令 (含 id、sh、bash、whoami 等高频命令)
  - 管道与操作符命令连接 (支持容空格模式匹配如 `| whoami`、`&& id`、`|| uname`)
  - 反弹 Shell 特征检测 (如 `bash -i >& /dev/tcp/...`、`nc -e /bin/sh` 等)
  - 敏感系统文件路径访问与环境变量提取

- **路径遍历检测** (path.lua)
  - 经典 `../` / `..\` 目录穿越及变体检测
  - 敏感系统文件探测 (如 `/etc/passwd`、`win.ini`、`/etc/shadow` 等)
  - 多点与双写绕过防御 (拦截针对后端单次替换漏洞的 `....//`、`..././`、`....\\` 等变体)
  - 双重 URL 编码绕过检测 (如 `%252e%252e%252f`)
  - 超长 UTF-8 编码穿越 (`\xc0\xaf` 等)

- **LDAP / JNDI 注入检测** (ldap.lua)
  - Log4j2 JNDI 注入及混淆绕过 (`${jndi:ldap:...}`, `${lower:...}`, `${::-...}`)
  - 经典 LDAP 逻辑过滤器注入 (`(&(...))`、`|`、`!`)
  - 属性通配符绕过探测 (`uid=*`, `cn=*`, `sAMAccountName=*`)
  - 对象类探测 (`objectClass=*`, `objectCategory=*`)
  - 空字节截断注入 (`%00`, `\x00`)

- **Spring 漏洞利用与端点访问** (spring.lua)
  - Spring Boot Actuator 敏感端点未授权访问 (`/actuator/env`, `/actuator/heapdump`, `/actuator/mappings` 等)
  - Swagger UI / OpenAPI 接口文档未授权泄露 (`/swagger-ui.html`, `/v2/api-docs`)
  - 探针误报治理：精准放行常规健康检查端点 (`/actuator/health`, `/actuator/healthcheck`, `/actuator/info`)，避免 Kubernetes 存活探针与监控误拦截

- **其他攻击类型**
  - SSRF 服务端请求伪造 (ssrf.lua)
  - XXE 外部实体注入 (xxe.lua)
  - 备份与临时文件泄露 (backup.lua)
  - 恶意机器人与扫描器识别 (bot.lua)
  - 敏感信息与私钥配置泄露 (sensitive.lua)
  - Java/PHP/Python 反序列化攻击 (deserialize.lua)
  - NoSQL 注入检测 (nosql.lua)
  - SSTI 模板注入检测 (ssti.lua)
  - 文件上传恶意脚本与 MIME 绕过 (upload.lua)
  - DNS 探测与带外回显 (dns.lua)

#### CC攻击防护
- 基于时间窗口的访问频率限制
- 可配置访问次数和时间窗口
- 默认: 60秒内100次请求

#### 人机挑战（行为特征检测 + 多级验证）
- **行为特征检测**（`utils/behavior.lua`）：对导航请求做轻量指纹评分，命中项包括：
  - UA 特征：空/超短 UA、curl/wget/python-requests/okhttp 等自动化客户端
  - 协议与头部完整性：HTTP/1.0、缺少 Accept / Accept-Language / Accept-Encoding
  - 浏览器一致性：Mozilla UA 缺少 `Sec-Fetch-*`、Chromium UA 缺少 `Sec-CH-UA`、Header 数量过少
  - 请求间隔规律性：连续请求间隔稳定在 ±8ms 内（脚本定时器特征）、导航间隔 <60ms
  - 首次冷启动导航（无 Referer 且无 Cookie）
- **四级挑战**：`js`（哈希工作量证明）、`redirect`（5 秒等待跳转）、`slider`（滑块对齐缺口）、`captcha`（内置 5x7 点阵 SVG 字符验证码，非文本节点）
- **auto 模式**：按同一 IP 的触发次数自动逐级升级，默认顺序 `js → redirect → slider → captcha`
- **通行凭据**：验证通过后签发绑定客户端 IP 的签名 Cookie（`nova_waf_pass`），在 `cc_challenge_ttl` 内跳过 CC 与行为检测；已通过者使用放大 `cc_passed_factor` 倍的独立限流阈值，防止解一次题后无限刷
- **防滥用**：挑战答案只存共享字典（页面仅下发随机 ID）；同一 IP+UA 复用未过期挑战；单 IP 下发频率上限；失败次数达阈值后临时封禁
- **降级语义**：非导航请求（接口、静态资源）仍返回原有 429，不注入 HTML；`cc_challenge = "off"` 时完全回退到旧行为
- **开放重定向防护**：验证后的跳转目标仅接受本站相对路径

验证端点（由 WAF 在 access 阶段直接处理，无需修改 nginx 配置）：`POST /_waf_challenge/verify`

### 2. 访问控制

#### IP管理
- **白名单**: 完全放行，不进行任何检测
- **黑名单**: 直接拦截访问
- **动态封禁**: 基于攻击行为自动封禁
- **CIDR支持**: 支持IP段配置 (如 192.168.1.0/24)
- **热更新**: 通过管理后台保存黑/白名单后立即生效,无需重载 nginx

#### 域名管理
- 域名白名单机制
- 支持完整域名匹配
- 保存后立即生效,无需重载 nginx

#### 名单热更新机制
- 各 worker 拥有独立 Lua VM,名单内存副本互不可见
- `nova_waf` 共享字典维护单调递增版本号 `__waf_lists_version`
- 管理后台保存名单后由 `notify_lists_changed()` 做 `incr` 广播
- 每个请求在 `Waf:process()` 入口调用 `ensure_lists_fresh()`,版本号变化才重读磁盘,常态仅一次 O(1) 共享字典读取
- 重载失败不推进本地版本号,下次请求自动重试,避免瞬时 IO 异常清空名单

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
│  6. 检查CC攻击 → 挑战/拦截                                   │
│     - 人机挑战关闭或非导航请求 → 429                          │
│     - 导航请求 → JS/5秒跳转/滑块/验证码                       │
│  7. 行为特征评分 → 挑战/拦截（导航请求）                      │
│  8. 检查请求体大小 → 拦截                                     │
│  9. 规则匹配检测:                                            │
│     - URL解码 (多层解码防绕过)                                │
│     - URI检测                                                │
│     - Header检测                                             │
│     - Body检测                                               │
│     - Cookie检测                                             │
│ 10. 匹配到攻击 → 记录日志 + 拦截/放行                          │
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
ccp:{ip}            # 已通过挑战者的独立CC计数
beh:{ip}            # 行为检测：最近请求时间/间隔/规律计数
behc:{ip}           # 行为检测采样计数
chal:{id}           # 挑战内容（类型/IP/时间/答案/回跳地址）
chalip:{ip}:{ua}    # 同 IP+UA 的挑战复用索引
chalissue:{ip}      # 单IP挑战下发频次
chalfail:{ip}       # 挑战失败次数
chaln:{ip}          # CC触发的挑战升级计数
behchaln:{ip}       # 行为触发的挑战升级计数
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
- `POST /api/reload-config` - 重载配置(规则与 waf.conf 变更需调用;名单变更无需调用)

#### IP管理(变更后立即生效,无需重载)
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
- `POST /api/save-file` - 保存文件(`blackIp` / `whiteIp` / `whitehost` 保存后立即生效;`waf.conf` 需重载)

## 配置说明

### waf.conf 主要配置项

```ini
# 工作模式
mode = "protection"  # monitor/protection/off

# 调试模式
debug = "on"  # on/off

# 代理与CDN配置
trust_proxy = "off"   # 是否信任反向代理转发头（X-Forwarded-For / X-Real-IP）
cdn_mode = "off"      # CDN加速模式开关（站点接入阿里ESA、Cloudflare等CDN时开启）
cdn_header = ""       # 指定CDN真实IP请求头（留空自动识别：Ali-CDN-Real-IP、CF-Connecting-IP等）
cdn_ips = ""          # 受信任CDN节点IP/CIDR网段（可选，多个逗号分隔）

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

# CC 人机挑战
cc_challenge = "auto"     # off/js/redirect/slider/captcha/auto
cc_challenge_order = "js,redirect,slider,captcha"  # auto 升级顺序
cc_challenge_ttl = 1800   # 通过后免验证时长(秒)
cc_challenge_delay = 5    # 5秒跳转等待时长
cc_challenge_pow = 3      # JS 工作量证明难度(前导零位数 1~6)
cc_challenge_max_fail = 5 # 挑战失败封禁阈值
cc_challenge_fail_time = 600  # 失败计数窗口/封禁时长(秒)
cc_challenge_issue_max = 20   # 单IP下发挑战上限(防刷页)
cc_passed_factor = 6      # 已通过者CC阈值放大倍数
challenge_secret = ""     # Cookie 签名密钥(留空自动生成)

# 行为特征检测
behavior_defence = "on"            # 总开关
behavior_window = 60               # 采样窗口(秒)
behavior_sample = 10               # 前N个请求仅采样不判定
behavior_challenge_score = 6       # 触发挑战的风险分
behavior_block_score = 0           # 直接403的风险分(0=不启用)

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
9. **人机挑战**: 行为特征检测 + JS工作量证明 / 5秒跳转 / 滑块 / 验证码四级挑战，兼顾防护强度与正常用户可达性

### 防绕过机制
1. 多层URL解码(递归至稳定,超 `decode_max_count` 视为恶意)
2. HTML实体解码(十进制 `&#NNN;` / 十六进制 `&#xNN;` / 命名实体 / 非 ASCII 编 UTF-8)
3. 大小写不敏感匹配(`ngx.re.match` 的 `i` flag)
4. 正则表达式深度匹配
5. 多位置检测(URI/Header/Body/Cookie/User-Agent),header 多值逐值入,避免 join 误命中
6. body 落盘兜底:大 body 写到 `client_body_temp_path` 时,WAF 回读文件而非放过
7. headers 无 100 上限(`get_headers(0)`),消除"发 >100 个 header 绕过"的盲区
8. 多点与双写绕过识别: 针对后端单次替换修复的 `....//`、`..././`、`....\\` 等变体及双重 URL 编码穿越
9. 反弹 Shell 与管道容空格支持: 精确覆盖 `bash -i >&`、`nc -e` 及 `| whoami`、`&& id` 模式
10. 生产探针误报治理: 放行 `/actuator/health`、`/actuator/info` 等探针，杜绝 Kubernetes 健康检查误杀

## 规则校验与基准测试工具

项目在 `tools/` 目录下提供了完善的规则离线测试与质量保障工具链，支持在不重启或不上线的情况下验证规则语法有效性、检出率与误报表现：

### 1. 规则语法与编译校验 (`validate_rules.lua`)

- **功能**: 离线加载所有 `rules/*.lua` 文件，验证每个规则模块的 Lua 语法、`ngx.re.match` 正则表达式编译合法性（针对 OpenResty PCRE 引擎）、以及 `position` 字段白名单，避免规则因正则编译错误而在运行时被静默忽略。
- **特性**: 支持 Windows 控制台代码页自适应（通过 Win32 API 动态适配 CP936/ANSI 与 UTF-8），避免控制台输出中文乱码或换行丢失。
- **运行命令**:
  ```bash
  perl -x E:/WebSite/openresty/resty tools/validate_rules.lua
  ```
- **输出样例**:
  ```text
  [ OK ] backup.lua: 5 条规则
  [ OK ] bot.lua: 9 条规则
  [ OK ] cmd.lua: 19 条规则
  [ OK ] deserialize.lua: 18 条规则
  ...
  合计 198 条规则：错误 0，警告 0
  ```

### 2. 命中率与覆盖度基准测试 (`test_rule_hit_rate.lua`)

- **功能**: 对照基准测试用例库，全自动化测试 WAF 各模块的**攻击样本检出率 (TP)**、**良性样本误报率 (FP)** 以及**规则激活覆盖率 (Rule Coverage)**，并自动审计与列举 0 命中的规则盲区。
- **特性**: 严格对齐 `waf.lua` 的检测数据结构（`checkData` 与 `position` 前缀过滤），支持参数过滤与外部用例扩展。
- **常用选项**:
  - `-h, --help`: 显示帮助信息
  - `--type <name>`: 仅测试指定分类规则（例如 `--type sqli`、`--type cmd`）
  - `-d, --detail`: 展示各规则具体命中频次明细及 0 命中盲区清单
  - `-u, --uncovered`: 仅展示各模块未被覆盖的 0 命中规则清单
  - `--file <path>`: 外挂指定的外部 JSON 格式测试用例文件
- **运行命令**:
  ```bash
  # 全量运行基准测试
  perl -x E:/WebSite/openresty/resty tools/test_rule_hit_rate.lua

  # 仅测试命令注入规则并展示命中明细
  perl -x E:/WebSite/openresty/resty tools/test_rule_hit_rate.lua --type cmd --detail

  # 仅查看未覆盖规则盲区
  perl -x E:/WebSite/openresty/resty tools/test_rule_hit_rate.lua --uncovered
  ```
- **测试指标与表现**:
  - **总规则数**: 198 条规则（涵盖 16 个防护分类）
  - **攻击检出率 (TP)**: 100.0% (110/110)
  - **良性误报数 (FP)**: 0 (0/40)

### 3. 测试用例库 (`test_payloads.lua`)

- 包含 16 类攻防维度的基准测试载荷，分为两大集合：
  - **attacks**: 包含真实渗透、编码绕过、混淆畸变等攻击样本（如多重 URL 编码、反弹 shell、LDAP 逻辑注入、JNDI 绕过等）。
  - **legitimate**: 包含容易产生误报的合法业务载荷（如包含技术关键词的搜索词、带数学比较符号的评论、K8s 健康检查端点、正常用户邮箱与 JSON 数据包等）。

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
