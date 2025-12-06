# 黑白名单管理说明

## 功能概述

黑白名单模块允许管理员通过直接编辑文本的方式管理 IP 黑白名单和域名白名单。

## 三种名单类型

### 1. IP 黑名单 (blackIp)
**文件位置**: `conf.d/blackIp`

**作用**: 
- 黑名单中的 IP 将被直接拦截
- 不进行任何规则检测
- 返回 403 Forbidden

**格式**:
```
192.168.1.100
10.0.0.50
172.16.0.0/16
```

**使用场景**:
- 已知的恶意 IP
- 频繁攻击的来源
- 需要永久封禁的 IP

### 2. IP 白名单 (whiteIp)
**文件位置**: `conf.d/whiteIp`

**作用**:
- 白名单中的 IP 完全放行
- 不进行任何 WAF 检测
- 优先级最高

**格式**:
```
192.168.1.100
10.0.0.0/8
172.16.0.1
```

**使用场景**:
- 内部办公网络
- 可信任的合作伙伴
- 监控系统
- 开发测试环境

### 3. HOST 白名单 (whitehost)
**文件位置**: `conf.d/whitehost`

**作用**:
- 白名单中的域名不进行 WAF 检测
- 基于 HTTP Host 头判断

**格式**:
```
example.com
www.example.com
api.example.com
```

**使用场景**:
- 内部管理域名
- API 接口域名
- 静态资源域名
- 不需要防护的域名

## CIDR 格式说明

### 什么是 CIDR？
CIDR (Classless Inter-Domain Routing) 是一种 IP 地址表示方法，可以表示一个 IP 地址段。

### 常用 CIDR 示例

| CIDR 表示 | IP 范围 | 可用 IP 数量 |
|-----------|---------|-------------|
| 192.168.1.0/24 | 192.168.1.0 - 192.168.1.255 | 256 |
| 192.168.0.0/16 | 192.168.0.0 - 192.168.255.255 | 65,536 |
| 10.0.0.0/8 | 10.0.0.0 - 10.255.255.255 | 16,777,216 |
| 172.16.0.0/12 | 172.16.0.0 - 172.31.255.255 | 1,048,576 |
| 192.168.1.0/28 | 192.168.1.0 - 192.168.1.15 | 16 |
| 192.168.1.0/30 | 192.168.1.0 - 192.168.1.3 | 4 |

### CIDR 计算器
- /32 = 1 个 IP
- /31 = 2 个 IP
- /30 = 4 个 IP
- /29 = 8 个 IP
- /28 = 16 个 IP
- /27 = 32 个 IP
- /26 = 64 个 IP
- /25 = 128 个 IP
- /24 = 256 个 IP

## 使用方法

### 方法 1: 通过管理后台

1. **访问黑白名单页面**
   ```
   http://localhost:9520/#blackwhitelist
   ```

2. **编辑名单**
   - 在对应的文本框中编辑
   - 每行一个 IP 地址或域名
   - 支持 CIDR 格式

3. **保存更改**
   - 点击对应的"保存"按钮
   - 系统自动保存到文件

4. **重载配置**
   - 保存后需要重载 Nginx 配置
   - 点击"重载配置"按钮或执行 `nginx -s reload`

### 方法 2: 直接编辑文件

1. **编辑文件**
   ```bash
   # 编辑黑名单
   notepad conf.d\blackIp
   
   # 编辑白名单
   notepad conf.d\whiteIp
   
   # 编辑 HOST 白名单
   notepad conf.d\whitehost
   ```

2. **保存文件**
   - 确保每行一个条目
   - 删除空行和注释

3. **重载配置**
   ```bash
   nginx -s reload
   ```

## 配置示例

### IP 黑名单示例
```
# 单个恶意 IP
203.0.113.100

# 恶意 IP 段
198.51.100.0/24

# 多个单独的 IP
192.0.2.50
192.0.2.51
192.0.2.52
```

### IP 白名单示例
```
# 办公网络
192.168.1.0/24

# VPN 网关
10.0.0.1

# 监控系统
172.16.0.100
172.16.0.101

# 开发环境
127.0.0.1
```

### HOST 白名单示例
```
# 内部管理域名
admin.internal.com

# API 域名
api.example.com

# 静态资源
static.example.com
cdn.example.com

# 开发环境
dev.example.com
test.example.com
```

## 优先级顺序

WAF 检查顺序（从高到低）：

1. **IP 白名单** - 完全放行，不检测
2. **HOST 白名单** - 域名放行，不检测
3. **IP 黑名单** - 直接拦截
4. **动态封禁 IP** - 攻击行为触发的封禁
5. **CC 攻击检测** - 访问频率限制
6. **规则检测** - WAF 规则匹配

## 测试工具

### 黑白名单测试页面
```
http://localhost:9520/test-blackwhitelist.html
```

**功能**:
- 加载现有配置
- 编辑名单内容
- 保存更改
- 验证保存结果
- 查看操作日志

### 使用步骤
1. 访问测试页面
2. 点击"加载所有名单"
3. 编辑需要修改的名单
4. 点击对应的"保存"按钮
5. 点击"验证所有名单"检查结果

## API 接口

### 读取名单
```
GET /api/read-file?file={fileName}
```

**参数**:
- `fileName`: `blackIp` | `whiteIp` | `whitehost`

**响应**:
```json
{
  "code": 200,
  "data": {
    "content": "192.168.1.100\n10.0.0.0/8\n..."
  }
}
```

### 保存名单
```
POST /api/save-file
Content-Type: application/json

{
  "file": "blackIp",
  "content": "192.168.1.100\n10.0.0.0/8\n..."
}
```

**响应**:
```json
{
  "code": 200,
  "data": {
    "message": "File saved successfully",
    "success": true
  }
}
```

## 注意事项

### 1. 文件格式
- 使用 UTF-8 编码
- 每行一个条目
- 不要有多余的空格
- 可以有空行（会被忽略）

### 2. CIDR 格式
- 确保 CIDR 格式正确
- 错误的格式会导致解析失败
- 建议使用在线 CIDR 计算器验证

### 3. 重载配置
- 修改后必须重载 Nginx
- 否则更改不会生效
- 使用 `nginx -s reload` 或管理后台的"重载配置"按钮

### 4. 性能考虑
- 名单过长会影响性能
- 建议使用 CIDR 合并 IP 段
- 定期清理无效条目

### 5. 安全建议
- 不要将自己的 IP 加入黑名单
- 谨慎使用白名单，避免绕过防护
- 定期审查名单内容
- 记录重要的添加/删除操作

## 常见问题

### Q1: 修改后没有生效？
**A**: 需要重载 Nginx 配置
```bash
nginx -s reload
```

### Q2: CIDR 格式错误？
**A**: 检查格式是否正确
- 正确: `192.168.1.0/24`
- 错误: `192.168.1.0-24`
- 错误: `192.168.1.0/33`

### Q3: 如何测试 IP 是否在名单中？
**A**: 
1. 查看 Nginx 日志
2. 使用不同 IP 访问测试
3. 查看 WAF 日志

### Q4: 白名单和黑名单冲突？
**A**: 白名单优先级更高，会覆盖黑名单

### Q5: 如何批量添加 IP？
**A**: 
1. 准备 IP 列表文件
2. 复制粘贴到文本框
3. 保存

## 最佳实践

### 1. 定期审查
- 每月审查一次名单
- 删除过期的条目
- 更新 IP 段

### 2. 使用 CIDR
- 合并连续的 IP
- 减少条目数量
- 提高匹配效率

### 3. 分类管理
- 添加注释说明（虽然会被忽略）
- 按来源分组
- 记录添加原因

### 4. 备份配置
```bash
# 备份黑名单
copy conf.d\blackIp conf.d\blackIp.backup

# 备份白名单
copy conf.d\whiteIp conf.d\whiteIp.backup

# 备份 HOST 白名单
copy conf.d\whitehost conf.d\whitehost.backup
```

### 5. 监控日志
```bash
# 查看被拦截的 IP
findstr "Black IP" logs\error.log

# 查看白名单放行
findstr "White IP" logs\error.log
```

## 故障排查

### 检查文件权限
```bash
# 确保文件可读写
icacls conf.d\blackIp
icacls conf.d\whiteIp
icacls conf.d\whitehost
```

### 验证文件内容
```bash
# 查看文件内容
type conf.d\blackIp
type conf.d\whiteIp
type conf.d\whitehost
```

### 测试 IP 匹配
```bash
# 使用 curl 测试
curl -H "X-Real-IP: 192.168.1.100" http://localhost:9520/
```

## 相关文档

- [使用说明](README.md)
- [规则管理](RULE_MANAGEMENT.md)
- [故障排查](TROUBLESHOOTING.md)
- [调试指南](DEBUG_GUIDE.md)
