# 规则管理功能说明

## 功能概述

规则管理模块允许管理员查看、启用和禁用 WAF 检测规则。规则状态保存在 `conf.d/waf.conf` 配置文件中。

## 规则状态配置

### 配置文件位置
```
e:/website/openresty/waf/conf.d/waf.conf
```

### 配置格式
```ini
# 检测规则
exp_backup = "on"       # 开启备份路径检测规则
exp_cmd = "on"          # 开启命令注入检测规则
exp_dns = "on"          # 开启DNS攻击检测规则
exp_ldap = "on"         # 开启LDAP注入检测规则
exp_path = "on"         # 开启路径遍历检测规则
exp_sensitive = "on"    # 开启敏感信息检测规则
exp_sqli = "on"         # 开启SQL注入检测规则
exp_ssrf = "on"         # 开启SSRF攻击检测规则
exp_xss = "on"          # 开启跨站脚本攻击检测规则
exp_xxe = "on"          # 开启XML外部实体攻击检测规则
exp_bot = "off"         # 关闭恶意机器人检测规则
```

### 配置项说明
- **配置键**: `exp_` + 规则文件名（不含 .lua 后缀）
- **配置值**: 
  - `"on"` - 启用规则
  - `"off"` - 禁用规则

## 使用流程

### 1. 查看规则列表

访问管理后台的"规则管理"页面：
```
http://localhost:9520/#rules
```

规则列表显示：
- 规则名称
- 描述
- 危险等级（高/中/低）
- 检测位置（URI/Body/Cookie）
- 当前状态（启用/禁用）
- 操作按钮

### 2. 切换规则状态

#### 方法 A: 使用开关按钮
1. 找到要修改的规则
2. 点击状态列的开关按钮
3. 系统自动更新配置文件
4. 显示成功提示

#### 方法 B: 批量修改
1. 直接编辑配置文件（系统设置页面）
2. 修改对应的 `exp_` 配置项
3. 保存配置文件

### 3. 重载配置

规则状态修改后，需要重载配置才能生效：

1. 点击"重载配置"按钮
2. 系统执行 `nginx -s reload`
3. 新的规则状态立即生效

## 技术实现

### 前端流程

```javascript
// 1. 用户点击开关
toggleRule(file, enabled)

// 2. 发送 API 请求
PUT /api/rules/{file}
Body: { "enabled": true/false }

// 3. 显示结果
showToast("规则已启用/禁用")
```

### 后端流程

```lua
-- 1. 接收请求
router.lua: PUT /api/rules/{file}

-- 2. 调用 API
api.switchRule(file, enabled)

-- 3. 更新配置文件
-- 读取 waf.conf
-- 查找 exp_{ruleName} = "on/off"
-- 替换为新值
-- 写回文件

-- 4. 返回结果
response({ success = true })
```

### 配置文件更新逻辑

```lua
function switchRule(ruleFile, enabled)
    -- 1. 提取规则名称
    local ruleName = ruleFile:match("(.+)%.lua$")
    
    -- 2. 构建配置键
    local ruleKey = "exp_" .. ruleName
    
    -- 3. 确定新值
    local newValue = enabled and "\"on\"" or "\"off\""
    
    -- 4. 读取配置文件
    local content = readFile("waf.conf")
    
    -- 5. 替换配置值
    local pattern = ruleKey .. "%s*=%s*\"[^\"]*\""
    local newContent = string.gsub(content, pattern, 
                                   ruleKey .. " = " .. newValue)
    
    -- 6. 写回文件
    writeFile("waf.conf", newContent)
    
    return true
end
```

## API 接口

### 获取规则列表
```
GET /api/rules
```

**响应示例**:
```json
{
  "code": 200,
  "data": {
    "sqli": {
      "file": "sqli.lua",
      "name": "Sql Injection",
      "desc": "SQL注入检测",
      "level": "high",
      "position": "uri,body,cookie",
      "enabled": true
    },
    "xss": {
      "file": "xss.lua",
      "name": "XSS",
      "desc": "跨站脚本攻击检测",
      "level": "medium",
      "position": "uri,body",
      "enabled": false
    }
  }
}
```

### 切换规则状态
```
PUT /api/rules/{file}
Content-Type: application/json

{
  "enabled": true
}
```

**响应示例**:
```json
{
  "code": 200,
  "data": {
    "success": true
  }
}
```

### 查看规则内容
```
GET /api/rules/{file}
```

**响应示例**:
```json
{
  "code": 200,
  "data": {
    "content": "local _M = {\n  name = \"SQL Injection\",\n  ...\n}"
  }
}
```

## 测试工具

### 规则切换测试页面
```
http://localhost:9520/test-switch.html
```

功能：
- 加载规则列表
- 测试规则切换
- 验证配置文件
- 查看操作日志

### 使用步骤
1. 访问测试页面
2. 点击"加载规则"
3. 选择一个规则进行测试
4. 点击"启用"或"禁用"按钮
5. 点击"验证配置"检查结果
6. 查看操作日志

## 常见问题

### Q1: 切换规则后没有生效？
**A**: 需要点击"重载配置"按钮，或执行 `nginx -s reload`

### Q2: 提示"操作失败"？
**A**: 检查：
1. 配置文件是否有写入权限
2. 规则文件名是否正确
3. 查看 Nginx 错误日志

### Q3: 配置文件格式错误？
**A**: 确保配置格式为：
```ini
exp_rulename = "on"
```
注意：
- 等号两边可以有空格
- 值必须用双引号包裹
- 只能是 "on" 或 "off"

### Q4: 规则状态显示不正确？
**A**: 
1. 刷新页面重新加载
2. 检查配置文件内容
3. 使用测试工具验证

## 安全注意事项

### 文件权限
确保以下文件可读写：
```
conf.d/waf.conf
```

### 操作审计
所有规则状态变更都会记录在 Nginx 日志中：
```
[INFO] Switching rule: sqli to on
[INFO] Successfully updated rule status: sqli
```

### 配置备份
建议在修改前备份配置文件：
```bash
copy conf.d\waf.conf conf.d\waf.conf.backup
```

## 最佳实践

### 1. 测试环境验证
在生产环境修改前，先在测试环境验证：
1. 切换规则状态
2. 重载配置
3. 测试应用功能
4. 确认无误后再应用到生产

### 2. 分批启用规则
不要一次性启用所有规则：
1. 先启用高危规则（SQL注入、XSS）
2. 观察一段时间
3. 逐步启用其他规则
4. 根据误报情况调整

### 3. 监控误报
启用新规则后：
1. 查看攻击日志
2. 识别误报情况
3. 调整规则或添加白名单
4. 持续优化

### 4. 定期审查
定期检查规则状态：
1. 每月审查一次
2. 根据威胁情况调整
3. 更新规则内容
4. 优化检测逻辑

## 故障排查

### 检查配置文件
```bash
# 查看配置文件
type conf.d\waf.conf

# 搜索特定规则
findstr "exp_sqli" conf.d\waf.conf
```

### 查看日志
```bash
# 查看错误日志
type logs\error.log

# 实时查看
tail -f logs\error.log
```

### 测试 API
```bash
# 获取规则列表
curl http://localhost:9520/api/rules

# 切换规则状态
curl -X PUT http://localhost:9520/api/rules/sqli.lua ^
     -H "Content-Type: application/json" ^
     -d "{\"enabled\":true}"
```

## 相关文档

- [使用说明](README.md)
- [故障排查](TROUBLESHOOTING.md)
- [调试指南](DEBUG_GUIDE.md)
- [更新日志](CHANGELOG.md)
