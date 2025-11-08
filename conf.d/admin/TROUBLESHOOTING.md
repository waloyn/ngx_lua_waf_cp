# 故障排查指南

## 问题 1: 规则管理无法加载规则列表

### 错误信息
```
Failed to load rules: TypeError: rules.map is not a function
```

### 原因
后端 API `/api/rules` 返回的是对象格式，而前端期望的是数组格式。

### 解决方案
已修复前端代码，将对象转换为数组：

```javascript
// 将对象转换为数组
const rules = Object.entries(rulesData).map(([key, rule]) => ({
    key: key,
    file: rule.file,
    name: rule.name,
    desc: rule.desc,
    // ...
}));
```

### 验证方法
1. 访问 `http://localhost:9520/debug.html`
2. 点击"测试规则列表"按钮
3. 检查返回的数据格式

## 问题 2: 系统设置无法加载配置

### 错误信息
```
GET http://localhost:9520/api/read-file?file=conf.d/waf.conf 404 (Not Found)
```

### 原因
1. 文件路径参数错误（应该是 `waf.conf` 而不是 `conf.d/waf.conf`）
2. 后端 `readFile` 函数的白名单中没有包含 `waf.conf`

### 解决方案

#### 后端修复 (utils/api.lua)
```lua
function _M.readFile(fileName)
    local allowedFiles = {
        blackIp = true,
        whiteIp = true,
        whitehost = true,
        ["waf.conf"] = true  -- 添加这一行
    }
    -- ...
end

function _M.saveFile(fileName, content)
    local allowedFiles = {
        blackIp = true,
        whiteIp = true,
        whitehost = true,
        ["waf.conf"] = true  -- 添加这一行
    }
    -- ...
end
```

#### 前端修复 (app.js)
```javascript
// 修改文件参数
const response = await fetch('/api/read-file?file=waf.conf');

// 保存时也使用正确的文件名
await apiRequest('/api/save-file', {
    method: 'POST',
    body: JSON.stringify({
        file: 'waf.conf',  // 不是 'conf.d/waf.conf'
        content
    })
});
```

### 验证方法
1. 访问 `http://localhost:9520/debug.html`
2. 点击"测试读取配置"按钮
3. 应该能看到配置文件内容

## 问题 3: API 响应格式不一致

### 问题描述
不同的 API 返回的数据结构不一致：
- 有些返回 `{ code: 200, data: {...} }`
- 有些直接返回数据

### 解决方案
前端 `apiRequest` 函数已修复，兼容两种格式：

```javascript
// 返回 data.data 或 data（兼容不同的响应格式）
return data.data !== undefined ? data.data : data;
```

## 调试步骤

### 1. 检查 Nginx 是否正常运行
```bash
# Windows
tasklist | findstr nginx

# 检查端口
netstat -ano | findstr :9520
```

### 2. 查看 Nginx 错误日志
```bash
# 日志位置
e:/website/openresty/logs/error.log
```

### 3. 测试 API 接口
访问 `http://localhost:9520/debug.html` 使用调试工具

### 4. 检查文件权限
确保以下文件可读写：
- `e:/website/openresty/waf/conf.d/waf.conf`
- `e:/website/openresty/waf/conf.d/blackIp`
- `e:/website/openresty/waf/conf.d/whiteIp`
- `e:/website/openresty/waf/conf.d/whitehost`

### 5. 重启 Nginx
```bash
# Windows
nginx -s reload

# 或完全重启
nginx -s stop
nginx
```

## 常见错误代码

### 401 Unauthorized
- 未登录或会话过期
- 解决：重新登录

### 404 Not Found
- API 路由不存在
- 文件路径错误
- 解决：检查 URL 和文件路径

### 500 Internal Server Error
- 后端 Lua 代码错误
- 文件权限问题
- 解决：查看 Nginx 错误日志

## 性能优化建议

### 1. 启用浏览器缓存
在 `http.conf` 中添加：
```nginx
location ~* \.(css|js|jpg|png|gif|ico)$ {
    expires 7d;
    add_header Cache-Control "public, immutable";
}
```

### 2. 压缩静态资源
```nginx
gzip on;
gzip_types text/css application/javascript application/json;
gzip_min_length 1000;
```

### 3. 减少 API 请求频率
修改自动刷新间隔：
```javascript
// 从 30 秒改为 60 秒
setInterval(() => {
    if (currentPage === 'dashboard') {
        loadDashboardData();
    }
}, 60000);
```

## 联系支持

如果问题仍未解决：
1. 收集错误日志
2. 记录重现步骤
3. 检查浏览器控制台错误
4. 提供系统环境信息
