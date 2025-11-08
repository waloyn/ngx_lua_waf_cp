# 调试指南

## 规则管理加载失败问题

### 问题描述
规则管理页面显示"加载失败"，但 API 接口响应正常。

### 调试步骤

#### 1. 打开浏览器开发者工具
- **Chrome/Edge**: 按 `F12` 或 `Ctrl+Shift+I`
- **Firefox**: 按 `F12` 或 `Ctrl+Shift+K`
- **Safari**: `Cmd+Option+I` (需先在偏好设置中启用开发菜单)

#### 2. 查看控制台日志
切换到 **Console** 标签，查看以下日志：

```
开始加载规则...
API 返回数据: {...}
数据类型: object
是否为对象: true
键数量: 10
开始转换规则数据...
处理规则: sqli {...}
处理规则: xss {...}
...
转换后的规则数组: [...]
规则数量: 10
规则表格渲染完成
```

#### 3. 检查网络请求
切换到 **Network** 标签：

1. 刷新页面
2. 找到 `/api/rules` 请求
3. 点击查看详情
4. 检查：
   - **Status**: 应该是 `200 OK`
   - **Response**: 查看返回的 JSON 数据
   - **Headers**: 检查 Content-Type 是否为 `application/json`

#### 4. 使用测试工具

**方法 A: 使用规则测试页面**
```
http://localhost:9520/test-rules.html
```
这个页面会：
- 自动测试 API
- 显示原始响应数据
- 逐步解析和渲染规则
- 显示每一步的详细信息

**方法 B: 使用系统检查工具**
```
http://localhost:9520/check.html
```
自动检查所有 API 接口是否正常。

**方法 C: 使用 API 调试工具**
```
http://localhost:9520/debug.html
```
手动测试各个 API 接口。

### 常见错误及解决方案

#### 错误 1: "规则数据为空"
**原因**: API 返回 `null` 或 `undefined`

**检查**:
1. 后端是否正常运行
2. 路由配置是否正确
3. 查看 Nginx 错误日志

**解决**:
```bash
# 重启 Nginx
nginx -s reload

# 查看错误日志
tail -f e:/website/openresty/logs/error.log
```

#### 错误 2: "规则数据格式错误"
**原因**: API 返回的不是对象类型

**检查**:
1. API 响应的 Content-Type
2. 响应数据是否被正确解析为 JSON

**解决**:
检查 `utils/router.lua` 中的响应格式：
```lua
ngx.header.content_type = "application/json; charset=utf-8"
ngx.say(cjson.encode({
    code = 200,
    data = rules,
    timestamp = ngx.time()
}))
```

#### 错误 3: "TypeError: rules.map is not a function"
**原因**: 尝试对对象使用数组方法

**解决**: 已修复，使用 `Object.entries()` 转换

#### 错误 4: "ReferenceError: WAF_CONFIG is not defined"
**原因**: 前端代码引用了后端的全局变量

**解决**: 已修复，改为从 API 返回的数据中获取状态

### 数据流程图

```
浏览器                    Nginx/OpenResty              后端 Lua
  |                            |                          |
  |-- GET /api/rules --------->|                          |
  |                            |-- router.lua ----------->|
  |                            |                          |
  |                            |<-- api.getRules() -------|
  |                            |    返回规则对象          |
  |                            |    {                     |
  |                            |      sqli: {...},        |
  |                            |      xss: {...}          |
  |                            |    }                     |
  |                            |                          |
  |<-- JSON 响应 --------------|                          |
  |    {                       |                          |
  |      code: 200,            |                          |
  |      data: {...}           |                          |
  |    }                       |                          |
  |                            |                          |
  |-- app.js 处理 ------------>|                          |
  |   1. apiRequest()          |                          |
  |   2. loadRules()           |                          |
  |   3. Object.entries()      |                          |
  |   4. 渲染表格              |                          |
```

### 验证 API 响应格式

正确的 API 响应应该是：

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
      "enabled": true
    }
  },
  "timestamp": 1699430400
}
```

### 手动测试 API

使用 curl 或浏览器直接访问：

```bash
# 使用 curl
curl http://localhost:9520/api/rules

# 或在浏览器中直接访问
http://localhost:9520/api/rules
```

### 检查后端日志

```bash
# Windows
type e:\website\openresty\logs\error.log

# 实时查看（需要安装 tail 工具）
tail -f e:\website\openresty\logs\error.log
```

查找以下关键信息：
- `Failed to load rule module`
- `WAF loading rules`
- Lua 错误堆栈

### 前端调试技巧

#### 在控制台手动测试

```javascript
// 1. 测试 API 请求
fetch('/api/rules')
  .then(r => r.json())
  .then(d => console.log(d));

// 2. 测试数据转换
const testData = {
  sqli: { name: "SQL Injection", desc: "Test" },
  xss: { name: "XSS", desc: "Test" }
};
const rules = Object.entries(testData).map(([key, rule]) => ({
  key, ...rule
}));
console.log(rules);

// 3. 检查 DOM 元素
console.log(document.getElementById('rulesTableBody'));
```

#### 设置断点

1. 打开 **Sources** 标签
2. 找到 `app.js` 文件
3. 在 `loadRules()` 函数的第一行设置断点
4. 刷新页面，逐步执行代码

### 性能分析

如果加载很慢：

1. 打开 **Performance** 标签
2. 点击录制按钮
3. 刷新页面
4. 停止录制
5. 查看时间线，找出瓶颈

### 常用调试命令

```javascript
// 查看全局变量
console.log(window);

// 查看所有函数
console.log(Object.getOwnPropertyNames(window).filter(p => typeof window[p] === 'function'));

// 清空控制台
console.clear();

// 查看对象结构
console.dir(object);

// 查看调用堆栈
console.trace();
```

### 联系支持

如果问题仍未解决，请提供：

1. **浏览器控制台截图** (包含所有日志)
2. **Network 标签截图** (显示 API 请求和响应)
3. **Nginx 错误日志** (最后 50 行)
4. **系统环境信息**:
   - 操作系统版本
   - 浏览器版本
   - OpenResty 版本
5. **重现步骤**

---

## 快速检查清单

- [ ] 浏览器控制台无错误
- [ ] `/api/rules` 返回 200 状态码
- [ ] 响应数据格式正确 (JSON 对象)
- [ ] 响应包含规则数据
- [ ] `rulesTableBody` 元素存在
- [ ] JavaScript 文件加载成功
- [ ] CSS 文件加载成功
- [ ] Nginx 正常运行
- [ ] 后端 Lua 文件无语法错误

全部通过后，规则管理应该能正常工作！
