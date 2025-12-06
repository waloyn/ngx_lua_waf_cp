# WAF 管理后台

## 简介

这是一个轻量、简洁、现代化的 WAF 管理后台，使用原生 HTML5 + CSS3 + JavaScript 开发，无需任何重型框架。

## 特点

- ✅ **轻量级**: 无框架依赖，纯原生实现
- ✅ **现代化**: 采用现代 CSS3 特性，渐变色设计
- ✅ **响应式**: 适配各种屏幕尺寸
- ✅ **单页应用**: 客户端路由，无刷新切换
- ✅ **简洁美观**: 清晰的视觉层次，优雅的交互

## 文件结构

```
conf.d/admin/
├── index.html      # 主页面（仪表盘、规则、IP、日志、设置）
├── login.html      # 登录页面
├── styles.css      # 全局样式
├── app.js          # 主应用逻辑
├── login.js        # 登录逻辑
└── README.md       # 说明文档
```

## 功能模块

### 1. 登录页面 (login.html)
- 用户名密码登录
- 记住我功能
- 渐变背景设计

### 2. 仪表盘
- 实时统计数据展示
- 总请求数、拦截请求、拦截率
- 攻击类型分布图表（Canvas 绘制）
- 系统运行状态

### 3. 规则管理
- 查看所有检测规则
- 启用/禁用规则（开关按钮）
  - 点击开关切换规则状态
  - 自动更新 `conf.d/waf.conf` 中的 `exp_` 配置项
  - `on` = 启用，`off` = 禁用
  - 切换后需要重载配置才能生效
- 查看规则详细内容
- 重载配置（使规则状态生效）

### 4. 黑白名单
- IP 黑名单（直接文本编辑）
- IP 白名单（直接文本编辑）
- HOST 白名单（域名白名单）
- 支持 CIDR 格式（如 192.168.1.0/24）
- 每行一个 IP 或域名
- 三列布局展示

### 5. 攻击日志
- 按域名和日期查询
- 日志列表展示
- 查看日志详情（JSON 格式）

### 6. 系统设置
- 在线编辑配置文件
- 保存配置

## 设计特色

### 配色方案
- 主色调: 紫色渐变 (#667eea → #764ba2)
- 成功色: 绿色 (#10b981)
- 警告色: 橙色 (#f59e0b)
- 危险色: 红色 (#ef4444)
- 信息色: 蓝色 (#3b82f6)

### UI 组件
- **卡片**: 圆角、阴影、分层设计
- **按钮**: 渐变背景、悬停效果
- **表格**: 斑马纹、悬停高亮
- **徽章**: 圆角、半透明背景
- **开关**: 自定义 Toggle Switch
- **Toast**: 右上角通知提示
- **加载动画**: 旋转 Spinner

### 交互设计
- 平滑过渡动画
- 悬停状态反馈
- 点击波纹效果
- 表单焦点高亮

## API 接口

后台调用以下 API 接口：

```
POST   /api/login                    # 登录
POST   /api/logout                   # 登出
GET    /api/stats                    # 统计数据
GET    /api/rules                    # 规则列表
GET    /api/rules/{file}             # 规则内容
PUT    /api/rules/{file}             # 更新规则
POST   /api/reload-config            # 重载配置
GET    /api/whitelist                # 白名单
POST   /api/whitelist                # 添加白名单
DELETE /api/whitelist                # 删除白名单
GET    /api/blacklist                # 黑名单
POST   /api/blacklist                # 添加黑名单
DELETE /api/blacklist                # 删除黑名单
GET    /api/logs                     # 查询日志
GET    /api/read-file?file=          # 读取文件
POST   /api/save-file                # 保存文件
```

## 使用说明

### 访问地址
```
http://localhost:9520/
```

### 默认登录
根据后端配置的用户名密码登录

### 开发调试
1. 打开浏览器开发者工具
2. 查看 Console 面板的日志输出
3. 查看 Network 面板的 API 请求
4. 访问 `http://localhost:9520/debug.html` 使用调试工具测试 API

### 常见问题

#### 1. 规则列表无法加载
- 检查 `/api/rules` 接口是否正常返回
- 确认 `utils/api.lua` 中的 `getRules()` 函数能正确读取规则文件
- 检查 `rules/` 目录下的 `.lua` 文件是否存在

#### 2. 配置文件无法加载
- 检查 `/api/read-file?file=waf.conf` 接口
- 确认 `conf.d/waf.conf` 文件存在且有读取权限
- 检查 `utils/api.lua` 中的 `readFile()` 函数

#### 3. 保存配置失败
- 确认 `conf.d/waf.conf` 文件有写入权限
- 检查 `utils/api.lua` 中的 `saveFile()` 函数
- 查看 Nginx 错误日志

## 浏览器兼容性

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## 技术栈

- **HTML5**: 语义化标签
- **CSS3**: Flexbox、Grid、渐变、动画
- **JavaScript ES6+**: 
  - Async/Await
  - Fetch API
  - Template Literals
  - Arrow Functions
  - Destructuring
  - Modules (未使用，保持简单)

## 性能优化

- 最小化 DOM 操作
- 事件委托
- 防抖节流（可扩展）
- 按需加载数据
- Canvas 图表绘制

## 安全特性

- CSRF 防护（Cookie HttpOnly）
- XSS 防护（内容转义）
- 会话超时自动跳转
- API 请求统一拦截

## 扩展建议

如需扩展功能，可以：

1. **添加新页面**: 在 `pages` 对象中添加渲染函数
2. **添加新 API**: 在 `apiRequest` 基础上封装
3. **自定义主题**: 修改 CSS 变量
4. **添加图表库**: 引入 Chart.js 等轻量库
5. **添加表单验证**: 使用原生 Constraint Validation API

## 维护说明

- 代码注释清晰，易于理解
- 模块化设计，便于扩展
- 无外部依赖，减少维护成本
- 遵循 Web 标准，长期可用

## License

MIT License
