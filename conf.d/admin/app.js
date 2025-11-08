// ========== 全局工具函数 ==========

// Toast 通知
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type}`;
    
    setTimeout(() => toast.classList.add('show'), 10);
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// 显示/隐藏加载动画
function showLoading() {
    document.getElementById('loading').classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loading').classList.add('hidden');
}

// API 请求封装
async function apiRequest(url, options = {}) {
    try {
        showLoading();
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            if (response.status === 401) {
                window.location.href = 'login.html';
                return null;
            }
            const errorMsg = data.data?.message || data.message || '请求失败';
            throw new Error(errorMsg);
        }
        
        // 返回 data.data 或 data（兼容不同的响应格式）
        return data.data !== undefined ? data.data : data;
    } catch (error) {
        console.error('API Request Error:', url, error);
        showToast(error.message, 'error');
        throw error;
    } finally {
        hideLoading();
    }
}

// 格式化数字
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

// 格式化日期
function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleString('zh-CN');
}

// ========== 页面路由 ==========

const pages = {
    dashboard: renderDashboard,
    rules: renderRules,
    'ip-list': renderIPList,
    logs: renderLogs,
    settings: renderSettings
};

let currentPage = 'dashboard';

// 导航切换
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const page = item.dataset.page;
        
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
        
        currentPage = page;
        renderPage(page);
    });
});

// 渲染页面
function renderPage(page) {
    const app = document.getElementById('app');
    if (pages[page]) {
        pages[page](app);
    }
}

// ========== 仪表盘页面 ==========

async function renderDashboard(container) {
    container.innerHTML = `
        <div class="page-header">
            <h1 class="page-title">仪表盘</h1>
            <p class="page-subtitle">系统运行状态概览</p>
        </div>

        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="stat-icon primary">
                    <svg width="24" height="24" viewBox="0 0 20 20" fill="currentColor">
                        <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z"/>
                    </svg>
                </div>
                <div class="stat-content">
                    <div class="stat-label">总请求数</div>
                    <div class="stat-value" id="totalRequests">-</div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon danger">
                    <svg width="24" height="24" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z"/>
                    </svg>
                </div>
                <div class="stat-content">
                    <div class="stat-label">拦截请求</div>
                    <div class="stat-value" id="blockedRequests">-</div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon warning">
                    <svg width="24" height="24" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"/>
                    </svg>
                </div>
                <div class="stat-content">
                    <div class="stat-label">拦截率</div>
                    <div class="stat-value" id="blockRate">-</div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon success">
                    <svg width="24" height="24" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"/>
                    </svg>
                </div>
                <div class="stat-content">
                    <div class="stat-label">系统状态</div>
                    <div class="stat-value" style="font-size: 16px;">
                        <span class="badge badge-success">运行中</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 class="card-title">攻击类型分布</h3>
            </div>
            <div class="card-body">
                <div id="attackChart" style="min-height: 300px;">
                    <canvas id="chartCanvas"></canvas>
                </div>
            </div>
        </div>
    `;

    await loadDashboardData();
}

async function loadDashboardData() {
    try {
        const stats = await apiRequest('/api/stats');
        
        if (stats) {
            // 适配后端返回的字段名
            const totalReq = stats.total_requests || stats.totalRequests || 0;
            const blockedReq = stats.blocked_requests || stats.blockedRequests || 0;
            
            document.getElementById('totalRequests').textContent = formatNumber(totalReq);
            document.getElementById('blockedRequests').textContent = formatNumber(blockedReq);
            
            const rate = totalReq > 0 
                ? ((blockedReq / totalReq) * 100).toFixed(2) + '%'
                : '0%';
            document.getElementById('blockRate').textContent = rate;
            
            // 绘制简单的攻击类型图表
            drawAttackChart(stats.attackTypes || stats.os_distribution || {});
        }
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
    }
}

function drawAttackChart(data) {
    const canvas = document.getElementById('chartCanvas');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    canvas.width = canvas.offsetWidth;
    canvas.height = 300;
    
    const entries = Object.entries(data);
    if (entries.length === 0) {
        ctx.fillStyle = '#9ca3af';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('暂无数据', canvas.width / 2, canvas.height / 2);
        return;
    }
    
    const total = entries.reduce((sum, [, value]) => sum + value, 0);
    const barWidth = (canvas.width - 100) / entries.length;
    const maxValue = Math.max(...entries.map(([, v]) => v));
    
    entries.forEach(([name, value], index) => {
        const barHeight = (value / maxValue) * (canvas.height - 80);
        const x = 50 + index * barWidth;
        const y = canvas.height - 50 - barHeight;
        
        // 绘制柱状图
        const gradient = ctx.createLinearGradient(0, y, 0, canvas.height - 50);
        gradient.addColorStop(0, '#667eea');
        gradient.addColorStop(1, '#764ba2');
        
        ctx.fillStyle = gradient;
        ctx.fillRect(x, y, barWidth - 20, barHeight);
        
        // 绘制数值
        ctx.fillStyle = '#111827';
        ctx.font = '12px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(value, x + (barWidth - 20) / 2, y - 5);
        
        // 绘制标签
        ctx.fillStyle = '#6b7280';
        ctx.save();
        ctx.translate(x + (barWidth - 20) / 2, canvas.height - 30);
        ctx.rotate(-Math.PI / 4);
        ctx.textAlign = 'right';
        ctx.fillText(name, 0, 0);
        ctx.restore();
    });
}

// ========== 规则管理页面 ==========

async function renderRules(container) {
    container.innerHTML = `
        <div class="page-header">
            <h1 class="page-title">规则管理</h1>
            <p class="page-subtitle">管理 WAF 检测规则</p>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 class="card-title">规则列表</h3>
                <button class="btn btn-primary btn-sm" onclick="loadRules()">
                    <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z"/>
                    </svg>
                    重载规则
                </button>
            </div>
            <div class="card-body">
                <div class="table-container">
                    <table id="rulesTable">
                        <thead>
                            <tr>
                                <th>规则名称</th>
                                <th>描述</th>
                                <th>危险等级</th>
                                <th>检测位置</th>
                                <th>状态</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="rulesTableBody">
                            <tr><td colspan="6" style="text-align: center;">加载中...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;

    await loadRules();
}

async function loadRules() {
    const tbody = document.getElementById('rulesTableBody');
    
    try {
        console.log('开始加载规则...');
        const rulesData = await apiRequest('/api/rules');
        console.log('API 返回数据:', rulesData);
        console.log('数据类型:', typeof rulesData);
        console.log('是否为对象:', typeof rulesData === 'object');
        console.log('键数量:', rulesData ? Object.keys(rulesData).length : 0);
        
        if (!rulesData) {
            console.error('规则数据为空');
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">规则数据为空</td></tr>';
            return;
        }
        
        if (typeof rulesData !== 'object') {
            console.error('规则数据类型错误:', typeof rulesData);
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">规则数据格式错误</td></tr>';
            return;
        }
        
        const keys = Object.keys(rulesData);
        if (keys.length === 0) {
            console.warn('规则列表为空');
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">暂无规则</td></tr>';
            return;
        }
        
        console.log('开始转换规则数据...');
        // 将对象转换为数组
        const rules = Object.entries(rulesData).map(([key, rule]) => {
            console.log(`处理规则: ${key}`, rule);
            return {
                key: key,
                file: rule.file || (key + '.lua'),
                name: rule.name || key,
                desc: rule.desc || '',
                level: rule.level || 'medium',
                position: rule.position || 'uri,body',
                enabled: rule.enabled !== false
            };
        });
        
        console.log('转换后的规则数组:', rules);
        console.log('规则数量:', rules.length);
        
        // 渲染表格
        tbody.innerHTML = rules.map(rule => `
            <tr>
                <td><strong>${rule.name}</strong></td>
                <td>${rule.desc || '-'}</td>
                <td>
                    <span class="badge ${
                        rule.level === 'high' ? 'badge-danger' : 
                        rule.level === 'medium' ? 'badge-warning' : 
                        'badge-info'
                    }">${rule.level}</span>
                </td>
                <td>${rule.position || '-'}</td>
                <td>
                    <label class="switch">
                        <input type="checkbox" ${rule.enabled ? 'checked' : ''} 
                               onchange="toggleRule('${rule.file}', this.checked)">
                        <span class="slider"></span>
                    </label>
                </td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="viewRule('${rule.file}')">查看</button>
                </td>
            </tr>
        `).join('');
        
        console.log('规则表格渲染完成');
    } catch (error) {
        console.error('加载规则失败:', error);
        console.error('错误堆栈:', error.stack);
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: red;">
                加载失败: ${error.message}<br>
                <small>请打开浏览器控制台查看详细错误信息</small>
            </td></tr>`;
        }
    }
}

async function toggleRule(file, enabled) {
    try {
        await apiRequest(`/api/rules/${file}`, {
            method: 'PUT',
            body: JSON.stringify({ enabled })
        });
        showToast(`规则已${enabled ? '启用' : '禁用'}`, 'success');
    } catch (error) {
        showToast('操作失败', 'error');
        await loadRules();
    }
}

async function viewRule(file) {
    try {
        const data = await apiRequest(`/api/rules/${file}`);
        
        const modal = document.createElement('div');
        modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;';
        modal.innerHTML = `
            <div class="card" style="width: 90%; max-width: 800px; max-height: 80vh; overflow: auto;">
                <div class="card-header">
                    <h3 class="card-title">规则内容 - ${file}</h3>
                    <button class="btn btn-secondary btn-sm" onclick="this.closest('div[style*=fixed]').remove()">关闭</button>
                </div>
                <div class="card-body">
                    <textarea readonly style="width: 100%; min-height: 400px; font-family: 'Courier New', monospace; font-size: 12px;">${data.content}</textarea>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    } catch (error) {
        showToast('加载失败', 'error');
    }
}

async function reloadConfig() {
    try {
        await apiRequest('/api/reload-config', { method: 'POST' });
        showToast('配置已重载', 'success');        
    } catch (error) {
        showToast('重载失败', 'error');
    }
    await loadRules();
}

// ========== IP 管理页面 ==========

async function renderIPList(container) {
    container.innerHTML = `
        <div class="page-header">
            <h1 class="page-title">IP 管理</h1>
            <p class="page-subtitle">管理黑白名单</p>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div class="card">
                <div class="card-header flex-between">
                    <h3 class="card-title">白名单</h3>
                    <button class="btn btn-primary btn-sm" onclick="addIP('white')">添加</button>
                </div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP 地址</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody id="whitelistBody">
                                <tr><td colspan="2" style="text-align: center;">加载中...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header flex-between">
                    <h3 class="card-title">黑名单</h3>
                    <button class="btn btn-primary btn-sm" onclick="addIP('black')">添加</button>
                </div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP 地址</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody id="blacklistBody">
                                <tr><td colspan="2" style="text-align: center;">加载中...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    `;

    await loadIPLists();
}

async function loadIPLists() {
    try {
        const [whitelist, blacklist] = await Promise.all([
            apiRequest('/api/whitelist'),
            apiRequest('/api/blacklist')
        ]);
        
        const whitelistBody = document.getElementById('whitelistBody');
        const blacklistBody = document.getElementById('blacklistBody');
        
        whitelistBody.innerHTML = whitelist && whitelist.length > 0
            ? whitelist.map(ip => `
                <tr>
                    <td>${ip}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="removeIP('white', '${ip}')">删除</button>
                    </td>
                </tr>
            `).join('')
            : '<tr><td colspan="2" style="text-align: center;">暂无数据</td></tr>';
        
        blacklistBody.innerHTML = blacklist && blacklist.length > 0
            ? blacklist.map(ip => `
                <tr>
                    <td>${ip}</td>
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="removeIP('black', '${ip}')">删除</button>
                    </td>
                </tr>
            `).join('')
            : '<tr><td colspan="2" style="text-align: center;">暂无数据</td></tr>';
    } catch (error) {
        console.error('Failed to load IP lists:', error);
    }
}

function addIP(type) {
    const ip = prompt(`请输入要添加到${type === 'white' ? '白' : '黑'}名单的 IP 地址:`);
    if (!ip) return;
    
    const endpoint = type === 'white' ? '/api/whitelist' : '/api/blacklist';
    
    apiRequest(endpoint, {
        method: 'POST',
        body: JSON.stringify({ ip })
    }).then(() => {
        showToast('添加成功', 'success');
        loadIPLists();
    }).catch(() => {
        showToast('添加失败', 'error');
    });
}

function removeIP(type, ip) {
    if (!confirm(`确定要删除 IP: ${ip} 吗?`)) return;
    
    const endpoint = type === 'white' ? '/api/whitelist' : '/api/blacklist';
    
    apiRequest(endpoint, {
        method: 'DELETE',
        body: JSON.stringify({ ip })
    }).then(() => {
        showToast('删除成功', 'success');
        loadIPLists();
    }).catch(() => {
        showToast('删除失败', 'error');
    });
}

// ========== 攻击日志页面 ==========

async function renderLogs(container) {
    const today = new Date().toISOString().split('T')[0];
    
    container.innerHTML = `
        <div class="page-header">
            <h1 class="page-title">攻击日志</h1>
            <p class="page-subtitle">查看攻击记录</p>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 class="card-title">日志查询</h3>
                <div class="flex gap-2">
                    <input type="text" id="logHost" placeholder="域名" value="127.0.0.1" style="width: 200px;">
                    <input type="date" id="logDate" value="${today}" style="width: 150px;">
                    <button class="btn btn-primary btn-sm" onclick="loadLogs()">查询</button>
                </div>
            </div>
            <div class="card-body">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>时间</th>
                                <th>IP</th>
                                <th>攻击类型</th>
                                <th>请求方法</th>
                                <th>URI</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="logsTableBody">
                            <tr><td colspan="6" style="text-align: center;">请选择查询条件</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

async function loadLogs() {
    const host = document.getElementById('logHost').value;
    const date = document.getElementById('logDate').value;
    
    try {
        const logsData = await apiRequest(`/api/logs?host=${host}&date=${date}&limit=100`);
        const tbody = document.getElementById('logsTableBody');
        
        // 处理返回的数据，可能是字符串数组（每行一个JSON）
        let logs = [];
        if (Array.isArray(logsData)) {
            logs = logsData.map(line => {
                try {
                    return typeof line === 'string' ? JSON.parse(line) : line;
                } catch (e) {
                    return null;
                }
            }).filter(log => log !== null);
        }
        
        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">暂无日志</td></tr>';
            return;
        }
        
        tbody.innerHTML = logs.map((log, index) => `
            <tr>
                <td>${formatDate(log.request_time)}</td>
                <td>${log.ip}</td>
                <td><span class="badge badge-danger">${log.attack_type}</span></td>
                <td>${log.http_method}</td>
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${log.request_uri}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="viewLogDetail(${index})">详情</button>
                </td>
            </tr>
        `).join('');
        
        window.currentLogs = logs;
    } catch (error) {
        console.error('Failed to load logs:', error);
        document.getElementById('logsTableBody').innerHTML = '<tr><td colspan="6" style="text-align: center; color: red;">加载失败</td></tr>';
    }
}

function viewLogDetail(index) {
    const log = window.currentLogs[index];
    
    const modal = document.createElement('div');
    modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;';
    modal.innerHTML = `
        <div class="card" style="width: 90%; max-width: 800px; max-height: 80vh; overflow: auto;">
            <div class="card-header">
                <h3 class="card-title">日志详情</h3>
                <button class="btn btn-secondary btn-sm" onclick="this.closest('div[style*=fixed]').remove()">关闭</button>
            </div>
            <div class="card-body">
                <pre style="background: #f3f4f6; padding: 16px; border-radius: 8px; overflow: auto; font-size: 12px;">${JSON.stringify(log, null, 2)}</pre>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

// ========== 系统设置页面 ==========

async function renderSettings(container) {
    container.innerHTML = `
        <div class="page-header">
            <h1 class="page-title">系统设置</h1>
            <p class="page-subtitle">配置 WAF 参数</p>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 class="card-title">配置文件 (waf.conf)</h3>
                <div class="flex gap-2">
                    <button class="btn btn-secondary btn-sm" onclick="reloadConfig()">
                        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z"/>
                        </svg>
                        重载配置
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="saveConfig()">
                        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                            <path d="M7.707 10.293a1 1 0 10-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 11.586V6h5a2 2 0 012 2v7a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h5v5.586l-1.293-1.293zM9 4a1 1 0 012 0v2H9V4z"/>
                        </svg>
                        保存配置
                    </button>
                </div>
            </div>
            <div class="card-body">
                <textarea id="configContent" style="width: 100%; min-height: 500px; font-family: 'Courier New', monospace; font-size: 12px;">加载中...</textarea>
            </div>
        </div>
    `;

    await loadConfig();
}

async function loadConfig() {
    try {
        // 直接读取waf.conf文件内容
        const response = await fetch('/api/read-file?file=waf.conf');
        const result = await response.json();
        
        if (response.ok && result.data) {
            document.getElementById('configContent').value = result.data.content || result.data;
        } else {
            // 如果API不支持，尝试直接读取
            const fileResponse = await fetch('../waf.conf');
            if (fileResponse.ok) {
                const content = await fileResponse.text();
                document.getElementById('configContent').value = content;
            } else {
                throw new Error('无法加载配置文件');
            }
        }
    } catch (error) {
        console.error('Failed to load config:', error);
        showToast('加载配置失败: ' + error.message, 'error');
        document.getElementById('configContent').value = '# 加载失败\n# 请检查文件路径和权限';
    }
}

async function saveConfig() {
    const content = document.getElementById('configContent').value;
    
    try {
        await apiRequest('/api/save-file', {
            method: 'POST',
            body: JSON.stringify({
                file: 'waf.conf',
                content
            })
        });
        showToast('保存成功，请重载配置使其生效', 'success');
    } catch (error) {
        showToast('保存失败: ' + error.message, 'error');
    }
}

// ========== 退出登录 ==========

document.getElementById('logoutBtn').addEventListener('click', async () => {
    if (!confirm('确定要退出登录吗?')) return;
    
    try {
        await apiRequest('/api/logout', { method: 'POST' });
        window.location.href = 'login.html';
    } catch (error) {
        showToast('退出失败', 'error');
    }
});

// ========== 初始化 ==========

// 检查登录状态
async function checkAuth() {
    try {
        await apiRequest('/api/stats');
    } catch (error) {
        window.location.href = 'login.html';
    }
}

checkAuth();
renderPage(currentPage);

// 定时刷新仪表盘数据
setInterval(() => {
    if (currentPage === 'dashboard') {
        loadDashboardData();
    }
}, 30000);
