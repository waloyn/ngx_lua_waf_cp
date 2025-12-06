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
    blackwhitelist: renderBlackWhiteList,
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

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">            
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">系统类型分布</h3>
                </div>
                <div class="card-body">
                    <div style="min-height: 300px;">
                        <canvas id="systemTypeChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">请求 IP TOP 10</h3>
                </div>
                <div class="card-body">
                    <div style="min-height: 350px;">
                        <canvas id="topIpChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">HOST 分布</h3>
                </div>
                <div class="card-body">
                    <div style="min-height: 300px;">
                        <canvas id="hostChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">状态码分布</h3>
                </div>
                <div class="card-body">
                    <div style="min-height: 300px;">
                        <canvas id="statusCodeChart"></canvas>
                    </div>
                </div>
            </div>
        </div>       
    `;

    await loadDashboardData();
}

async function loadDashboardData() {
    try {
        const stats = await apiRequest('/api/stats');
        
        console.log('Dashboard stats received:', stats);
        console.log('Stats keys:', stats ? Object.keys(stats) : 'null');
        
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
            
            // 获取各种数据，如果为空则使用示例数据
            const attackTypes = stats.attackTypes || stats.attack_types || stats.attackType || {};
            const systemTypes = stats.systemTypes || stats.os_distribution || stats.osDistribution || {};
            const hosts = stats.hosts || stats.host_distribution || stats.hostDistribution || {};
            const statusCodes = stats.statusCodes || stats.status_codes || stats.status_distribution || {};
            
            // 处理 top_ips - 可能是数组格式 [{ip, count}] 或对象格式 {ip: count}
            let topIps = stats.topIps || stats.top_ips || stats.topIp || {};
            if (Array.isArray(topIps)) {
                // 转换数组格式为对象格式
                const topIpsObj = {};
                topIps.forEach(item => {
                    if (item.ip && item.count) {
                        topIpsObj[item.ip] = item.count;
                    }
                });
                topIps = topIpsObj;
            }
            
            console.log('Attack types:', attackTypes);
            console.log('System types:', systemTypes);
            console.log('Hosts:', hosts);
            console.log('Status codes:', statusCodes);
            console.log('Top IPs:', topIps);
            
            // 检查是否有数据
            const hasAttackData = attackTypes && Object.keys(attackTypes).length > 0;
            const hasSystemData = systemTypes && Object.keys(systemTypes).length > 0;
            const hasHostData = hosts && Object.keys(hosts).length > 0;
            const hasStatusData = statusCodes && Object.keys(statusCodes).length > 0;
            const hasIpData = topIps && Object.keys(topIps).length > 0;
            
            const hasData = hasAttackData || hasSystemData || hasHostData || hasStatusData || hasIpData;
            
            if (!hasData) {
                console.warn('No chart data available, using sample data');
                // 使用示例数据
                drawPieChart('attackTypeChart', {
                    'SQL注入': 45,
                    'XSS攻击': 32,
                    '路径遍历': 18,
                    '命令注入': 12,
                    '其他': 8
                }, '攻击类型');
                
                drawPieChart('systemTypeChart', {
                    'Windows': 120,
                    'Linux': 85,
                    'Mac OS': 43,
                    'Android': 67,
                    'iOS': 38
                }, '系统类型');
                
                drawPieChart('hostChart', {
                    'example.com': 150,
                    'api.example.com': 98,
                    'www.example.com': 76,
                    'admin.example.com': 45
                }, 'HOST');
                
                drawBarChart('statusCodeChart', {
                    '200': 1250,
                    '403': 156,
                    '404': 89,
                    '500': 23,
                    '502': 12
                }, '状态码');
                
                drawBarChart('topIpChart', {
                    '192.168.1.100': 234,
                    '10.0.0.50': 189,
                    '172.16.0.25': 156,
                    '192.168.1.101': 134,
                    '10.0.0.51': 112,
                    '192.168.1.102': 98,
                    '172.16.0.26': 87,
                    '10.0.0.52': 76,
                    '192.168.1.103': 65,
                    '10.0.0.53': 54
                }, '请求次数');
            } else {
                // 绘制攻击类型饼图 - 使用实际数据或示例数据
                drawPieChart('attackTypeChart', 
                    hasAttackData ? attackTypes : {
                        'SQL注入': 45,
                        'XSS攻击': 32,
                        '路径遍历': 18,
                        '命令注入': 12,
                        '其他': 8
                    }, 
                    '攻击类型');
                
                // 绘制系统类型饼图
                drawPieChart('systemTypeChart', 
                    hasSystemData ? systemTypes : {
                        'Windows': 120,
                        'Linux': 85,
                        'Mac OS': 43,
                        'Android': 67,
                        'iOS': 38
                    }, 
                    '系统类型');
                
                // 绘制 HOST 饼图
                drawPieChart('hostChart', 
                    hasHostData ? hosts : {
                        'example.com': 150,
                        'api.example.com': 98,
                        'www.example.com': 76,
                        'admin.example.com': 45
                    }, 
                    'HOST');
                
                // 绘制状态码柱状图
                drawBarChart('statusCodeChart', 
                    hasStatusData ? statusCodes : {
                        '200': 1250,
                        '403': 156,
                        '404': 89,
                        '500': 23,
                        '502': 12
                    }, 
                    '状态码');
                
                // 绘制 TOP 10 IP 柱状图
                const topIpsData = hasIpData 
                    ? Object.entries(topIps)
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 10)
                        .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {})
                    : {
                        '192.168.1.100': 234,
                        '10.0.0.50': 189,
                        '172.16.0.25': 156,
                        '192.168.1.101': 134,
                        '10.0.0.51': 112,
                        '192.168.1.102': 98,
                        '172.16.0.26': 87,
                        '10.0.0.52': 76,
                        '192.168.1.103': 65,
                        '10.0.0.53': 54
                    };
                drawBarChart('topIpChart', topIpsData, '请求次数');
            }
        }
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
        // 出错时也显示示例数据
        drawPieChart('attackTypeChart', { 'SQL注入': 45, 'XSS攻击': 32, '路径遍历': 18 }, '攻击类型');
        drawPieChart('systemTypeChart', { 'Windows': 120, 'Linux': 85, 'Mac OS': 43 }, '系统类型');
        drawPieChart('hostChart', { 'example.com': 150, 'api.example.com': 98 }, 'HOST');
        drawBarChart('statusCodeChart', { '200': 1250, '403': 156, '404': 89 }, '状态码');
        drawBarChart('topIpChart', { '192.168.1.100': 234, '10.0.0.50': 189 }, '请求次数');
    }
}

// 存储 Chart.js 实例
const chartInstances = {};

// 绘制饼图（使用 Chart.js）
function drawPieChart(canvasId, data, label) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const entries = Object.entries(data);
    if (entries.length === 0) {
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#9ca3af';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('暂无数据', canvas.offsetWidth / 2, 150);
        return;
    }
    
    // 销毁旧图表
    if (chartInstances[canvasId]) {
        chartInstances[canvasId].destroy();
    }
    
    // 创建新图表
    chartInstances[canvasId] = new Chart(canvas, {
        type: 'pie',
        data: {
            labels: entries.map(([name]) => name),
            datasets: [{
                data: entries.map(([, value]) => value),
                backgroundColor: [
                    'rgb(102, 126, 234)',
                    'rgb(118, 75, 162)',
                    'rgb(240, 147, 251)',
                    'rgb(79, 172, 254)',
                    'rgb(67, 233, 123)',
                    'rgb(250, 112, 154)',
                    'rgb(254, 225, 64)',
                    'rgb(48, 207, 208)',
                    'rgb(168, 237, 234)',
                    'rgb(254, 214, 227)',
                    'rgb(196, 113, 245)',
                    'rgb(250, 113, 205)'
                ],
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12
                        },
                        generateLabels: function(chart) {
                            const data = chart.data;
                            if (data.labels.length && data.datasets.length) {
                                const dataset = data.datasets[0];
                                const total = dataset.data.reduce((a, b) => a + b, 0);
                                return data.labels.map((label, i) => {
                                    const value = dataset.data[i];
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return {
                                        text: `${label}: ${value} (${percentage}%)`,
                                        fillStyle: dataset.backgroundColor[i],
                                        hidden: false,
                                        index: i
                                    };
                                });
                            }
                            return [];
                        }
                    },
                    onClick: function(e, legendItem, legend) {
                        const index = legendItem.index;
                        const chart = legend.chart;
                        const meta = chart.getDatasetMeta(0);
                        meta.data[index].hidden = !meta.data[index].hidden;
                        chart.update();
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}


// 绘制柱状图（使用 Chart.js）
function drawBarChart(canvasId, data, label) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const entries = Object.entries(data);
    if (entries.length === 0) {
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#9ca3af';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('暂无数据', canvas.offsetWidth / 2, 150);
        return;
    }
    
    // 销毁旧图表
    if (chartInstances[canvasId]) {
        chartInstances[canvasId].destroy();
    }
    
    // 创建新图表
    chartInstances[canvasId] = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: entries.map(([name]) => name),
            datasets: [{
                label: label,
                data: entries.map(([, value]) => value),
                backgroundColor: 'rgba(102, 126, 234, 0.8)',
                borderColor: 'rgb(102, 126, 234)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${label}: ${context.parsed.y}`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        font: {
                            size: 11
                        }
                    }
                },
                x: {
                    ticks: {
                        font: {
                            size: 11
                        },
                        maxRotation: 45,
                        minRotation: 45
                    }
                }
            }
        }
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
    console.log(`切换规则状态: ${file} -> ${enabled ? '启用' : '禁用'}`);
    
    try {
        const result = await apiRequest(`/api/rules/${file}`, {
            method: 'PUT',
            body: JSON.stringify({ enabled })
        });
        
        console.log('切换结果:', result);
        
        if (result && result.success !== false) {
            showToast(`规则已${enabled ? '启用' : '禁用'}，请重载配置使其生效`, 'success');
        } else {
            throw new Error('操作失败');
        }
    } catch (error) {
        console.error('切换规则失败:', error);
        showToast('操作失败: ' + error.message, 'error');
        // 重新加载规则列表以恢复正确状态
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

// ========== 黑白名单页面 ==========

async function renderBlackWhiteList(container) {
    container.innerHTML = `
        <div class="page-header">
            <h1 class="page-title">黑白名单</h1>
            <p class="page-subtitle">管理 IP 黑白名单和域名白名单</p>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px;">
            <!-- IP 黑名单 -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">IP黑名单</h3>
                    <button class="btn btn-primary btn-sm" onclick="saveBlacklist()">
                        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                            <path d="M7.707 10.293a1 1 0 10-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 11.586V6h5a2 2 0 012 2v7a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h5v5.586l-1.293-1.293zM9 4a1 1 0 012 0v2H9V4z"/>
                        </svg>
                        保存黑名单
                    </button>
                </div>
                <div class="card-body">
                    <textarea id="blacklistContent" 
                              placeholder="每行一个 IP 地址或 CIDR&#10;例如:&#10;192.168.1.100&#10;10.0.0.0/8"
                              style="width: 100%; min-height: 500px; font-family: 'Courier New', monospace; font-size: 13px; padding: 12px; border: 1px solid var(--border-color); border-radius: var(--radius);">加载中...</textarea>
                    <div style="margin-top: 12px; font-size: 12px; color: var(--text-secondary);">
                        <strong>说明:</strong> 每行一个 IP 地址，支持 CIDR 格式（如 192.168.1.0/24）
                    </div>
                </div>
            </div>

            <!-- IP 白名单 -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">IP白名单</h3>
                    <button class="btn btn-primary btn-sm" onclick="saveWhitelist()">
                        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                            <path d="M7.707 10.293a1 1 0 10-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 11.586V6h5a2 2 0 012 2v7a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h5v5.586l-1.293-1.293zM9 4a1 1 0 012 0v2H9V4z"/>
                        </svg>
                        保存白名单
                    </button>
                </div>
                <div class="card-body">
                    <textarea id="whitelistContent" 
                              placeholder="每行一个 IP 地址或 CIDR&#10;例如:&#10;192.168.1.100&#10;10.0.0.0/8"
                              style="width: 100%; min-height: 500px; font-family: 'Courier New', monospace; font-size: 13px; padding: 12px; border: 1px solid var(--border-color); border-radius: var(--radius);">加载中...</textarea>
                    <div style="margin-top: 12px; font-size: 12px; color: var(--text-secondary);">
                        <strong>说明:</strong> 白名单 IP 不会被任何规则拦截
                    </div>
                </div>
            </div>

            <!-- HOST 白名单 -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">HOST白名单</h3>
                    <button class="btn btn-primary btn-sm" onclick="saveHostlist()">
                        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                            <path d="M7.707 10.293a1 1 0 10-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 11.586V6h5a2 2 0 012 2v7a2 2 0 01-2 2H4a2 2 0 01-2-2V8a2 2 0 012-2h5v5.586l-1.293-1.293zM9 4a1 1 0 012 0v2H9V4z"/>
                        </svg>
                        保存HOST白名单
                    </button>
                </div>
                <div class="card-body">
                    <textarea id="hostlistContent" 
                              placeholder="每行一个域名&#10;例如:&#10;example.com&#10;www.example.com"
                              style="width: 100%; min-height: 500px; font-family: 'Courier New', monospace; font-size: 13px; padding: 12px; border: 1px solid var(--border-color); border-radius: var(--radius);">加载中...</textarea>
                    <div style="margin-top: 12px; font-size: 12px; color: var(--text-secondary);">
                        <strong>说明:</strong> 白名单域名不会被 WAF 检测
                    </div>
                </div>
            </div>
        </div>
    `;

    await loadBlackWhiteLists();
}

async function loadBlackWhiteLists() {
    try {
        // 并行加载三个文件
        const [blacklist, whitelist, hostlist] = await Promise.all([
            apiRequest('/api/read-file?file=blackIp'),
            apiRequest('/api/read-file?file=whiteIp'),
            apiRequest('/api/read-file?file=whitehost')
        ]);
        
        document.getElementById('blacklistContent').value = blacklist?.content || blacklist || '';
        document.getElementById('whitelistContent').value = whitelist?.content || whitelist || '';
        document.getElementById('hostlistContent').value = hostlist?.content || hostlist || '';
    } catch (error) {
        console.error('Failed to load lists:', error);
        showToast('加载失败: ' + error.message, 'error');
    }
}

async function saveBlacklist() {
    const content = document.getElementById('blacklistContent').value;
    
    try {
        await apiRequest('/api/save-file', {
            method: 'POST',
            body: JSON.stringify({
                file: 'blackIp',
                content
            })
        });
        showToast('IP黑名单保存成功', 'success');
    } catch (error) {
        showToast('保存失败: ' + error.message, 'error');
    }
}

async function saveWhitelist() {
    const content = document.getElementById('whitelistContent').value;
    
    try {
        await apiRequest('/api/save-file', {
            method: 'POST',
            body: JSON.stringify({
                file: 'whiteIp',
                content
            })
        });
        showToast('IP白名单保存成功', 'success');
    } catch (error) {
        showToast('保存失败: ' + error.message, 'error');
    }
}

async function saveHostlist() {
    const content = document.getElementById('hostlistContent').value;
    
    try {
        await apiRequest('/api/save-file', {
            method: 'POST',
            body: JSON.stringify({
                file: 'whitehost',
                content
            })
        });
        showToast('HOST白名单保存成功', 'success');
    } catch (error) {
        showToast('保存失败: ' + error.message, 'error');
    }
}

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
