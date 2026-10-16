// 检查用户认证状态
async function checkAuth() {
    try {
        const response = await fetch('/api/stats');
        if (response.status === 401) {
            window.location.href = '/login.html';
            return false;
        }
        return true;
    } catch (error) {
        console.error('认证检查失败:', error);
        return false;
    }
}

// 加载统计数据
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        if (data.code === 200) {
            // 更新基础统计数据
            document.getElementById('totalRequests').textContent = data.data.total_requests || 0;
            document.getElementById('blockedAttacks').textContent = data.data.blocked_requests || 0;
            document.getElementById('blockedIPs').textContent = data.data.blocked_ips || 0;
            document.getElementById('ccAttacks').textContent = data.data.cc_attacks || 0;

            // 更新操作系统分布图表
            const osCtx = document.getElementById('osDistribution').getContext('2d');
            new Chart(osCtx, {
                type: 'pie',
                data: {
                    labels: Object.keys(data.data.os_distribution),
                    datasets: [{
                        data: Object.values(data.data.os_distribution),
                        backgroundColor: [
                            'rgb(255, 99, 132)',
                            'rgb(54, 162, 235)',
                            'rgb(255, 206, 86)',
                            'rgb(75, 192, 192)',
                            'rgb(153, 102, 255)',
                            'rgb(255, 159, 64)',
                            'rgb(129, 76, 87)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });

            // 更新状态码分布图表
            const statusCtx = document.getElementById('statusDistribution').getContext('2d');
            new Chart(statusCtx, {
                type: 'bar',
                data: {
                    labels: Object.keys(data.data.status_distribution),
                    datasets: [{
                        label: '请求数',
                        data: Object.values(data.data.status_distribution),
                        backgroundColor: 'rgb(54, 162, 235)'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });

            // 更新域名访问分布图表
            const hostCtx = document.getElementById('hostDistribution').getContext('2d');
            new Chart(hostCtx, {
                type: 'pie',
                data: {
                    labels: Object.keys(data.data.host_distribution),
                    datasets: [{
                        data: Object.values(data.data.host_distribution),
                        backgroundColor: [
                            'rgb(255, 99, 132)',
                            'rgb(54, 162, 235)',
                            'rgb(255, 206, 86)',
                            'rgb(75, 192, 192)',
                            'rgb(153, 102, 255)',
                            'rgb(255, 159, 64)',
                            'rgb(129, 76, 87)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });

            // 更新IP访问排名表格
            const topIPsTable = document.getElementById('topIPs');
            topIPsTable.innerHTML = data.data.top_ips.map(item => `
                <tr>
                    <td>${item.ip}</td>
                    <td>${item.count}</td>
                </tr>
            `).join('');
        }
    } catch (error) {
        console.error('加载统计数据失败:', error);
    }
}

// 加载请求趋势数据
async function loadRequestTrend() {
    try {
        const response = await fetch('/api/stats/request_trend');
        const data = await response.json();
        if (data.code === 200) {
            const ctx = document.getElementById('requestTrend').getContext('2d');
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.data.labels,
                    datasets: [{
                        label: '请求量',
                        data: data.data.values,
                        fill: false,
                        borderColor: 'rgb(75, 192, 192)',
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }
    } catch (error) {
        console.error('加载请求趋势数据失败:', error);
    }
}

// 加载攻击分布数据
async function loadAttackDistribution() {
    try {
        const response = await fetch('/api/stats/attack_distribution');
        const data = await response.json();
        if (data.code === 200) {
            const ctx = document.getElementById('attackDistribution').getContext('2d');
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: data.data.labels,
                    datasets: [{
                        data: data.data.values,
                        backgroundColor: [
                            'rgb(255, 99, 132)',
                            'rgb(54, 162, 235)',
                            'rgb(255, 206, 86)',
                            'rgb(75, 192, 192)',
                            'rgb(153, 102, 255)',
                            'rgb(255, 159, 64)',
                            'rgb(129, 76, 87)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }
    } catch (error) {
        console.error('加载攻击分布数据失败:', error);
    }
}

// 处理登出
async function handleLogout() {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST'
        });
        if (response.ok) {
            window.location.href = '/login.html';
        }
    } catch (error) {
        console.error('登出失败:', error);
    }
}

// 初始化页面
async function initializeDashboard() {
    if (await checkAuth()) {
        loadStats();
        // loadRequestTrend();
        // loadAttackDistribution();

        // 设置定时刷新
        setInterval(loadStats, 30000); // 每30秒更新一次统计数据

        // 绑定登出按钮事件
        document.querySelector('.nav-link[href="#logout"]').addEventListener('click', (e) => {
            e.preventDefault();
            handleLogout();
        });
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', initializeDashboard);