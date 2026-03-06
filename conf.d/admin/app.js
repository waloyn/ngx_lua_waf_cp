const { createApp } = Vue;

createApp({
    data() {
        return {
            currentPage: 'dashboard',
            isLoading: false,
            toast: {
                show: false,
                message: '',
                type: 'info'
            },
            modal: {
                show: false,
                title: '',
                content: '',
                type: 'rule'
            },
            
            // Dashboard data
            dashboardStats: {
                totalRequests: 0,
                blockedRequests: 0,
                blockRate: '0%'
            },
            chartInstances: {},

            // Rules data
            rules: [],

            // Black/White lists data
            listContents: {
                blackIp: '',
                whiteIp: '',
                whitehost: ''
            },

            // Logs data
            logs: [],
            logQuery: {
                host: '127.0.0.1',
                date: new Date().toISOString().split('T')[0]
            },

            // Settings data
            configContent: ''
        };
    },
    methods: {
        showToast(message, type = 'info') {
            this.toast.message = message;
            this.toast.type = type;
            this.toast.show = true;
            setTimeout(() => {
                this.toast.show = false;
            }, 3000);
        },
        async apiRequest(url, options = {}, silent = false) {
            try {
                if (!silent) this.isLoading = true;
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
                
                return data.data !== undefined ? data.data : data;
            } catch (error) {
                console.error('API Request Error:', url, error);
                if (!silent) this.showToast(error.message, 'error');
                throw error;
            } finally {
                if (!silent) this.isLoading = false;
            }
        },
        formatNumber(num) {
            if (num == null) return '0';
            if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
            if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
            return num.toString();
        },
        formatDate(dateStr) {
            if (!dateStr) return '-';
            const date = new Date(dateStr);
            return date.toLocaleString('zh-CN');
        },
        switchPage(page) {
            this.currentPage = page;
            this.loadPageData(page);
            
            // Fix Chart.js interaction bug when un-hiding via v-show
            if (page === 'dashboard') {
                this.$nextTick(() => {
                    Object.values(this.chartInstances).forEach(chart => {
                        if (chart) {
                            chart.resize();
                            chart.update('none'); // silent update to refresh event listeners
                        }
                    });
                });
            }
        },
        async loadPageData(page) {
            switch(page) {
                case 'dashboard':
                    await this.loadDashboardData();
                    break;
                case 'rules':
                    await this.loadRules();
                    break;
                case 'blackwhitelist':
                    await this.loadBlackWhiteLists();
                    break;
                case 'settings':
                    await this.loadConfig();
                    break;
            }
        },

        // --- Dashboard Methods ---
        async loadDashboardData(silent = false) {
            try {
                const stats = await this.apiRequest('/api/stats', {}, silent);
                if (!stats) return;

                const totalReq = stats.total_requests || stats.totalRequests || 0;
                const blockedReq = stats.blocked_requests || stats.blockedRequests || 0;
                
                this.dashboardStats.totalRequests = totalReq;
                this.dashboardStats.blockedRequests = blockedReq;
                this.dashboardStats.blockRate = totalReq > 0 
                    ? ((blockedReq / totalReq) * 100).toFixed(2) + '%'
                    : '0%';

                const attackTypes = stats.attackTypes || stats.attack_types || stats.attackType || {};
                const systemTypes = stats.systemTypes || stats.os_distribution || stats.osDistribution || {};
                const hosts = stats.hosts || stats.host_distribution || stats.hostDistribution || {};
                const statusCodes = stats.statusCodes || stats.status_codes || stats.status_distribution || {};
                let topIps = stats.topIps || stats.top_ips || stats.topIp || {};
                
                if (Array.isArray(topIps)) {
                    const topIpsObj = {};
                    topIps.forEach(item => {
                        if (item.ip && item.count) topIpsObj[item.ip] = item.count;
                    });
                    topIps = topIpsObj;
                }

                this.$nextTick(() => {
                    if (this.currentPage !== 'dashboard') return;

                    const hasData = Object.keys(attackTypes).length || Object.keys(systemTypes).length || Object.keys(hosts).length || Object.keys(statusCodes).length || Object.keys(topIps).length;
                    
                    if (!hasData) {
                        this.drawPieChart('systemTypeChart', {'Windows': 120, 'Linux': 85, 'Mac OS': 43, 'Android': 67, 'iOS': 38}, '系统类型');
                        this.drawPieChart('hostChart', {'example.com': 150, 'api.example.com': 98, 'www.example.com': 76, 'admin.example.com': 45}, 'HOST');
                        this.drawBarChart('statusCodeChart', {'200': 1250, '403': 156, '404': 89, '500': 23, '502': 12}, '状态码');
                        this.drawBarChart('topIpChart', {'192.168.1.100': 234, '10.0.0.50': 189, '172.16.0.25': 156, '192.168.1.101': 134, '10.0.0.51': 112, '192.168.1.102': 98, '172.16.0.26': 87, '10.0.0.52': 76, '192.168.1.103': 65, '10.0.0.53': 54}, '请求次数');
                    } else {
                        this.drawPieChart('systemTypeChart', systemTypes, '系统类型');
                        this.drawPieChart('hostChart', hosts, 'HOST');
                        this.drawBarChart('statusCodeChart', statusCodes, '状态码');
                        
                        const topIpsData = Object.entries(topIps)
                            .sort((a, b) => b[1] - a[1])
                            .slice(0, 10)
                            .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {});
                        this.drawBarChart('topIpChart', topIpsData, '请求次数');
                    }
                });

            } catch (error) {
                console.error('Failed to load dashboard data:', error);
            }
        },
        drawPieChart(refName, data, label) {
            const canvas = this.$refs[refName];
            if (!canvas) return;
            
            const entries = Object.entries(data);
            
            if (entries.length === 0) {
                if (this.chartInstances[refName]) {
                    this.chartInstances[refName].destroy();
                    delete this.chartInstances[refName];
                }
                const ctx = canvas.getContext('2d');
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                ctx.fillStyle = '#9ca3af';
                ctx.font = '14px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('暂无数据', canvas.offsetWidth / 2, canvas.offsetHeight / 2 || 150);
                return;
            }

            const labels = entries.map(([name]) => name);
            const values = entries.map(([, value]) => value);

            if (this.chartInstances[refName]) {
                const chart = this.chartInstances[refName];
                chart.data.labels = labels;
                chart.data.datasets[0].data = values;
                chart.update();
            } else {
                this.chartInstances[refName] = new Chart(canvas, {
                    type: 'pie',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: values,
                            backgroundColor: [
                                'rgb(102, 126, 234)', 'rgb(118, 75, 162)', 'rgb(240, 147, 251)',
                                'rgb(79, 172, 254)', 'rgb(67, 233, 123)', 'rgb(250, 112, 154)',
                                'rgb(254, 225, 64)', 'rgb(48, 207, 208)', 'rgb(168, 237, 234)',
                                'rgb(254, 214, 227)', 'rgb(196, 113, 245)', 'rgb(250, 113, 205)'
                            ],
                            borderWidth: 2,
                            borderColor: '#ffffff'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'right' }
                        }
                    }
                });
            }
        },
        drawBarChart(refName, data, label) {
            const canvas = this.$refs[refName];
            if (!canvas) return;
            
            const entries = Object.entries(data);

            if (entries.length === 0) {
                if (this.chartInstances[refName]) {
                    this.chartInstances[refName].destroy();
                    delete this.chartInstances[refName];
                }
                const ctx = canvas.getContext('2d');
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                ctx.fillStyle = '#9ca3af';
                ctx.font = '14px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('暂无数据', canvas.offsetWidth / 2, canvas.offsetHeight / 2 || 150);
                return;
            }

            const labels = entries.map(([name]) => name);
            const values = entries.map(([, value]) => value);

            if (this.chartInstances[refName]) {
                const chart = this.chartInstances[refName];
                chart.data.labels = labels;
                chart.data.datasets[0].data = values;
                chart.data.datasets[0].label = label;
                chart.update();
            } else {
                this.chartInstances[refName] = new Chart(canvas, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: label,
                            data: values,
                            backgroundColor: 'rgba(102, 126, 234, 0.8)',
                            borderColor: 'rgb(102, 126, 234)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } }
                    }
                });
            }
        },

        // --- Rules Methods ---
        async loadRules() {
            try {
                const rulesData = await this.apiRequest('/api/rules');
                if (!rulesData || typeof rulesData !== 'object') {
                    this.rules = [];
                    return;
                }
                this.rules = Object.entries(rulesData).map(([key, rule]) => ({
                    key: key,
                    file: rule.file || (key + '.lua'),
                    name: rule.name || key,
                    desc: rule.desc || '',
                    level: rule.level || 'medium',
                    position: rule.position || 'uri,body',
                    enabled: rule.enabled !== false
                }));
            } catch (error) {
                console.error('加载规则失败:', error);
                this.rules = [];
            }
        },
        async toggleRule(file, enabled) {
            try {
                await this.apiRequest(`/api/rules/${file}`, {
                    method: 'PUT',
                    body: JSON.stringify({ enabled })
                });
                this.showToast(`规则已${enabled ? '启用' : '禁用'}，请重载配置使其生效`, 'success');
            } catch (error) {
                this.showToast('操作失败: ' + error.message, 'error');
                await this.loadRules();
            }
        },
        async viewRule(file) {
            try {
                const data = await this.apiRequest(`/api/rules/${file}`);
                this.modal.title = `规则内容 - ${file}`;
                this.modal.content = data.content;
                this.modal.type = 'rule';
                this.modal.show = true;
            } catch (error) {
                this.showToast('加载规则内容失败', 'error');
            }
        },
        async reloadConfig() {
            try {
                await this.apiRequest('/api/reload-config', { method: 'POST' });
                this.showToast('配置已重载', 'success');        
            } catch (error) {
                this.showToast('重载失败', 'error');
            }
        },

        // --- Lists Methods ---
        async loadBlackWhiteLists() {
            try {
                const [blacklist, whitelist, hostlist] = await Promise.all([
                    this.apiRequest('/api/read-file?file=blackIp').catch(()=>''),
                    this.apiRequest('/api/read-file?file=whiteIp').catch(()=>''),
                    this.apiRequest('/api/read-file?file=whitehost').catch(()=>'')
                ]);
                this.listContents.blackIp = blacklist?.content || blacklist || '';
                this.listContents.whiteIp = whitelist?.content || whitelist || '';
                this.listContents.whitehost = hostlist?.content || hostlist || '';
            } catch (error) {
                this.showToast('加载黑白名单失败', 'error');
            }
        },
        async saveFile(file, content) {
            try {
                await this.apiRequest('/api/save-file', {
                    method: 'POST',
                    body: JSON.stringify({ file, content })
                });
                this.showToast(`保存 ${file} 成功`, 'success');
            } catch (error) {
                this.showToast('保存失败: ' + error.message, 'error');
            }
        },

        // --- Logs Methods ---
        async loadLogs() {
            try {
                const logsData = await this.apiRequest(`/api/logs?host=${this.logQuery.host}&date=${this.logQuery.date}&limit=100`);
                let parsedLogs = [];
                if (Array.isArray(logsData)) {
                    parsedLogs = logsData.map(line => {
                        try { return typeof line === 'string' ? JSON.parse(line) : line; } catch (e) { return null; }
                    }).filter(log => log !== null);
                }
                this.logs = parsedLogs;
            } catch (error) {
                this.logs = [];
                this.showToast('加载日志失败', 'error');
            }
        },
        viewLogDetail(log) {
            this.modal.title = '日志详情';
            this.modal.content = JSON.stringify(log, null, 2);
            this.modal.type = 'log';
            this.modal.show = true;
        },

        // --- Settings Methods ---
        async loadConfig() {
            try {
                const response = await fetch('/api/read-file?file=waf.conf');
                const result = await response.json();
                if (response.ok && result.data) {
                    this.configContent = result.data.content || result.data;
                } else {
                    const fileResponse = await fetch('../waf.conf');
                    if (fileResponse.ok) {
                        this.configContent = await fileResponse.text();
                    } else {
                        throw new Error('无法加载配置文件');
                    }
                }
            } catch (error) {
                this.configContent = '# 加载失败\n# 请检查文件路径和权限';
            }
        },

        // --- Auth ---
        async checkAuth() {
            try {
                await this.apiRequest('/api/stats', {}, true);
            } catch (error) {
                window.location.href = 'login.html';
            }
        },
        async logout() {
            if (!confirm('确定要退出登录吗?')) return;
            try {
                await this.apiRequest('/api/logout', { method: 'POST' });
                window.location.href = 'login.html';
            } catch (error) {
                this.showToast('退出失败', 'error');
            }
        }
    },
    mounted() {
        this.checkAuth();
        this.loadPageData(this.currentPage);
        
        // Timer for dashboard
        setInterval(() => {
            if (this.currentPage === 'dashboard') {
                this.loadDashboardData(true);
            }
        }, 30000);
    }
}).mount('#app');