const { createApp, markRaw } = Vue;


createApp({
    data() {
        return {
            currentPage: 'dashboard',
            isSidebarOpen: false,
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
            statsPeriod: 'day',
            periodOptions: [
                { key: 'day', label: '日 (今日)' },
                { key: 'week', label: '周 (7天)' },
                { key: 'month', label: '月 (30天)' },
                { key: 'hour', label: '当前小时' },
                { key: 'process', label: '启动至今' }
            ],
            dashboardStats: {
                totalRequests: 0,
                blockedRequests: 0,
                vulnRequests: 0,
                ccRequests: 0,
                attackIpsCount: 0,
                vulnIpsCount: 0,
                ccIpsCount: 0,
                attackTypesCount: 0,
                domainCount: 1,
                blockRate: '0%',
                reportTime: '',
                attackTypesList: [],
                attackTargets: { '数据': 0, '应用': 0, '服务器': 0, '文件': 0, '其他': 0 },
                attackTargetsRadar: { labels: ['数据', '其他', '应用', '服务器', '文件'], values: [0, 0, 0, 0, 0], max: 100 },
                attackTrend: { hours: [], vuln: [], cc: [], total: [] },
                attackGeo: [],
                maliciousIps: { all: [], vuln: [], cc: [] },
                securitySummary: {},
                challengeStats: { issued: 0, passed: 0, failed: 0 },
                recentAttacks: []
            },
            trafficProfileData: {
                systemTypes: {},
                hosts: {},
                statusCodes: {},
                topIps: {}
            },
            selectedIpTab: 'all',
            isIpsExpanded: false,
            selectedAttackFilter: '',
            isAttacksExpanded: false,
            showTrafficProfile: true,
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
                host: '',
                date: new Date().toISOString().split('T')[0]
            },

            // Settings data
            configContent: '',

            // Palette tokens
            chartColors: [
                '#6366f1', // Indigo
                '#0d9488', // Teal
                '#f43f5e', // Rose
                '#f59e0b', // Amber
                '#0284c7', // Sky
                '#8b5cf6', // Violet
                '#10b981', // Emerald
                '#475569', // Slate
                '#ec4899', // Pink
                '#eab308', // Yellow
                '#06b6d4', // Cyan
                '#84cc16'  // Lime
            ]
        };
    },
    computed: {
        statsPeriodLabel() {
            switch (this.statsPeriod) {
                case 'day': return '今日';
                case 'week': return '近7天';
                case 'month': return '近30天';
                case 'hour': return '当前小时';
                case 'process': return '启动至今';
                default: return '今日';
            }
        },
        displayedMaliciousIps() {
            const mal = this.dashboardStats.maliciousIps;
            const list = (mal && Array.isArray(mal[this.selectedIpTab])) ? mal[this.selectedIpTab] : [];
            if (!this.isIpsExpanded) {
                return list.slice(0, 10);
            }
            return list;
        },
        totalMaliciousIpsCount() {
            const mal = this.dashboardStats.maliciousIps;
            const list = (mal && Array.isArray(mal[this.selectedIpTab])) ? mal[this.selectedIpTab] : [];
            return list.length;
        },
        displayedRecentAttacks() {
            let list = Array.isArray(this.dashboardStats.recentAttacks) ? this.dashboardStats.recentAttacks : [];
            if (this.selectedAttackFilter) {
                list = list.filter(item => {
                    if (!item) return false;
                    const t = String(item.attack_type || item.type || item.raw_type || item.rule || item.category || '');
                    return t.includes(this.selectedAttackFilter) || this.selectedAttackFilter.includes(t);
                });
            }
            if (!this.isAttacksExpanded) {
                return list.slice(0, 10);
            }
            return list.slice(0, 50);
        },
        totalRecentAttacksCount() {
            let list = Array.isArray(this.dashboardStats.recentAttacks) ? this.dashboardStats.recentAttacks : [];
            if (this.selectedAttackFilter) {
                list = list.filter(item => {
                    if (!item) return false;
                    const t = String(item.attack_type || item.type || item.raw_type || item.rule || item.category || '');
                    return t.includes(this.selectedAttackFilter) || this.selectedAttackFilter.includes(t);
                });
            }
            return list.length;
        }
    },
    methods: {
        toggleSidebar() {
            this.isSidebarOpen = !this.isSidebarOpen;
        },
        closeSidebar() {
            this.isSidebarOpen = false;
        },
        handleKeydown(e) {
            if (e.key === 'Escape' || e.key === 'Esc') {
                if (this.modal.show) {
                    this.modal.show = false;
                } else if (this.isSidebarOpen) {
                    this.isSidebarOpen = false;
                }
            }
        },
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
                const headers = {
                    'Content-Type': 'application/json',
                    ...options.headers
                };
                const method = (options.method || 'GET').toUpperCase();
                if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
                    const csrfToken = sessionStorage.getItem('csrf_token');
                    if (csrfToken) {
                        headers['X-CSRF-Token'] = csrfToken;
                    }
                }
                const response = await fetch(url, {
                    ...options,
                    headers: headers
                });
                
                const data = await response.json();
                
                if (!response.ok) {
                    if (response.status === 401) {
                        sessionStorage.removeItem('csrf_token');
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
            const n = Number(num);
            if (isNaN(n)) return num.toString();
            return n.toLocaleString('en-US');
        },
        formatDate(dateStr) {
            if (!dateStr) return '-';
            const date = new Date(dateStr);
            return isNaN(date.getTime()) ? dateStr : date.toLocaleString('zh-CN');
        },
        switchPage(page) {
            this.currentPage = page;
            this.closeSidebar();
            this.loadPageData(page);
            
            if (page === 'dashboard') {
                this.$nextTick(() => {
                    this.resizeCharts();
                });
            }
        },
        resizeCharts() {
            Object.values(this.chartInstances).forEach(chart => {
                if (chart) {
                    chart.resize();
                    chart.update('none');
                }
            });
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
                case 'logs':
                    await this.loadLogs();
                    break;
                case 'settings':
                    await this.loadConfig();
                    break;
            }
        },

        // --- Dashboard Methods ---
        changeStatsPeriod(period) {
            this.statsPeriod = period;
            this.loadDashboardData(false);
        },
        getMaliciousIpsCount(tab) {
            const mal = this.dashboardStats.maliciousIps;
            const list = mal && Array.isArray(mal[tab]) ? mal[tab] : [];
            return list.length;
        },
        async loadDashboardData(silent = false) {
            try {
                const stats = await this.apiRequest(`/api/stats?period=${encodeURIComponent(this.statsPeriod)}`, {}, silent);
                if (!stats || typeof stats !== 'object') return;

                const toArray = (val) => Array.isArray(val) ? val : [];

                const totalReq = Number(stats.total_requests ?? stats.totalRequests ?? 0) || 0;
                const blockedReq = Number(stats.blocked_requests ?? stats.blockedRequests ?? 0) || 0;
                const vulnReq = Number(stats.vuln_requests ?? stats.vulnRequests ?? 0) || 0;
                const ccReq = Number(stats.cc_requests ?? stats.ccRequests ?? 0) || 0;
                const typesList = toArray(stats.attack_types_list ?? stats.attackTypesList);

                this.dashboardStats.totalRequests = totalReq;
                this.dashboardStats.blockedRequests = blockedReq;
                this.dashboardStats.vulnRequests = vulnReq;
                this.dashboardStats.ccRequests = ccReq;

                const chal = (stats.challenge && typeof stats.challenge === 'object') ? stats.challenge : {};
                this.dashboardStats.challengeStats = {
                    issued: Number(chal.issued ?? stats.challenge_issued ?? 0) || 0,
                    passed: Number(chal.passed ?? stats.challenge_passed ?? 0) || 0,
                    failed: Number(chal.failed ?? stats.challenge_failed ?? 0) || 0
                };

                const rawAttackIpsCount = stats.attack_ips_count ?? stats.attacker_ips_count ?? stats.attackIpsCount ?? 0;
                this.dashboardStats.attackIpsCount = Number(rawAttackIpsCount) || 0;

                const rawVulnIpsCount = stats.vuln_ips_count ?? stats.vulnIpsCount ?? 0;
                this.dashboardStats.vulnIpsCount = Number(rawVulnIpsCount) || 0;

                const rawCcIpsCount = stats.cc_ips_count ?? stats.ccIpsCount ?? 0;
                this.dashboardStats.ccIpsCount = Number(rawCcIpsCount) || 0;

                const rawTypesCount = stats.attack_types_count ?? stats.attackTypesCount;
                this.dashboardStats.attackTypesCount = rawTypesCount != null ? (Number(rawTypesCount) || 0) : typesList.length;

                const rawDomainCount = stats.domain_count ?? stats.domainCount;
                this.dashboardStats.domainCount = Number(rawDomainCount) || 1;

                this.dashboardStats.blockRate = stats.block_rate || stats.blockRate || (totalReq > 0 ? ((blockedReq / totalReq) * 100).toFixed(2) + '%' : '0%');
                this.dashboardStats.reportTime = stats.report_time || stats.reportTime || new Date().toLocaleString();
                this.dashboardStats.attackTypesList = typesList;

                const rawTargets = stats.attack_targets || stats.attackTargets;
                this.dashboardStats.attackTargets = (rawTargets && typeof rawTargets === 'object' && !Array.isArray(rawTargets))
                    ? rawTargets
                    : { '数据': 0, '应用': 0, '服务器': 0, '文件': 0, '其他': 0 };

                const rawRadar = stats.attack_targets_radar || stats.attackTargetsRadar || {};
                this.dashboardStats.attackTargetsRadar = {
                    labels: toArray(rawRadar.labels).length ? rawRadar.labels : ['数据', '其他', '应用', '服务器', '文件'],
                    values: toArray(rawRadar.values).length ? rawRadar.values : [0, 0, 0, 0, 0],
                    max: Number(rawRadar.max) || 100
                };

                const rawTrend = stats.attack_trend || stats.attackTrend || {};
                const trendHours = toArray(rawTrend.hours).length ? rawTrend.hours : Array.from({length: 24}, (_, i) => `${String(i).padStart(2, '0')}:00`);
                this.dashboardStats.attackTrend = {
                    hours: trendHours,
                    vuln: toArray(rawTrend.vuln).length ? rawTrend.vuln : new Array(trendHours.length).fill(0),
                    cc: toArray(rawTrend.cc).length ? rawTrend.cc : new Array(trendHours.length).fill(0),
                    total: toArray(rawTrend.total).length ? rawTrend.total : new Array(trendHours.length).fill(0)
                };

                this.dashboardStats.attackGeo = toArray(stats.attack_geo ?? stats.attackGeo);

                const rawMalicious = stats.malicious_ips || stats.maliciousIps || {};
                this.dashboardStats.maliciousIps = {
                    all: toArray(rawMalicious.all),
                    vuln: toArray(rawMalicious.vuln),
                    cc: toArray(rawMalicious.cc)
                };

                this.dashboardStats.securitySummary = (stats.security_summary && typeof stats.security_summary === 'object' && !Array.isArray(stats.security_summary))
                    ? stats.security_summary
                    : {};

                this.dashboardStats.recentAttacks = toArray(stats.recent_attacks ?? stats.recentAttacks);

                // 流量画像数据
                this.trafficProfileData.systemTypes = (stats.os_distribution && typeof stats.os_distribution === 'object' && !Array.isArray(stats.os_distribution)) ? stats.os_distribution : {};
                this.trafficProfileData.hosts = (stats.host_distribution && typeof stats.host_distribution === 'object' && !Array.isArray(stats.host_distribution)) ? stats.host_distribution : {};
                this.trafficProfileData.statusCodes = (stats.status_distribution && typeof stats.status_distribution === 'object' && !Array.isArray(stats.status_distribution)) ? stats.status_distribution : {};

                let topIps = stats.top_ips || stats.topIps || {};
                if (Array.isArray(topIps)) {
                    const topIpsObj = {};
                    topIps.forEach(item => {
                        if (item && item.ip && item.count) topIpsObj[item.ip] = item.count;
                    });
                    topIps = topIpsObj;
                } else if (typeof topIps !== 'object' || topIps === null) {
                    topIps = {};
                }
                this.trafficProfileData.topIps = topIps;

                // 操作系统统计：合并 unknown
                if (this.trafficProfileData.systemTypes['unknown'] !== undefined || this.trafficProfileData.systemTypes['Unknown'] !== undefined) {
                    const mergedUnknown = (Number(this.trafficProfileData.systemTypes['unknown']) || 0) + (Number(this.trafficProfileData.systemTypes['Unknown']) || 0);
                    delete this.trafficProfileData.systemTypes['unknown'];
                    if (mergedUnknown > 0) {
                        this.trafficProfileData.systemTypes['Unknown'] = mergedUnknown;
                    }
                }

                this.$nextTick(() => {
                    if (this.currentPage === 'dashboard') {
                        this.renderAllCharts();
                    }
                });

            } catch (error) {
                console.error('Failed to load dashboard data:', error);
            }
        },

        renderAllCharts() {
            this.drawAttackTypeChart();
            this.drawRadarChart();
            this.drawLineTrendChart();
            this.drawGeoBarChart();
            if (this.showTrafficProfile) {
                this.renderTrafficCharts();
            }
        },

        // 1. 攻击类型环形图 (Doughnut)
        drawAttackTypeChart() {
            const canvas = this.$refs.attackTypeChart;
            if (!canvas) return;

            const list = Array.isArray(this.dashboardStats.attackTypesList) ? this.dashboardStats.attackTypesList : [];
            if (list.length === 0) {
                if (this.chartInstances['attackTypeChart']) {
                    this.chartInstances['attackTypeChart'].destroy();
                    delete this.chartInstances['attackTypeChart'];
                }
                const ctx = canvas.getContext('2d');
                if (ctx) {
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    ctx.fillStyle = '#94a3b8';
                    ctx.font = '13px sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    const x = (canvas.offsetWidth || canvas.width || 300) / 2;
                    const y = (canvas.offsetHeight || canvas.height || 240) / 2;
                    ctx.fillText('暂无攻击类型记录', x, y);
                }
                return;
            }

            const labels = list.map(item => item.name);
            const values = list.map(item => item.value);
            const percentages = list.map(item => item.percent || '');
            const bgColors = labels.map((_, idx) => this.chartColors[idx % this.chartColors.length]);

            if (this.chartInstances['attackTypeChart']) {
                const chart = this.chartInstances['attackTypeChart'];
                chart.data.labels = labels;
                chart.data.datasets[0].data = values;
                chart.data.datasets[0].backgroundColor = bgColors;
                chart.update();
            } else {
                this.chartInstances['attackTypeChart'] = markRaw(new Chart(canvas, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: values,
                            backgroundColor: bgColors,
                            borderWidth: 2,
                            borderColor: '#ffffff',
                            hoverOffset: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '62%',
                        plugins: {
                            legend: {
                                position: 'right',
                                labels: {
                                    boxWidth: 10,
                                    boxHeight: 10,
                                    usePointStyle: true,
                                    pointStyle: 'circle',
                                    font: { size: 11, family: 'inherit' },
                                    color: '#475569',
                                    padding: 10
                                }
                            },
                            tooltip: {
                                backgroundColor: '#0f172a',
                                titleFont: { size: 12, weight: '600' },
                                bodyFont: { size: 12 },
                                padding: { top: 8, bottom: 8, left: 12, right: 12 },
                                cornerRadius: 8,
                                callbacks: {
                                    label: function(ctx) {
                                        const p = percentages[ctx.dataIndex] ? ` (${percentages[ctx.dataIndex]})` : '';
                                        return ` ${ctx.label}: ${ctx.raw} 次${p}`;
                                    }
                                }
                            }
                        }
                    }
                }));
            }
        },

        // 2. 攻击目标分类雷达图 (Radar)
        drawRadarChart() {
            const canvas = this.$refs.attackRadarChart;
            if (!canvas) return;

            const radar = this.dashboardStats.attackTargetsRadar || {};
            const labels = Array.isArray(radar.labels) && radar.labels.length ? radar.labels : ['数据', '其他', '应用', '服务器', '文件'];
            const values = Array.isArray(radar.values) && radar.values.length ? radar.values : [0, 0, 0, 0, 0];
            const maxVal = radar.max && radar.max > 0 ? radar.max : 100;

            if (this.chartInstances['attackRadarChart']) {
                const chart = this.chartInstances['attackRadarChart'];
                chart.data.labels = labels;
                chart.data.datasets[0].data = values;
                chart.options.scales.r.suggestedMax = maxVal;
                chart.update();
            } else {
                this.chartInstances['attackRadarChart'] = markRaw(new Chart(canvas, {
                    type: 'radar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: '攻击目标威胁指数',
                            data: values,
                            backgroundColor: 'rgba(99, 102, 241, 0.22)',
                            borderColor: '#6366f1',
                            borderWidth: 2,
                            pointBackgroundColor: '#4f46e5',
                            pointBorderColor: '#ffffff',
                            pointHoverBackgroundColor: '#ffffff',
                            pointHoverBorderColor: '#4f46e5',
                            pointRadius: 4,
                            pointHoverRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: '#0f172a',
                                titleFont: { size: 12, weight: '600' },
                                bodyFont: { size: 12 },
                                padding: { top: 8, bottom: 8, left: 12, right: 12 },
                                cornerRadius: 8
                            }
                        },
                        scales: {
                            r: {
                                angleLines: { color: '#e2e8f0' },
                                grid: { color: '#f1f5f9' },
                                pointLabels: {
                                    font: { size: 12, weight: '600', family: 'inherit' },
                                    color: '#334155'
                                },
                                ticks: {
                                    display: false,
                                    precision: 0
                                },
                                suggestedMin: 0,
                                suggestedMax: maxVal
                            }
                        }
                    }
                }));
            }
        },

        // 3. 24小时攻击时序趋势双折线图 (Line)
        drawLineTrendChart() {
            const canvas = this.$refs.attackTrendChart;
            if (!canvas) return;

            const trend = this.dashboardStats.attackTrend || {};
            const hours = Array.isArray(trend.hours) && trend.hours.length ? trend.hours : Array.from({length: 24}, (_, i) => `${String(i).padStart(2, '0')}:00`);
            const vulnData = Array.isArray(trend.vuln) && trend.vuln.length ? trend.vuln : new Array(hours.length).fill(0);
            const ccData = Array.isArray(trend.cc) && trend.cc.length ? trend.cc : new Array(hours.length).fill(0);

            if (this.chartInstances['attackTrendChart']) {
                const chart = this.chartInstances['attackTrendChart'];
                chart.data.labels = hours;
                chart.data.datasets[0].data = vulnData;
                chart.data.datasets[1].data = ccData;
                chart.update();
            } else {
                this.chartInstances['attackTrendChart'] = markRaw(new Chart(canvas, {
                    type: 'line',
                    data: {
                        labels: hours,
                        datasets: [
                            {
                                label: '漏洞攻击 (次)',
                                data: vulnData,
                                borderColor: '#f43f5e',
                                backgroundColor: 'rgba(244, 63, 94, 0.12)',
                                borderWidth: 2,
                                fill: true,
                                tension: 0.35,
                                pointRadius: 2.5,
                                pointHoverRadius: 5
                            },
                            {
                                label: 'CC 刷量攻击 (次)',
                                data: ccData,
                                borderColor: '#f59e0b',
                                backgroundColor: 'rgba(245, 158, 11, 0.08)',
                                borderWidth: 2,
                                fill: true,
                                tension: 0.35,
                                pointRadius: 2.5,
                                pointHoverRadius: 5
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: {
                            mode: 'index',
                            intersect: false
                        },
                        plugins: {
                            legend: {
                                position: 'top',
                                align: 'end',
                                labels: {
                                    boxWidth: 10,
                                    boxHeight: 10,
                                    usePointStyle: true,
                                    pointStyle: 'circle',
                                    font: { size: 11, family: 'inherit' },
                                    color: '#475569',
                                    padding: 12
                                }
                            },
                            tooltip: {
                                backgroundColor: '#0f172a',
                                titleFont: { size: 12, weight: '600' },
                                bodyFont: { size: 12 },
                                padding: { top: 8, bottom: 8, left: 12, right: 12 },
                                cornerRadius: 8
                            }
                        },
                        scales: {
                            x: {
                                grid: { display: false },
                                ticks: { 
                                    color: '#64748b', 
                                    font: { size: 10, family: 'inherit' },
                                    maxRotation: 0,
                                    autoSkip: true,
                                    maxTicksLimit: 12
                                }
                            },
                            y: {
                                beginAtZero: true,
                                grid: { color: '#f1f5f9' },
                                ticks: { 
                                    color: '#64748b', 
                                    font: { size: 11, family: 'inherit' }, 
                                    precision: 0 
                                }
                            }
                        }
                    }
                }));
            }
        },

        // 4. 攻击 IP 地理分布横向柱状图 (Bar)
        drawGeoBarChart() {
            const canvas = this.$refs.attackGeoChart;
            if (!canvas) return;

            const geoList = (Array.isArray(this.dashboardStats.attackGeo) ? this.dashboardStats.attackGeo : []).slice(0, 10);
            if (geoList.length === 0) {
                if (this.chartInstances['attackGeoChart']) {
                    this.chartInstances['attackGeoChart'].destroy();
                    delete this.chartInstances['attackGeoChart'];
                }
                const ctx = canvas.getContext('2d');
                if (ctx) {
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    ctx.fillStyle = '#94a3b8';
                    ctx.font = '13px sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    const x = (canvas.offsetWidth || canvas.width || 300) / 2;
                    const y = (canvas.offsetHeight || canvas.height || 240) / 2;
                    ctx.fillText('暂无归属地统计', x, y);
                }
                return;
            }

            const labels = geoList.map(item => item.name);
            const values = geoList.map(item => item.value);
            const percentages = geoList.map(item => item.percent || '');
            const bgColors = labels.map((_, idx) => this.chartColors[idx % this.chartColors.length]);

            if (this.chartInstances['attackGeoChart']) {
                const chart = this.chartInstances['attackGeoChart'];
                chart.data.labels = labels;
                chart.data.datasets[0].data = values;
                chart.data.datasets[0].backgroundColor = bgColors;
                chart.update();
            } else {
                this.chartInstances['attackGeoChart'] = markRaw(new Chart(canvas, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: '拦截次数',
                            data: values,
                            backgroundColor: bgColors,
                            borderRadius: 4,
                            borderSkipped: false
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: '#0f172a',
                                titleFont: { size: 12, weight: '600' },
                                bodyFont: { size: 12 },
                                padding: { top: 8, bottom: 8, left: 12, right: 12 },
                                cornerRadius: 8,
                                callbacks: {
                                    label: function(ctx) {
                                        const p = percentages[ctx.dataIndex] ? ` (${percentages[ctx.dataIndex]})` : '';
                                        return ` 拦截: ${ctx.raw} 次${p}`;
                                    }
                                }
                            }
                        },
                        scales: {
                            x: {
                                grid: { color: '#f1f5f9' },
                                ticks: { 
                                    color: '#64748b', 
                                    font: { size: 10, family: 'inherit' }, 
                                    precision: 0 
                                }
                            },
                            y: {
                                grid: { display: false },
                                ticks: { 
                                    color: '#334155', 
                                    font: { size: 11, weight: '500', family: 'inherit' } 
                                }
                            }
                        }
                    }
                }));
            }
        },

        // 5. 基础访问流量画像 (原有 4 个图表)
        renderTrafficCharts() {
            const systemTypes = this.trafficProfileData.systemTypes || {};
            const hosts = this.trafficProfileData.hosts || {};
            const statusCodes = this.trafficProfileData.statusCodes || {};
            const topIps = this.trafficProfileData.topIps || {};

            this.drawPieChart('systemTypeChart', systemTypes, '系统类型');
            this.drawPieChart('hostChart', hosts, 'HOST');
            this.drawBarChart('statusCodeChart', statusCodes, '状态码');
            
            const topIpsData = {};
            if (topIps && typeof topIps === 'object') {
                Object.entries(topIps)
                    .sort((a, b) => (Number(b[1]) || 0) - (Number(a[1]) || 0))
                    .slice(0, 10)
                    .forEach(([k, v]) => { topIpsData[k] = v; });
            }
            this.drawBarChart('topIpChart', topIpsData, '请求次数');
        },

        drawPieChart(refName, data, label) {
            const canvas = this.$refs[refName];
            if (!canvas) return;
            
            const entries = Object.entries(data || {});
            
            if (entries.length === 0) {
                if (this.chartInstances[refName]) {
                    this.chartInstances[refName].destroy();
                    delete this.chartInstances[refName];
                }
                const ctx = canvas.getContext('2d');
                if (ctx) {
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    ctx.fillStyle = '#94a3b8';
                    ctx.font = '13px sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    const x = (canvas.offsetWidth || canvas.width || 300) / 2;
                    const y = (canvas.offsetHeight || canvas.height || 240) / 2;
                    ctx.fillText('暂无分布数据', x, y);
                }
                return;
            }

            const labels = entries.map(([name]) => name);
            const values = entries.map(([, value]) => value);
            const bgColors = labels.map((_, idx) => this.chartColors[idx % this.chartColors.length]);

            if (this.chartInstances[refName]) {
                const chart = this.chartInstances[refName];
                chart.data.labels = labels;
                chart.data.datasets[0].data = values;
                chart.data.datasets[0].backgroundColor = bgColors;
                chart.update();
            } else {
                this.chartInstances[refName] = markRaw(new Chart(canvas, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: values,
                            backgroundColor: bgColors,
                            borderWidth: 2,
                            borderColor: '#ffffff',
                            hoverOffset: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '62%',
                        plugins: {
                            legend: {
                                position: 'right',
                                labels: {
                                    boxWidth: 10,
                                    boxHeight: 10,
                                    usePointStyle: true,
                                    pointStyle: 'circle',
                                    font: { size: 11, family: 'inherit' },
                                    color: '#475569',
                                    padding: 10
                                }
                            },
                            tooltip: {
                                backgroundColor: '#0f172a',
                                titleFont: { size: 12, weight: '600' },
                                bodyFont: { size: 12 },
                                padding: { top: 8, bottom: 8, left: 12, right: 12 },
                                cornerRadius: 8
                            }
                        }
                    }
                }));
            }
        },

        drawBarChart(refName, data, label) {
            const canvas = this.$refs[refName];
            if (!canvas) return;
            
            const entries = Object.entries(data || {});

            if (entries.length === 0) {
                if (this.chartInstances[refName]) {
                    this.chartInstances[refName].destroy();
                    delete this.chartInstances[refName];
                }
                const ctx = canvas.getContext('2d');
                if (ctx) {
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    ctx.fillStyle = '#94a3b8';
                    ctx.font = '13px sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    const x = (canvas.offsetWidth || canvas.width || 300) / 2;
                    const y = (canvas.offsetHeight || canvas.height || 240) / 2;
                    ctx.fillText('暂无统计数据', x, y);
                }
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
                this.chartInstances[refName] = markRaw(new Chart(canvas, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: label,
                            data: values,
                            backgroundColor: '#334155',
                            hoverBackgroundColor: '#0f172a',
                            borderRadius: 6,
                            borderSkipped: false
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: '#0f172a',
                                titleFont: { size: 12, weight: '600' },
                                bodyFont: { size: 12 },
                                padding: { top: 8, bottom: 8, left: 12, right: 12 },
                                cornerRadius: 8
                            }
                        },
                        scales: {
                            x: {
                                grid: { display: false },
                                ticks: { 
                                    color: '#64748b', 
                                    font: { size: 10, family: 'inherit' },
                                    maxRotation: 45,
                                    minRotation: 0
                                }
                            },
                            y: {
                                grid: { color: '#f1f5f9' },
                                ticks: { 
                                    color: '#64748b', 
                                    font: { size: 11, family: 'inherit' }, 
                                    precision: 0 
                                }
                            }
                        }
                    }
                }));
            }
        },

        // --- Dashboard 交互与联动方法 ---
        selectAttackFilter(typeName) {
            if (this.selectedAttackFilter === typeName) {
                this.selectedAttackFilter = '';
            } else {
                this.selectedAttackFilter = typeName;
                const target = document.getElementById('highRiskIncidentsSection');
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            }
        },
        toggleIpTab(tab) {
            this.selectedIpTab = tab;
            this.isIpsExpanded = false;
        },
        toggleIpsExpanded() {
            this.isIpsExpanded = !this.isIpsExpanded;
        },
        toggleAttacksExpanded() {
            this.isAttacksExpanded = !this.isAttacksExpanded;
        },
        toggleTrafficProfile() {
            this.showTrafficProfile = !this.showTrafficProfile;
            if (this.showTrafficProfile) {
                this.$nextTick(() => {
                    this.renderTrafficCharts();
                });
            }
        },
        async addIpToBlacklist(ipItem) {
            const ip = typeof ipItem === 'string' ? ipItem : ipItem.ip;
            if (!ip) return;
            if (!confirm(`确定要将恶意 IP [${ip}] 添加至黑名单并阻断其所有访问吗？`)) return;

            try {
                const fileData = await this.apiRequest('/api/read-file?file=blackIp');
                let content = fileData?.content || fileData || '';
                const lines = content.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
                if (lines.includes(ip)) {
                    this.showToast(`IP ${ip} 已在黑名单列表中`, 'info');
                    if (typeof ipItem === 'object') ipItem.is_blocked = true;
                    return;
                }
                lines.push(ip);
                const newContent = lines.join('\n') + '\n';
                await this.apiRequest('/api/save-file', {
                    method: 'POST',
                    body: JSON.stringify({ file: 'blackIp', content: newContent })
                });

                if (typeof ipItem === 'object') ipItem.is_blocked = true;
                ['all', 'vuln', 'cc'].forEach(k => {
                    const arr = this.dashboardStats.maliciousIps && this.dashboardStats.maliciousIps[k];
                    if (Array.isArray(arr)) {
                        arr.forEach(item => {
                            if (item && item.ip === ip) item.is_blocked = true;
                        });
                    }
                });
                const rec = this.dashboardStats.recentAttacks;
                if (Array.isArray(rec)) {
                    rec.forEach(item => {
                        if (item && item.ip === ip) item.is_blocked = true;
                    });
                }

                this.showToast(`已将恶意 IP ${ip} 加入黑名单，防护即时生效`, 'success');
            } catch (err) {
                this.showToast(`加入黑名单失败: ${err.message}`, 'error');
            }
        },
        viewAttackDetail(attack) {
            this.modal.title = `拦截事件明细 [${attack.attack_type || attack.type || attack.raw_type || attack.rule || '高危攻击'}]`;
            this.modal.content = JSON.stringify(attack, null, 2);
            this.modal.type = 'log';
            this.modal.show = true;
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
                this.modal.title = `规则源文件: ${file}`;
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
                this.showToast('WAF 配置已成功重载', 'success');        
            } catch (error) {
                this.showToast('重载失败: ' + error.message, 'error');
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
                const hotReloadFiles = ['blackIp', 'whiteIp', 'whitehost'];
                if (hotReloadFiles.includes(file)) {
                    this.showToast(`文件 ${file} 已保存并即时生效`, 'success');
                } else {
                    this.showToast(`文件 ${file} 已保存，请重载配置使其生效`, 'success');
                }
            } catch (error) {
                this.showToast('保存失败: ' + error.message, 'error');
            }
        },

        // --- Logs Methods ---
        async loadLogs() {
            try {
                const logsData = await this.apiRequest(`/api/logs?host=${encodeURIComponent(this.logQuery.host)}&date=${encodeURIComponent(this.logQuery.date)}&limit=100`);
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
            this.modal.title = '安全事件详情';
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
            if (!confirm('确定要安全退出管理后台吗?')) return;
            try {
                await this.apiRequest('/api/logout', { method: 'POST' });
                sessionStorage.removeItem('csrf_token');
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

        // Window resize listener for responsive charts
        window.addEventListener('resize', this.resizeCharts);

        // Global keyboard listener
        window.addEventListener('keydown', this.handleKeydown);
    },
    beforeUnmount() {
        window.removeEventListener('resize', this.resizeCharts);
        window.removeEventListener('keydown', this.handleKeydown);
    }
}).mount('#app');
