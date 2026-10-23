const { createApp } = Vue;

createApp({
    data() {
        return {
            username: '',
            password: '',
            showPassword: false,
            remember: false,
            isLoading: false,
            toast: {
                show: false,
                message: '',
                type: 'info'
            }
        }
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
        async handleLogin() {
            this.isLoading = true;
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ 
                        username: this.username, 
                        password: this.password 
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // 保存 CSRF Token
                    const csrfToken = data.data?.csrf_token;
                    if (csrfToken) {
                        sessionStorage.setItem('csrf_token', csrfToken);
                    }
                    // 仅记住用户名，禁止将明文密码存入 localStorage
                    localStorage.removeItem('password');
                    if (this.remember) {
                        localStorage.setItem('remember', 'true');
                        localStorage.setItem('username', this.username);
                    } else {
                        localStorage.removeItem('remember');
                        localStorage.removeItem('username');
                    }
                    this.showToast('登录成功', 'success');
                    setTimeout(() => {
                        window.location.href = 'index.html';
                    }, 500);
                } else {
                    this.showToast(data.data?.message || '登录失败', 'error');
                }
            } catch (error) {
                this.showToast('网络错误，请稍后重试', 'error');
                console.error('Login error:', error);
            } finally {
                this.isLoading = false;
            }
        },
        async checkAuth() {
            try {
                const response = await fetch('/api/stats');
                if (response.ok) {
                    window.location.href = 'index.html';
                }
            } catch (error) {
                // 未登录，保持在登录页
            }
        },
        checkRemember() {
            // 清理历史版本遗留的明文密码存储
            localStorage.removeItem('password');
            const remember = localStorage.getItem('remember') === 'true';
            if (remember) {
                this.username = localStorage.getItem('username') || '';
                this.remember = true;
            }
        }
    },
    mounted() {
        this.checkRemember();
        this.checkAuth();
    }
}).mount('#app');
