const { createApp } = Vue;

createApp({
    data() {
        return {
            username: '',
            password: '',
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
                    if (this.remember) {
                        localStorage.setItem('remember', 'true');
                        localStorage.setItem('username', this.username);
                        localStorage.setItem('password', this.password);
                    } else {
                        localStorage.removeItem('remember');
                        localStorage.removeItem('username');
                        localStorage.removeItem('password');
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
            const remember = localStorage.getItem('remember') === 'true';
            if (remember) {
                this.username = localStorage.getItem('username') || '';
                this.password = localStorage.getItem('password') || '';
                this.remember = true;
            }
        }
    },
    mounted() {
        this.checkRemember();
        this.checkAuth();
    }
}).mount('#app');