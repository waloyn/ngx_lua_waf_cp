// 检查用户认证状态
async function checkAuth() {
    try {
        const response = await fetch('/api/stats');
        if (response.status === 401) {
            // 如果当前页面不是登录页面，则重定向到登录页面
            if (!window.location.pathname.endsWith('/login.html')) {
                window.location.href = '/login.html';
            }
            return false;
        }
        return true;
    } catch (error) {
        console.error('认证检查失败:', error);
        return false;
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

// 在页面加载时检查登录状态
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkAuth);
} else {
    checkAuth();
}