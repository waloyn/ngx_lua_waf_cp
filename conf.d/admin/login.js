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

// 登录表单处理
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const remember = document.getElementById('remember').checked;
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (remember) {
                localStorage.setItem('remember', 'true');
            }
            showToast('登录成功', 'success');
            setTimeout(() => {
                window.location.href = 'index.html';
            }, 500);
        } else {
            showToast(data.data?.message || '登录失败', 'error');
        }
    } catch (error) {
        showToast('网络错误，请稍后重试', 'error');
        console.error('Login error:', error);
    }
});

// 检查是否已登录
async function checkAuth() {
    try {
        const response = await fetch('/api/stats');
        if (response.ok) {
            window.location.href = 'index.html';
        }
    } catch (error) {
        // 未登录，保持在登录页
    }
}

checkAuth();
