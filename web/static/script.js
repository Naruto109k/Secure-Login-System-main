// Global state
let currentUsername = '';
let currentRole = 'user';

// Utility: Show Alert
function showAlert(message, isError = true) {
    const box = document.getElementById('alert-box');
    box.textContent = message;
    box.className = `alert ${isError ? 'error' : 'success'}`;
    
    setTimeout(() => {
        box.classList.add('hidden');
    }, 5000);
}

function hideAlert() {
    document.getElementById('alert-box').classList.add('hidden');
}

// Utility: View Navigation
function showView(viewId) {
    hideAlert();
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(viewId).classList.add('active');
    
    const container = document.querySelector('.container');
    if (viewId === 'admin-view' || viewId === 'dashboard-view') {
        container.classList.add('wide');
        if(viewId === 'admin-view') loadAdminUsers();
        if(viewId === 'dashboard-view') loadProfile();
    } else {
        container.classList.remove('wide');
    }
}

// API Helper
async function apiCall(endpoint, method = 'POST', body = null) {
    const options = {
        method,
        headers: { 'Content-Type': 'application/json' }
    };
    if (body) options.body = JSON.stringify(body);
    
    try {
        const res = await fetch(endpoint, options);
        const data = await res.json();
        return { status: res.status, data };
    } catch (e) {
        return { status: 500, data: { success: false, message: 'Network error.' } };
    }
}

// Check auth status on load
window.addEventListener('DOMContentLoaded', async () => {
    const res = await apiCall('/api/status', 'GET');
    if (res.data.authenticated) {
        currentUsername = res.data.profile.username;
        currentRole = res.data.profile.role;
        updateNav();
        showView('dashboard-view');
    } else {
        showView('login-view');
    }
});

function updateNav() {
    const nav = document.getElementById('nav-menu');
    const adminBtn = document.getElementById('nav-admin');
    if (currentUsername) {
        nav.classList.remove('hidden');
        if (currentRole === 'admin') adminBtn.classList.remove('hidden');
        else adminBtn.classList.add('hidden');
    } else {
        nav.classList.add('hidden');
    }
}

// Handlers
async function handleLogin(e) {
    e.preventDefault();
    const u = document.getElementById('login-username').value;
    const p = document.getElementById('login-password').value;
    
    const res = await apiCall('/api/login', 'POST', { username: u, password: p });
    if (res.data.success) {
        // fetch profile to get role
        const pRes = await apiCall('/api/profile', 'GET');
        currentUsername = pRes.data.profile.username;
        currentRole = pRes.data.profile.role;
        updateNav();
        showView('dashboard-view');
        e.target.reset();
    } else {
        showAlert(res.data.message);
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const u = document.getElementById('reg-username').value;
    const p = document.getElementById('reg-password').value;
    const c = document.getElementById('reg-confirm').value;
    const sq = document.getElementById('reg-question').value;
    const sa = document.getElementById('reg-answer').value;
    const role = document.getElementById('reg-role').value;
    
    if (p !== c) return showAlert('Passwords do not match.');
    
    const res = await apiCall('/api/register', 'POST', {
        username: u, password: p, security_question: sq, security_answer: sa, role
    });
    
    if (res.data.success) {
        showAlert('Registration successful. Please login.', false);
        showView('login-view');
        e.target.reset();
    } else {
        showAlert(res.data.message);
    }
}

async function logout() {
    await apiCall('/api/logout', 'POST');
    currentUsername = '';
    currentRole = 'user';
    updateNav();
    showView('login-view');
}

// Reset Password
let resetTargetUsername = '';

async function handleResetInit(e) {
    e.preventDefault();
    const u = document.getElementById('reset-username').value;
    const res = await apiCall('/api/reset-password/init', 'POST', { username: u });
    
    if (res.data.success) {
        resetTargetUsername = u;
        document.getElementById('reset-question-display').textContent = res.data.question;
        showView('reset-complete-view');
        e.target.reset();
    } else {
        showAlert(res.data.message);
    }
}

async function handleResetComplete(e) {
    e.preventDefault();
    const a = document.getElementById('reset-answer').value;
    const np = document.getElementById('reset-new-pass').value;
    
    const res = await apiCall('/api/reset-password/complete', 'POST', {
        username: resetTargetUsername, answer: a, new_password: np
    });
    
    if (res.data.success) {
        showAlert('Password reset successful. Please login.', false);
        showView('login-view');
        e.target.reset();
    } else {
        showAlert(res.data.message);
    }
}

// Dashboard
async function loadProfile() {
    const res = await apiCall('/api/profile', 'GET');
    if (!res.data.success) return logout();
    
    const p = res.data.profile;
    const s = res.data.session;
    
    document.getElementById('profile-stats').innerHTML = `
        <div class="stat-item"><div class="stat-label">Username</div><div class="stat-value">${p.username}</div></div>
        <div class="stat-item"><div class="stat-label">Role</div><div class="stat-value"><span class="badge ${p.role}">${p.role}</span></div></div>
        <div class="stat-item"><div class="stat-label">Failed Logins</div><div class="stat-value">${p.failed_login_count}</div></div>
        <div class="stat-item"><div class="stat-label">Locked Until</div><div class="stat-value">${p.locked_until !== 'N/A' && p.locked_until !== 'None' ? new Date(parseFloat(p.locked_until)*1000).toLocaleString() : 'Not Locked'}</div></div>
    `;
    
    document.getElementById('session-stats').innerHTML = `
        <div class="stat-item"><div class="stat-label">Status</div><div class="stat-value">${s.active ? 'Active' : 'Inactive'}</div></div>
        <div class="stat-item"><div class="stat-label">Token</div><div class="stat-value">${s.token_prefix || 'N/A'}</div></div>
        <div class="stat-item"><div class="stat-label">Expires In</div><div class="stat-value">${s.remaining_seconds ? s.remaining_seconds + 's' : 'N/A'}</div></div>
    `;
}

// Admin Panel
async function loadAdminUsers() {
    const res = await apiCall('/api/admin/users', 'GET');
    if (!res.data.success) return showAlert(res.data.message);
    
    const tbody = document.querySelector('#users-table tbody');
    tbody.innerHTML = '';
    
    res.data.users.forEach(u => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${u.username}</td>
            <td><span class="badge ${u.role}">${u.role}</span></td>
            <td>${u.failed_login_count}</td>
            <td>${u.locked_until ? 'Yes' : 'No'}</td>
            <td>
                ${u.locked_until ? `<button class="btn-outline btn-small" onclick="adminUnlock('${u.username}')">Unlock</button>` : ''}
                <button class="btn-outline btn-small" onclick="prepAdminReset('${u.username}')">Reset Pass</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function adminUnlock(user) {
    const res = await apiCall('/api/admin/unlock', 'POST', { username: user });
    showAlert(res.data.message, !res.data.success);
    if(res.data.success) loadAdminUsers();
}

function prepAdminReset(user) {
    document.getElementById('admin-reset-target').value = user;
    document.getElementById('admin-reset-target-display').textContent = user;
    document.getElementById('admin-reset-panel').classList.remove('hidden');
    document.getElementById('admin-reset-pass').value = '';
}

async function handleAdminReset(e) {
    e.preventDefault();
    const user = document.getElementById('admin-reset-target').value;
    const pass = document.getElementById('admin-reset-pass').value;
    
    const res = await apiCall('/api/admin/reset-password', 'POST', { username: user, new_password: pass });
    showAlert(res.data.message, !res.data.success);
    if(res.data.success) {
        document.getElementById('admin-reset-panel').classList.add('hidden');
    }
}
