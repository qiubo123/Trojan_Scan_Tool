const API_BASE = '/api/v1';
let currentPage = 1;
let currentTab = 'dashboard';

function getToken() {
    return localStorage.getItem('token');
}

function getUsername() {
    return localStorage.getItem('username');
}

function apiHeaders() {
    return {
        'Content-Type': 'application/json',
        'X-Auth-Token': getToken() || ''
    };
}

function checkAuth() {
    const token = getToken();
    if (!token) {
        window.location.href = 'login.html';
        return false;
    }
    const expiresAt = localStorage.getItem('expires_at');
    if (expiresAt && new Date(expiresAt) < new Date()) {
        doLogout();
        return false;
    }
    return true;
}

function doLogout() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
    localStorage.removeItem('expires_at');
    window.location.href = 'login.html';
}

function showToast(message, type) {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'toast toast-' + (type || 'info');
    toast.textContent = message;
    document.body.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

    const tabEl = document.querySelector(`.tab[onclick*="'${tab}'"]`);
    if (tabEl) tabEl.classList.add('active');

    const contentEl = document.getElementById('tab-' + tab);
    if (contentEl) contentEl.classList.add('active');

    if (tab === 'dashboard') loadDashboard();
    else if (tab === 'ips') { currentPage = 1; loadIPs(); }
    else if (tab === 'clients') loadClients();
    else if (tab === 'audit') { currentPage = 1; loadAuditLog(); }
    else if (tab === 'settings') { loadNetworks(); }
    else if (tab === 'keys') loadKeys();
    else if (tab === 'pending') loadPending();
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
}

function openModal(id) {
    document.getElementById(id).classList.add('active');
}

function esc(s) {
    if (!s) return '-';
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function getBadgeClass(type) {
    const map = {
        'C2服务器': 'badge-c2',
        '扫描器': 'badge-scan',
        '僵尸网络': 'badge-botnet',
        '钓鱼网站': 'badge-phishing',
        '恶意下载': 'badge-scan',
    };
    return map[type] || 'badge-default';
}

function getActionTagClass(action) {
    if (action.includes('登录')) return 'action-tag login';
    if (action.includes('添加') || action.includes('导入')) return 'action-tag add';
    if (action.includes('删除')) return 'action-tag delete';
    if (action.includes('编辑') || action.includes('过期') || action.includes('恢复') || action.includes('修改')) return 'action-tag edit';
    return 'action-tag default';
}

// ========== 仪表盘 ==========
function loadDashboard() {
    if (!checkAuth()) return;

    fetch(API_BASE + '/ips/statistics', { headers: apiHeaders() })
        .then(r => r.json())
        .then(res => {
            if (res.code === 0) {
                const d = res.data;
                document.getElementById('statsCards').innerHTML = `
                    <div class="stat-card"><div class="label">IP总数</div><div class="value">${d.total}</div><div class="sub">全部记录</div></div>
                    <div class="stat-card"><div class="label">活跃IP</div><div class="value" style="color:#4caf50">${d.active}</div><div class="sub">有效威胁</div></div>
                    <div class="stat-card"><div class="label">已过期</div><div class="value" style="color:#888">${d.expired}</div><div class="sub">已标记过期</div></div>
                `;

                const chart = document.getElementById('typeChart');
                if (d.by_type && d.by_type.length > 0) {
                    chart.innerHTML = d.by_type.map(t =>
                        `<div class="type-item"><span class="count">${t.count}</span> ${t.threat_type}</div>`
                    ).join('');
                } else {
                    chart.innerHTML = '<div style="color:#666;padding:20px;">暂无数据</div>';
                }
            }
        })
        .catch(() => {});
}

// ========== IP管理 ==========
function loadIPs() {
    if (!checkAuth()) return;

    const status = document.getElementById('statusFilter').value;
    let url = API_BASE + `/ips?page=${currentPage}&size=20`;
    if (status) url += '&status=' + status;

    fetch(url, { headers: apiHeaders() })
        .then(r => r.json())
        .then(res => {
            if (res.code === 0) {
                renderIPTable(res.data);
            }
        })
        .catch(() => showToast('加载IP列表失败', 'error'));
}

function renderIPTable(data) {
    const tbody = document.getElementById('ipTableBody');
    if (!data.ips || data.ips.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;padding:40px;color:#666;">暂无数据</td></tr>';
        document.getElementById('ipPagination').innerHTML = '';
        return;
    }

    tbody.innerHTML = data.ips.map(ip => {
        const statusText = ip.status === 'active' ? '活跃' : '已过期';
        const statusColor = ip.status === 'active' ? '#4caf50' : '#888';
        const badgeClass = getBadgeClass(ip.threat_type);
        return `<tr>
            <td>${esc(String(ip.id))}</td>
            <td style="font-family:monospace;">${esc(ip.ip)}</td>
            <td>${esc(String(ip.port || '-'))}</td>
            <td><span class="badge ${badgeClass}">${esc(ip.threat_type || '-')}</span></td>
            <td>${esc(ip.source || '-')}</td>
            <td style="color:${statusColor}">${esc(statusText)}</td>
            <td class="cell-ellipsis" data-tip="${esc(ip.location)}">${esc(ip.location || '-')}</td>
            <td class="cell-ellipsis" data-tip="${esc(ip.tags)}">${esc(ip.tags || '-')}</td>
            <td style="font-size:12px;">${esc(ip.create_time || '-')}</td>
            <td>
                <button class="btn btn-sm btn-outline" data-action="editIP" data-id="${ip.id}">编辑</button>
                <button class="btn btn-sm ${ip.status === 'active' ? 'btn-warning' : 'btn-success'}" data-action="toggleIPStatus" data-id="${ip.id}" data-status="${ip.status}">${ip.status === 'active' ? '过期' : '恢复'}</button>
                <button class="btn btn-sm btn-danger" data-action="deleteIP" data-id="${ip.id}">删除</button>
            </td>
        </tr>`;
    }).join('');

    const totalPages = Math.ceil(data.total / data.size);
    document.getElementById('ipPagination').innerHTML = `
        <span>共 ${data.total} 条记录，第 ${data.page}/${totalPages} 页</span>
        <div>
            <button class="page-btn" ${data.page <= 1 ? 'disabled' : ''} onclick="changeIPPage(${data.page - 1})">上一页</button>
            <button class="page-btn" ${data.page >= totalPages ? 'disabled' : ''} onclick="changeIPPage(${data.page + 1})">下一页</button>
        </div>
    `;
}

function changeIPPage(page) {
    currentPage = page;
    loadIPs();
}

let searchTimer = null;
function searchIPs() {
    clearTimeout(searchTimer);
    const keyword = document.getElementById('searchInput').value.trim();
    if (!keyword) { loadIPs(); return; }

    searchTimer = setTimeout(() => {
        if (!checkAuth()) return;
        fetch(API_BASE + '/ips/search?keyword=' + encodeURIComponent(keyword), { headers: apiHeaders() })
            .then(r => r.json())
            .then(res => {
                if (res.code === 0) {
                    renderIPTable(res.data);
                }
            })
            .catch(() => {});
    }, 300);
}

function showAddModal() {
    document.getElementById('addIp').value = '';
    document.getElementById('addPort').value = '0';
    document.getElementById('addType').value = 'C2服务器';
    document.getElementById('addDesc').value = '';
    document.getElementById('addLocation').value = '';
    document.getElementById('addTags').value = '';
    document.getElementById('addVirus').value = '';
    openModal('addModal');
}

function submitAdd() {
    const ip = document.getElementById('addIp').value.trim();
    if (!ip) { showToast('请输入IP地址', 'error'); return; }

    const data = {
        ip: ip,
        port: parseInt(document.getElementById('addPort').value) || 0,
        threat_type: document.getElementById('addType').value,
        description: document.getElementById('addDesc').value.trim(),
        location: document.getElementById('addLocation').value.trim(),
        tags: document.getElementById('addTags').value.trim(),
        related_virus: document.getElementById('addVirus').value.trim()
    };

    fetch(API_BASE + '/ips', {
        method: 'POST', headers: apiHeaders(),
        body: JSON.stringify(data)
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast('添加成功', 'success');
            closeModal('addModal');
            loadIPs();
        } else {
            showToast(res.message || '添加失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

function showBatchModal() {
    document.getElementById('batchData').value = '';
    document.getElementById('batchCount').textContent = '已识别: 0 个有效IP';
    document.getElementById('batchPreview').innerHTML = '';
    openModal('batchModal');

    document.getElementById('batchData').oninput = function() {
        const lines = this.value.split('\n').filter(l => l.trim());
        const valid = lines.filter(l => {
            const parts = l.split('|');
            return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parts[0].trim());
        });
        document.getElementById('batchCount').textContent = `已识别: ${valid.length} 个有效IP`;
        document.getElementById('batchPreview').innerHTML = valid.slice(0, 10).map(ip =>
            `<div class="valid">✓ ${ip}</div>`
        ).join('') + (valid.length > 10 ? `<div>...还有 ${valid.length - 10} 个</div>` : '');
    };
}

function submitBatch() {
    const text = document.getElementById('batchData').value.trim();
    if (!text) { showToast('请输入要导入的数据', 'error'); return; }

    const ips = [];
    text.split('\n').forEach(line => {
        line = line.trim();
        if (!line) return;
        const parts = line.split('|');
        const ip = parts[0].trim();
        if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return;
        ips.push({
            ip: ip,
            port: parseInt(parts[1]) || 0,
            threat_type: parts[2] || '其他',
            description: parts[3] || ''
        });
    });

    if (ips.length === 0) { showToast('没有有效的IP地址', 'error'); return; }

    fetch(API_BASE + '/ips/batch', {
        method: 'POST', headers: apiHeaders(),
        body: JSON.stringify({ ips: ips, source: 'web' })
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast(`成功导入 ${res.data.added} 条记录`, 'success');
            closeModal('batchModal');
            loadIPs();
        } else {
            showToast(res.message || '导入失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

function editIP(id) {
    fetch(API_BASE + '/ips/' + id, { headers: apiHeaders() })
        .then(r => r.json())
        .then(res => {
            if (res.code === 0) {
                const ip = res.data;
                document.getElementById('editId').value = ip.id;
                document.getElementById('editIp').value = ip.ip;
                document.getElementById('editPort').value = ip.port;
                document.getElementById('editType').value = ip.threat_type;
                document.getElementById('editDesc').value = ip.description;
                document.getElementById('editLocation').value = ip.location;
                document.getElementById('editTags').value = ip.tags;
                document.getElementById('editVirus').value = ip.related_virus;
                openModal('editModal');
            }
        })
        .catch(() => showToast('加载IP详情失败', 'error'));
}

function submitEdit() {
    const id = document.getElementById('editId').value;
    const data = {
        ip: document.getElementById('editIp').value.trim(),
        port: parseInt(document.getElementById('editPort').value) || 0,
        threat_type: document.getElementById('editType').value,
        description: document.getElementById('editDesc').value.trim(),
        location: document.getElementById('editLocation').value.trim(),
        tags: document.getElementById('editTags').value.trim(),
        related_virus: document.getElementById('editVirus').value.trim()
    };

    fetch(API_BASE + '/ips/' + id, {
        method: 'PUT', headers: apiHeaders(),
        body: JSON.stringify(data)
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast('更新成功', 'success');
            closeModal('editModal');
            loadIPs();
        } else {
            showToast(res.message || '更新失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

function toggleStatus(id, currentStatus) {
    const newStatus = currentStatus === 'active' ? 'expired' : 'active';
    const action = newStatus === 'expired' ? '过期' : '恢复';

    if (!confirm(`确定要将该IP${action}吗？`)) return;

    fetch(API_BASE + '/ips/' + id, {
        method: 'PUT', headers: apiHeaders(),
        body: JSON.stringify({ status: newStatus })
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast(`${action}成功`, 'success');
            loadIPs();
        } else {
            showToast(res.message || `${action}失败`, 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

function deleteIP(id) {
    if (!confirm('确定要删除该IP记录吗？此操作不可恢复。')) return;

    fetch(API_BASE + '/ips/' + id, {
        method: 'DELETE', headers: apiHeaders()
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast('删除成功', 'success');
            loadIPs();
        } else {
            showToast(res.message || '删除失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

// ========== 客户端管理 ==========
function loadClients() {
    if (!checkAuth()) return;

    fetch(API_BASE + '/clients', { headers: apiHeaders() })
        .then(r => r.json())
        .then(res => {
            if (res.code === 0) {
                const list = document.getElementById('clientList');
                const clients = res.data.clients;
                if (!clients || clients.length === 0) {
                    list.innerHTML = '<div class="empty-state"><div class="icon">🖥</div><div>暂无已注册客户端</div></div>';
                    return;
                }
                list.innerHTML = clients.map(c => `
                    <div class="client-card">
                        <div class="client-id">${esc(c.client_id)}</div>
                        <div class="client-info">主机名: ${esc(c.hostname || '-')}</div>
                        <div class="client-info">版本: ${esc(c.version || '-')} | 系统: ${esc(c.os || '-')}</div>
                        <div class="client-info">IP: ${esc(c.ip_address || '-')}</div>
                        <div class="client-time">注册: ${esc(c.registered_at || '-')}</div>
                        <div class="client-time">最后在线: ${esc(c.last_seen || '-')}</div>
                    </div>
                `).join('');
            }
        })
        .catch(() => showToast('加载客户端失败', 'error'));
}

// ========== 审计日志 ==========
let auditPage = 1;

function loadAuditLog() {
    if (!checkAuth()) return;

    fetch(API_BASE + `/audit_log?page=${auditPage}&size=50`, { headers: apiHeaders() })
        .then(r => r.json())
        .then(res => {
            if (res.code === 0) {
                renderAuditTable(res.data);
            }
        })
        .catch(() => showToast('加载审计日志失败', 'error'));
}

function renderAuditTable(data) {
    const tbody = document.getElementById('auditTableBody');
    if (!data.logs || data.logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:40px;color:#666;">暂无审计日志</td></tr>';
        document.getElementById('auditPagination').innerHTML = '';
        return;
    }

    tbody.innerHTML = data.logs.map(log => {
        const tagClass = getActionTagClass(log.action);
        return `<tr>
            <td>${esc(String(log.id))}</td>
            <td>${esc(log.username || '-')}</td>
            <td><span class="action-tag ${tagClass}">${esc(log.action)}</span></td>
            <td class="cell-ellipsis" style="max-width:300px" data-tip="${esc(log.detail)}">${esc(log.detail || '-')}</td>
            <td style="font-family:monospace;font-size:12px;">${esc(log.ip_address || '-')}</td>
            <td style="font-size:12px;">${esc(log.created_at || '-')}</td>
        </tr>`;
    }).join('');

    const totalPages = Math.ceil(data.total / data.size);
    document.getElementById('auditPagination').innerHTML = `
        <span>共 ${data.total} 条记录，第 ${data.page}/${totalPages} 页</span>
        <div>
            <button class="page-btn" ${data.page <= 1 ? 'disabled' : ''} onclick="changeAuditPage(${data.page - 1})">上一页</button>
            <button class="page-btn" ${data.page >= totalPages ? 'disabled' : ''} onclick="changeAuditPage(${data.page + 1})">下一页</button>
        </div>
    `;
}

function changeAuditPage(page) {
    auditPage = page;
    loadAuditLog();
}

// ========== 设置页 - 网段管理 ==========
function loadNetworks() {
    if (!checkAuth()) return;

    fetch(API_BASE + '/settings/networks', { headers: apiHeaders() })
        .then(r => r.json())
        .then(res => {
            if (res.code === 0) {
                const networks = res.data.allowed_networks || [];
                document.getElementById('networksTextarea').value = networks.join('\n');
                document.getElementById('networkError').textContent = '';
            }
        })
        .catch(() => showToast('加载网段配置失败', 'error'));
}

function saveNetworks() {
    if (!checkAuth()) return;

    const text = document.getElementById('networksTextarea').value.trim();
    const networks = text ? text.split('\n').map(l => l.trim()).filter(l => l) : [];

    fetch(API_BASE + '/settings/networks', {
        method: 'POST', headers: apiHeaders(),
        body: JSON.stringify({ allowed_networks: networks })
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast('网段配置已保存，已生效', 'success');
        } else {
            showToast(res.message || '保存失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

// ========== 密钥管理 ==========
function loadKeys() {
    if (!checkAuth()) return;

    fetch(API_BASE + '/keys', { headers: apiHeaders() })
        .then(r => r.json())
        .then(res => {
            if (res.code === 0) {
                const keys = res.data.keys || [];
                const total = res.data.total || 0;
                const max = res.data.max || 20;
                document.getElementById('keyCountInfo').textContent = `共 ${total} 个密钥（最多 ${max} 个）`;

                const tbody = document.getElementById('keyTableBody');
                    tbody.innerHTML = '';
                    for (const k of keys) {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td>${k.id}</td>
                            <td><strong>${esc(k.purpose || '-')}</strong></td>
                            <td style="font-family:Consolas,monospace;font-size:13px;color:#64b5f6;user-select:all;">${esc(k.api_key || '')}</td>
                            <td>${esc(k.created_at || '')}</td>
                            <td>
                                <button class="btn btn-sm btn-warning" data-action="updateKey" data-id="${k.id}" data-purpose="${esc(k.purpose)}">更新</button>
                                <button class="btn btn-sm btn-danger" data-action="deleteKey" data-id="${k.id}" data-purpose="${esc(k.purpose)}">删除</button>
                            </td>
                        `;
                        tbody.appendChild(tr);
                    }
            }
        })
        .catch(() => showToast('加载密钥列表失败', 'error'));
}

function showAddKeyModal() {
    document.getElementById('addKeyPurpose').value = '';
    document.getElementById('addKeyValue').value = '';
    openModal('addKeyModal');
}

function confirmAddKey() {
    const purpose = document.getElementById('addKeyPurpose').value.trim();
    if (!purpose) {
        showToast('请输入密钥用途', 'error');
        return;
    }

    const api_key = document.getElementById('addKeyValue').value.trim();

    fetch(API_BASE + '/keys', {
        method: 'POST', headers: apiHeaders(),
        body: JSON.stringify({ purpose: purpose, api_key: api_key })
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast(res.message || '密钥添加成功', 'success');
            closeModal('addKeyModal');
            loadKeys();
            if (res.data && res.data.api_key) {
                const fullKey = res.data.api_key;
                showToast('生成的密钥已复制到剪贴板', 'info');
                navigator.clipboard.writeText(fullKey).catch(() => {});
            }
        } else {
            showToast(res.message || '添加失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

let _deleteKeyId = null;
function showDeleteKeyModal(id, purpose) {
    _deleteKeyId = id;
    document.getElementById('confirmKeyDeleteText').textContent = `确定要删除用途为「${purpose}」的API密钥吗？删除后使用该密钥的客户端将无法连接。`;
    openModal('confirmKeyDeleteModal');
}

function doDeleteKey() {
    if (_deleteKeyId === null) return;
    fetch(API_BASE + '/keys/' + _deleteKeyId, {
        method: 'DELETE', headers: apiHeaders()
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast('密钥已删除', 'success');
            closeModal('confirmKeyDeleteModal');
            _deleteKeyId = null;
            loadKeys();
        } else {
            showToast(res.message || '删除失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

let _updateKeyId = null;
let _updateOldPurpose = '';
function showUpdateKeyModal(id, purpose) {
    _updateKeyId = id;
    _updateOldPurpose = purpose;
    document.getElementById('confirmKeyUpdateText').textContent = `确定要更新用途为「${purpose}」的API密钥吗？点击确认后将自动生成新的随机密钥。`;
    openModal('confirmKeyUpdateModal');
}

function doUpdateKey() {
    if (_updateKeyId === null) return;

    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let newKey = '';
    for (let i = 0; i < 10; i++) {
        newKey += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    fetch(API_BASE + '/keys/' + _updateKeyId, {
        method: 'PUT', headers: apiHeaders(),
        body: JSON.stringify({ purpose: _updateOldPurpose, api_key: newKey })
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast('密钥已自动更新', 'success');
            closeModal('confirmKeyUpdateModal');
            _updateKeyId = null;
            loadKeys();
        } else {
            showToast(res.message || '更新失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

// ========== 审核管理 ==========
let _pendingBatchApproveId = null;
let _pendingBatchRejectId = null;
let _pendingFilter = 'pending';

function setPendingFilter(filter) {
    _pendingFilter = filter;
    document.querySelectorAll('[data-pending-filter]').forEach(b => {
        b.classList.toggle('active', b.dataset.pendingFilter === filter);
    });
    loadPending();
}

function loadPending() {
    if (!checkAuth()) return;

    fetch(API_BASE + '/pending/batches?status=' + _pendingFilter, { headers: apiHeaders() })
        .then(r => r.json())
        .then(res => {
            if (res.code === 0) {
                const items = res.data.items || [];
                const label = _pendingFilter === 'pending' ? '待审核' : (_pendingFilter === 'rejected' ? '已拒绝' : '全部');
                document.getElementById('pendingCountInfo').textContent = `共 ${items.length} 个批次 ${label}`;

                const tbody = document.getElementById('pendingTableBody');
                tbody.innerHTML = '';
                for (const batch of items) {
                    const tr = document.createElement('tr');

                    let statusHtml, actionHtml;
                    if (batch.batch_status === 'pending') {
                        statusHtml = '<span style="color:#f39c12;font-size:12px;">待审核</span>';
                        actionHtml = `
                            <button class="btn btn-sm btn-info" data-action="viewPendingBatch" data-batch-id="${esc(batch.batch_id)}">详情</button>
                            <button class="btn btn-sm btn-success" data-action="approveBatch" data-batch-id="${esc(batch.batch_id)}">批准</button>
                            <button class="btn btn-sm btn-danger" data-action="rejectBatch" data-batch-id="${esc(batch.batch_id)}">拒绝</button>
                        `;
                    } else if (batch.batch_status === 'rejected') {
                        statusHtml = '<span style="color:#888;font-size:12px;">已拒绝</span>';
                        actionHtml = `
                            <button class="btn btn-sm btn-info" data-action="viewPendingBatch" data-batch-id="${esc(batch.batch_id)}">详情</button>
                        `;
                    } else {
                        statusHtml = '<span style="color:#4caf50;font-size:12px;">已批准</span>';
                        actionHtml = `
                            <button class="btn btn-sm btn-info" data-action="viewPendingBatch" data-batch-id="${esc(batch.batch_id)}">详情</button>
                        `;
                    }

                    tr.innerHTML = `
                        <td>${batch.batch_id ? batch.batch_id.slice(-6) : '-'}</td>
                        <td style="font-family:monospace;font-size:12px;">${esc(batch.client_ip || '-')}</td>
                        <td style="font-size:12px;">${esc(batch.hostname || '-')}</td>
                        <td style="font-size:12px;">${esc(batch.os || '-')}</td>
                        <td style="font-weight:bold;font-size:14px;color:#e94560;">${batch.ip_count || 0}</td>
                        <td>${statusHtml}</td>
                        <td style="font-size:12px;">${esc(batch.push_time || '')}</td>
                        <td>${actionHtml}</td>
                    `;
                    tbody.appendChild(tr);
                }
            }
        })
        .catch(() => showToast('加载批次列表失败', 'error'));
}

document.addEventListener('click', function(e) {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    if (action === 'approveBatch') {
        _pendingBatchApproveId = btn.dataset.batchId;
        document.getElementById('confirmApproveText').textContent = `确定要批准该批次所有IP加入情报库吗？`;
        openModal('confirmApproveModal');
    } else if (action === 'rejectBatch') {
        _pendingBatchRejectId = btn.dataset.batchId;
        document.getElementById('confirmRejectText').textContent = `确定要拒绝该批次所有IP吗？`;
        openModal('confirmRejectModal');
    } else if (action === 'viewPendingBatch') {
        viewPendingBatch(btn.dataset.batchId);
    } else if (action === 'approveItem') {
        approvePendingItem(parseInt(btn.dataset.id), btn.dataset.batchId);
    } else if (action === 'rejectItem') {
        rejectPendingItem(parseInt(btn.dataset.id), btn.dataset.batchId);
    }
});

function doApprovePending() {
    if (_pendingBatchApproveId === null) return;
    fetch(API_BASE + '/pending/batch/' + encodeURIComponent(_pendingBatchApproveId) + '/approve', {
        method: 'POST', headers: apiHeaders()
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast(res.message || '已批准', 'success');
            closeModal('confirmApproveModal');
            _pendingBatchApproveId = null;
            loadPending();
        } else {
            showToast(res.message || '操作失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

function doRejectPending() {
    if (_pendingBatchRejectId === null) return;
    fetch(API_BASE + '/pending/batch/' + encodeURIComponent(_pendingBatchRejectId) + '/reject', {
        method: 'POST', headers: apiHeaders()
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast(res.message || '已拒绝', 'success');
            closeModal('confirmRejectModal');
            _pendingBatchRejectId = null;
            loadPending();
        } else {
            showToast(res.message || '操作失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

function viewPendingBatch(batchId) {
    if (!batchId) {
        showToast('批次ID无效', 'error');
        return;
    }
    fetch(API_BASE + '/pending/batch/' + encodeURIComponent(batchId), { headers: apiHeaders() })
        .then(r => r.json())
        .then(res => {
            if (res.code === 0) {
                const items = res.data.items || [];
                const client = res.data.client;
                const total = res.data.total;

                let html = '';

                if (client) {
                    html += '<div style="margin-bottom:14px;padding:10px;background:#1a1a2e;border-radius:6px;border:1px solid #2a2a4a;">';
                    html += '<div style="color:#e94560;font-weight:bold;font-size:14px;margin-bottom:8px;">来源客户端</div>';
                    const cliLines = [
                        ['客户端ID', client.client_id],
                        ['主机名', client.hostname],
                        ['版本', client.version],
                        ['系统', client.os],
                        ['IP地址', client.ip_address],
                        ['注册时间', client.registered_at],
                        ['最后在线', client.last_seen],
                    ];
                    html += '<table style="width:100%;border-collapse:collapse;">';
                    for (const [label, value] of cliLines) {
                        html += `<tr><td style="padding:3px 8px;color:#aaa;width:80px;white-space:nowrap;font-size:12px;">${esc(label)}</td><td style="padding:3px 8px;font-size:12px;">${esc(String(value || '-'))}</td></tr>`;
                    }
                    html += '</table></div>';
                }

                html += `<div style="color:#e94560;font-weight:bold;font-size:14px;margin-bottom:8px;">推送IP列表（共 ${total} 条）</div>`;
                html += '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;">';
                html += '<tr style="background:#0f3460;"><th style="padding:4px 6px;text-align:left;font-size:12px;color:#a0a0c0;white-space:nowrap;">IP</th><th style="padding:4px 6px;text-align:left;font-size:12px;color:#a0a0c0;white-space:nowrap;width:40px;">端口</th><th style="padding:4px 6px;text-align:left;font-size:12px;color:#a0a0c0;white-space:nowrap;width:70px;">威胁类型</th><th style="padding:4px 6px;text-align:left;font-size:12px;color:#a0a0c0;white-space:nowrap;width:70px;">归属地</th><th style="padding:4px 6px;text-align:left;font-size:12px;color:#a0a0c0;white-space:nowrap;width:70px;">标签</th><th style="padding:4px 6px;text-align:left;font-size:12px;color:#a0a0c0;white-space:nowrap;width:70px;">关联病毒</th><th style="padding:4px 6px;text-align:left;font-size:12px;color:#a0a0c0;">描述</th><th style="padding:4px 6px;text-align:left;font-size:12px;color:#a0a0c0;white-space:nowrap;width:100px;">操作</th></tr>';
                for (const item of items) {
                    actionHtml = '';
                    if (item.review_status === 'pending') {
                        actionHtml = `
                            <button class="btn btn-sm btn-success" data-action="approveItem" data-id="${item.id}" data-batch-id="${batchId}" style="padding:2px 6px;font-size:11px;">批准</button>
                            <button class="btn btn-sm btn-danger" data-action="rejectItem" data-id="${item.id}" data-batch-id="${batchId}" style="padding:2px 6px;font-size:11px;">拒绝</button>
                        `;
                    }
                    html += `<tr><td style="padding:3px 6px;border-bottom:1px solid #2a2a4a;font-family:monospace;font-size:12px;white-space:nowrap;">${esc(item.ip)}</td><td style="padding:3px 6px;border-bottom:1px solid #2a2a4a;font-size:12px;white-space:nowrap;">${item.port || '-'}</td><td style="padding:3px 6px;border-bottom:1px solid #2a2a4a;font-size:12px;white-space:nowrap;">${esc(item.threat_type || '-')}</td><td style="padding:3px 6px;border-bottom:1px solid #2a2a4a;font-size:12px;white-space:nowrap;">${esc(item.location || '-')}</td><td style="padding:3px 6px;border-bottom:1px solid #2a2a4a;font-size:12px;white-space:nowrap;">${esc(item.tags || '-')}</td><td style="padding:3px 6px;border-bottom:1px solid #2a2a4a;font-size:12px;white-space:nowrap;">${esc(item.related_virus || '-')}</td><td style="padding:3px 6px;border-bottom:1px solid #2a2a4a;font-size:12px;">${esc(item.description || '-')}</td><td style="padding:3px 6px;border-bottom:1px solid #2a2a4a;font-size:12px;white-space:nowrap;">${actionHtml}</td></tr>`;
                }
                html += '</table></div>';

                document.getElementById('pendingDetailBody').innerHTML = html;
                openModal('pendingDetailModal');
            } else {
                showToast(res.message || '加载批次详情失败', 'error');
            }
        })
        .catch(() => showToast('网络错误', 'error'));
}

function approvePendingItem(id, batchId) {
    fetch(API_BASE + '/pending/ips/' + id + '/approve', {
        method: 'POST', headers: apiHeaders()
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast('已批准', 'success');
            viewPendingBatch(batchId);
        } else {
            showToast(res.message || '操作失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

function rejectPendingItem(id, batchId) {
    fetch(API_BASE + '/pending/ips/' + id + '/reject', {
        method: 'POST', headers: apiHeaders()
    })
    .then(r => r.json())
    .then(res => {
        if (res.code === 0) {
            showToast('已拒绝', 'success');
            viewPendingBatch(batchId);
        } else {
            showToast(res.message || '操作失败', 'error');
        }
    })
    .catch(() => showToast('网络错误', 'error'));
}

// ========== 页面初始化 ==========
document.addEventListener('DOMContentLoaded', function() {
    const username = getUsername();
    const userEl = document.getElementById('displayUser');
    if (userEl && username) {
        userEl.textContent = username;
    }

    if (currentTab === 'dashboard') loadDashboard();

    // 全局事件委托：处理所有 data-action 按钮点击
    document.addEventListener('click', function(e) {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;
        const id = parseInt(btn.dataset.id);
        if (action === 'editIP') editIP(id);
        else if (action === 'deleteIP') deleteIP(id);
        else if (action === 'toggleIPStatus') toggleStatus(id, btn.dataset.status);
        else if (action === 'updateKey') showUpdateKeyModal(id, btn.dataset.purpose);
        else if (action === 'deleteKey') showDeleteKeyModal(id, btn.dataset.purpose);
    });
});