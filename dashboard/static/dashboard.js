/**
 * CORTEX Dashboard — Main JavaScript
 * Handles data fetching, rendering, auto-refresh, and interactions.
 */

// ---- Utility Functions ----

function getToken() {
    const params = new URLSearchParams(window.location.search);
    return params.get('token') || '';
}

function apiUrl(path) {
    const token = getToken();
    const sep = path.includes('?') ? '&' : '?';
    return token ? `${path}${sep}token=${token}` : path;
}

async function fetchJSON(url) {
    try {
        const res = await fetch(apiUrl(url));
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (err) {
        console.error(`[CORTEX] Fetch error: ${url}`, err);
        return null;
    }
}

function formatTimestamp(ts) {
    if (!ts) return '—';
    const d = new Date(ts.replace(' ', 'T'));
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString('en-US', {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false
    });
}

function severityBadge(severity) {
    if (!severity) return '<span class="badge badge-low">N/A</span>';
    const s = severity.toUpperCase();
    return `<span class="badge badge-${s.toLowerCase()}">${s}</span>`;
}

function actionBadge(action) {
    if (!action) return '';
    const cls = action.toLowerCase().replace('_', '-');
    return `<span class="badge badge-${cls}">${action}</span>`;
}

function updateHeaderTime() {
    const el = document.getElementById('header-timestamp');
    if (el) {
        el.textContent = new Date().toLocaleString('en-US', {
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false
        });
    }
}

// ---- Update header time every second ----
setInterval(updateHeaderTime, 1000);
updateHeaderTime();


// =============================================
//  OVERVIEW PAGE
// =============================================

async function loadOverview() {
    const data = await fetchJSON('/admin/stats');
    if (!data) return;

    // Metric cards
    setMetric('metric-users', data.total_users);
    setMetric('metric-logins', data.logins_24h.total);
    setMetric('metric-success', data.logins_24h.success);
    setMetric('metric-fail', data.logins_24h.fail);
    setMetric('metric-locks', data.active_locks.account + data.active_locks.ip);
    setMetric('metric-risk', data.avg_risk_today);

    // Sub-details
    setSub('sub-locks', `Account: ${data.active_locks.account} · IP: ${data.active_locks.ip}`);

    // Top risk users
    const tbody = document.getElementById('top-risk-tbody');
    if (tbody) {
        if (data.top_risk_users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state"><p>No risk data yet</p></td></tr>';
        } else {
            tbody.innerHTML = data.top_risk_users.map(u => `
                <tr>
                    <td>${u.username || 'ID: ' + u.id}</td>
                    <td><span class="metric-value ${riskColor(u.cumulative_risk)}" style="font-size:14px">${u.cumulative_risk}</span></td>
                    <td>${severityBadge(riskSeverity(u.cumulative_risk))}</td>
                    <td>${formatTimestamp(u.last_updated)}</td>
                </tr>
            `).join('');
        }
    }

    // Recent actions
    const actionsTbody = document.getElementById('recent-actions-tbody');
    if (actionsTbody) {
        if (data.recent_actions.length === 0) {
            actionsTbody.innerHTML = '<tr><td colspan="6" class="empty-state"><p>No enforcement actions yet</p></td></tr>';
        } else {
            actionsTbody.innerHTML = data.recent_actions.map(a => `
                <tr>
                    <td>${formatTimestamp(a.timestamp)}</td>
                    <td>${a.username || 'ID: ' + (a.user_id || '?')}</td>
                    <td>${a.ip_address || '—'}</td>
                    <td>${a.risk_score || 0}</td>
                    <td>${severityBadge(a.severity)}</td>
                    <td>${actionBadge(a.enforcement_action)}</td>
                </tr>
            `).join('');
        }
    }
}

function setMetric(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value ?? '—';
}

function setSub(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function riskColor(score) {
    if (score >= 60) return 'red';
    if (score >= 30) return 'amber';
    return 'green';
}

function riskSeverity(score) {
    if (score >= 60) return 'HIGH';
    if (score >= 30) return 'MEDIUM';
    return 'LOW';
}


// =============================================
//  USERS PAGE
// =============================================

async function loadUsers() {
    const data = await fetchJSON('/admin/users/data');
    if (!data) return;

    const tbody = document.getElementById('users-tbody');
    if (!tbody) return;

    if (data.users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><p>No users registered</p></td></tr>';
        return;
    }

    tbody.innerHTML = data.users.map(u => `
        <tr class="user-row" data-user-id="${u.id}" onclick="showUserDetail(${u.id})" style="cursor:pointer">
            <td>${u.username}</td>
            <td>${formatTimestamp(u.last_login)}</td>
            <td><span class="metric-value ${riskColor(u.cumulative_risk)}" style="font-size:14px">${u.cumulative_risk}</span></td>
            <td>${severityBadge(u.severity)}</td>
            <td>${u.is_locked ? '<span class="badge badge-locked">LOCKED</span>' : '<span class="badge badge-allowed">ACTIVE</span>'}</td>
            <td>${u.total_logins}</td>
            <td>
                ${u.is_locked ? `<button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); unlockUser(${u.id})">Unlock</button>` : ''}
                <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); removeUser(${u.id})">Delete</button>
            </td>
        </tr>
    `).join('');
}

async function showUserDetail(userId) {
    const data = await fetchJSON(`/admin/users/${userId}/history`);
    if (!data) return;

    const overlay = document.getElementById('user-modal');
    const content = document.getElementById('modal-content');
    if (!overlay || !content) return;

    const u = data.user;

    let html = `
        <h2>User: ${u.username} (ID: ${u.id})</h2>
        <div class="metrics-grid" style="margin-bottom:20px">
            <div class="metric-card blue">
                <div class="metric-label">Status</div>
                <div class="metric-value" style="font-size:16px">${u.is_locked ? 'LOCKED' : 'ACTIVE'}</div>
            </div>
            <div class="metric-card amber">
                <div class="metric-label">Risk Memory</div>
                <div class="metric-value amber" style="font-size:18px">${data.risk_memory ? data.risk_memory.cumulative_risk : 0}</div>
            </div>
            <div class="metric-card green">
                <div class="metric-label">Created</div>
                <div class="metric-value" style="font-size:14px">${formatTimestamp(u.created_at)}</div>
            </div>
        </div>

        <div class="section-title">Login History (Last 50)</div>
        <div class="table-container card" style="margin-bottom:20px">
            <table>
                <thead><tr><th>Time</th><th>IP</th><th>Device</th><th>Status</th></tr></thead>
                <tbody>
                    ${data.login_history.length === 0 ? '<tr><td colspan="4" class="empty-state"><p>No logins</p></td></tr>' :
                      data.login_history.map(l => `
                        <tr>
                            <td>${formatTimestamp(l.timestamp)}</td>
                            <td>${l.ip_address || '—'}</td>
                            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${l.device_info || '—'}</td>
                            <td><span class="badge badge-${l.status === 'SUCCESS' ? 'success' : 'fail'}">${l.status}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <div class="section-title">Enforcement History (Last 50)</div>
        <div class="table-container card">
            <table>
                <thead><tr><th>Time</th><th>Score</th><th>Severity</th><th>Action</th></tr></thead>
                <tbody>
                    ${data.enforcement_history.length === 0 ? '<tr><td colspan="4" class="empty-state"><p>No enforcement logs</p></td></tr>' :
                      data.enforcement_history.map(e => `
                        <tr>
                            <td>${formatTimestamp(e.timestamp)}</td>
                            <td>${e.risk_score || 0}</td>
                            <td>${severityBadge(e.severity)}</td>
                            <td>${actionBadge(e.enforcement_action)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;

    content.innerHTML = html;
    overlay.classList.add('visible');
}

function closeModal() {
    const overlay = document.getElementById('user-modal');
    if (overlay) overlay.classList.remove('visible');
}

async function unlockUser(userId) {
    const res = await fetch(apiUrl(`/admin/unlock/${userId}`), { method: 'POST' });
    const data = await res.json();

    if (data.status === 'unlocked') {
        alert(`User ${data.username} unlocked successfully.`);
        loadUsers();
    } else {
        alert('Failed to unlock user.');
    }
}

async function removeUser(userId) {
    if (!confirm('Are you sure you want to permanently delete this user?')) return;
    const res = await fetch(apiUrl(`/admin/users/${userId}/delete`), { method: 'POST' });
    const data = await res.json();
    if (data.status === 'deleted') {
        alert('User deleted successfully.');
        loadUsers();
    } else {
        alert('Failed to delete user: ' + (data.error || 'Unknown error'));
    }
}


// =============================================
//  LOGS PAGE
// =============================================

let logsPage = 1;

async function loadLogs(page) {
    logsPage = page || 1;
    const severity = document.getElementById('filter-severity')?.value || '';
    const action = document.getElementById('filter-action')?.value || '';

    let url = `/admin/logs/data?page=${logsPage}&per_page=20`;
    if (severity) url += `&severity=${severity}`;
    if (action) url += `&action=${action}`;

    const data = await fetchJSON(url);
    if (!data) return;

    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;

    if (data.logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state"><p>No enforcement logs found</p></td></tr>';
        updatePagination(0, 0, 0);
        return;
    }

    tbody.innerHTML = data.logs.map((log, idx) => {
        const rowId = `log-row-${idx}`;
        const panelId = `log-panel-${idx}`;
        const hasExplanation = log.explanation && typeof log.explanation === 'object';

        let expansionHtml = '';
        if (hasExplanation) {
            const exp = log.explanation;
            expansionHtml = `
                <tr id="${panelId}" class="expansion-panel">
                    <td colspan="7">
                        <div class="expansion-content">
                            <strong>Decision:</strong> ${exp.decision || '—'}<br>
                            <strong>Reason:</strong> ${exp.reason_summary || '—'}<br>
                            <strong>Recommended Action:</strong> ${exp.recommended_action || '—'}
                            ${exp.risk_breakdown && exp.risk_breakdown.length > 0 ? `
                                <div class="risk-breakdown" style="margin-top:10px">
                                    <strong>Risk Breakdown:</strong>
                                    ${exp.risk_breakdown.map(rb => `
                                        <div class="risk-breakdown-item">
                                            <span class="risk-rule-name">${rb.rule}</span>
                                            <span class="risk-points">+${rb.points}</span>
                                            <span class="risk-explanation">${rb.explanation || ''}</span>
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''}
                        </div>
                    </td>
                </tr>
            `;
        }

        return `
            <tr id="${rowId}" class="expandable-row ${hasExplanation ? '' : ''}" onclick="${hasExplanation ? `toggleExpand('${rowId}','${panelId}')` : ''}">
                <td>${hasExplanation ? '<span class="expand-icon">▶</span>' : ''}${formatTimestamp(log.timestamp)}</td>
                <td>${log.username || 'ID: ' + (log.user_id || '?')}</td>
                <td>${log.ip_address || '—'}</td>
                <td>${log.risk_score || 0}</td>
                <td>${severityBadge(log.severity)}</td>
                <td>${actionBadge(log.enforcement_action)}</td>
                <td>${log.decay_applied ? '<span class="badge badge-low">DECAY</span>' : ''}</td>
            </tr>
            ${expansionHtml}
        `;
    }).join('');

    updatePagination(data.page, data.total_pages, data.total);
}

function toggleExpand(rowId, panelId) {
    const row = document.getElementById(rowId);
    const panel = document.getElementById(panelId);
    if (!row || !panel) return;

    row.classList.toggle('expanded');
    panel.classList.toggle('visible');
}

function updatePagination(current, totalPages, total) {
    const container = document.getElementById('pagination');
    if (!container) return;

    if (totalPages <= 1) {
        container.innerHTML = total > 0 ? `<span class="page-info">${total} entries</span>` : '';
        return;
    }

    let html = '';
    if (current > 1) {
        html += `<button class="btn btn-sm" onclick="loadLogs(${current - 1})">← Prev</button>`;
    }

    html += `<span class="page-info">Page ${current} of ${totalPages} (${total} entries)</span>`;

    if (current < totalPages) {
        html += `<button class="btn btn-sm" onclick="loadLogs(${current + 1})">Next →</button>`;
    }

    container.innerHTML = html;
}

function applyLogFilters() {
    loadLogs(1);
}


// =============================================
//  THREATS PAGE
// =============================================

async function loadThreats() {
    const data = await fetchJSON('/admin/threats/data');
    if (!data) return;

    // Rules table
    const rulesTbody = document.getElementById('threats-rules-tbody');
    if (rulesTbody) {
        if (data.rules.length === 0) {
            rulesTbody.innerHTML = '<tr><td colspan="3" class="empty-state"><p>No rules triggered in 24h</p></td></tr>';
        } else {
            rulesTbody.innerHTML = data.rules.map(r => `
                <tr>
                    <td>${r.rule_name}</td>
                    <td>${r.count}</td>
                    <td><span class="metric-value red" style="font-size:14px">+${r.total_points}</span></td>
                </tr>
            `).join('');
        }
    }

    // Top IPs table
    const ipsTbody = document.getElementById('threats-ips-tbody');
    if (ipsTbody) {
        if (data.top_ips.length === 0) {
            ipsTbody.innerHTML = '<tr><td colspan="3" class="empty-state"><p>No attacking IPs detected</p></td></tr>';
        } else {
            ipsTbody.innerHTML = data.top_ips.map(ip => `
                <tr>
                    <td style="color:var(--accent-amber)">${ip.ip}</td>
                    <td>${ip.attempts}</td>
                    <td><span class="metric-value red" style="font-size:14px">${ip.total_risk}</span></td>
                </tr>
            `).join('');
        }
    }

    // Blocked IPs table
    const blockedTbody = document.getElementById('threats-blocked-tbody');
    if (blockedTbody) {
        if (!data.blocked_ips || data.blocked_ips.length === 0) {
            blockedTbody.innerHTML = '<tr><td colspan="4" class="empty-state"><p>No IPs currently blocked</p></td></tr>';
        } else {
            blockedTbody.innerHTML = data.blocked_ips.map(ip => `
                <tr>
                    <td style="color:var(--accent-red)">${ip.ip_address}</td>
                    <td>${formatTimestamp(ip.lock_until)}</td>
                    <td>${ip.reason || '—'}</td>
                    <td><button class="btn btn-sm btn-primary" onclick="unblockIP('${ip.ip_address}')">Unblock</button></td>
                </tr>
            `).join('');
        }
    }
}


// =============================================
//  SYSTEM PAGE
// =============================================

async function loadSystem() {
    const data = await fetchJSON('/admin/system/data');
    if (!data) return;

    setMetric('sys-db-size', data.db_size_readable);
    setMetric('sys-total-logs', data.total_logs);
    setMetric('sys-decay-events', data.decay_events_today);
    setMetric('sys-feed-updated', data.feed_last_updated || 'Never');
    setMetric('sys-feed-entries', data.feed_entries);
    setMetric('sys-total-attempts', data.total_attempts);
    setMetric('sys-total-users', data.total_users);
}

async function refreshFeeds() {
    const btn = document.getElementById('btn-refresh-feeds');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Refreshing...';
    }

    const data = await fetchJSON('/admin/feeds/refresh');

    if (btn) {
        btn.disabled = false;
        btn.textContent = 'Refresh Feeds';
    }

    if (data && data.refreshed) {
        alert(`Threat feeds refreshed: ${data.entries} entries loaded.`);
        loadSystem();
    }
}


// =============================================
//  AUTO-REFRESH
// =============================================

function startAutoRefresh(loadFn, intervalMs) {
    loadFn();
    setInterval(loadFn, intervalMs);
}


// =============================================
//  LOGIN PAGE
// =============================================

async function adminLogin() {
    const tokenInput = document.getElementById('admin-token-input');
    const errorEl = document.getElementById('login-error');
    if (!tokenInput) return;

    const token = tokenInput.value.trim();

    try {
        const res = await fetch('/admin/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });

        if (res.ok) {
            window.location.href = `/admin?token=${encodeURIComponent(token)}`;
        } else {
            if (errorEl) {
                errorEl.textContent = 'Invalid admin token.';
                errorEl.style.display = 'block';
            }
        }
    } catch (err) {
        if (errorEl) {
            errorEl.textContent = 'Connection error.';
            errorEl.style.display = 'block';
        }
    }
}

function handleLoginKeypress(e) {
    if (e.key === 'Enter') adminLogin();
}


// =============================================
//  MANUAL IP UNBLOCK
// =============================================

async function unblockIP(ipAddress) {
    const ip = ipAddress || prompt('Enter IP address to unblock:');
    if (!ip) return;

    if (!confirm(`Are you sure you want to unblock IP ${ip}?`)) return;

    const res = await fetch(apiUrl('/admin/ip/unblock'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });

    const data = await res.json();
    if (data.status === 'unblocked') {
        alert(`IP ${ip} unblocked.`);
        if (typeof loadThreats === 'function') loadThreats();
    } else {
        alert('Failed to unblock IP.');
    }
}
