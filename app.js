/**
 * MAESTER Cybersecurity Platform - Full Stack UI Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initDrawer();
    initInteractiveElements();
    initChatEngine();
    initVAPTEngine();
    initRedTeamEngine();
    initDashboard();
    initNotifications();
    initFindings();
    initBlueTeam();
    initGRC();
    initThreatIntel();
    initSOC();
    initSIEM();
    initSearch();
    initCompliance();
    initPurpleTeam();
});

/**
 * Global State & Helpers
 */
const API_BASE = '/api/v1';

async function apiFetch(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
        return await response.json();
    } catch (error) {
        console.error(`Fetch error [${endpoint}]:`, error);
        return null;
    }
}

/**
 * Handle View Navigation
 */
function initNavigation() {
    const navItems = document.querySelectorAll('.sidebar-item');
    const views = document.querySelectorAll('.view-section');
    const breadcrumb = document.getElementById('breadcrumb');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetViewId = item.getAttribute('data-view');
            
            // Handle active states
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            // Handle view switching
            views.forEach(view => {
                const isActive = view.id === targetViewId;
                view.classList.toggle('active', isActive);
                if (view.id === 'chat') {
                    view.style.display = isActive ? 'flex' : 'none';
                }
            });

            // Update Breadcrumb
            const sectionEl = item.closest('.sidebar-section')?.querySelector('.sidebar-label');
            const section = sectionEl ? sectionEl.textContent : 'Platform';
            breadcrumb.textContent = `${section.charAt(0) + section.slice(1).toLowerCase()} / ${item.querySelector('span:not(.badge)').textContent}`;
            
            // Close drawer if open
            document.getElementById('drawer-backdrop').classList.remove('active');
            document.getElementById('detail-drawer').classList.remove('active');
        });
    });
}

/**
 * Dashboard Integration
 */
async function initDashboard() {
    const refreshDashboard = async () => {
        const stats = await apiFetch('/dashboard');
        if (!stats) return;

        // Update Risk Score
        const riskScoreVal = document.querySelector('.risk-score-value');
        const riskRing = document.querySelector('.risk-score-container svg circle:last-child');
        if (riskScoreVal) riskScoreVal.textContent = stats.risk_score;
        if (riskRing) {
            const circumference = 339; // 2 * PI * 54
            riskRing.style.strokeDashoffset = circumference - (circumference * stats.risk_score / 100);
        }

        // Update Stats Cards
        const dashboardCards = document.querySelectorAll('.card .display-xl, .card .display-m');
        // This mapping depends on the HTML structure, usually we'd use IDs
        // For the demo, let's just update the ones we know
        const findingCounts = document.querySelectorAll('.finding-count');
        if (findingCounts.length >= 3) {
            findingCounts[0].textContent = stats.critical_findings;
            findingCounts[1].textContent = stats.open_findings - stats.critical_findings;
            findingCounts[2].textContent = stats.total_findings - stats.open_findings;
        }
    };

    refreshDashboard();
    setInterval(refreshDashboard, 10000); // Refresh every 10s
}

/**
 * Notifications Engine
 */
async function initNotifications() {
    const btn = document.getElementById('notification-btn');
    const dropdown = document.getElementById('notification-dropdown');
    const badge = document.getElementById('notification-badge');
    const list = document.getElementById('notification-list');
    const markRead = document.getElementById('mark-read-btn');

    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('active');
    });

    document.addEventListener('click', () => dropdown.classList.remove('active'));
    dropdown.addEventListener('click', (e) => e.stopPropagation());

    const refreshNotifications = async () => {
        const notes = await apiFetch('/notifications');
        if (!notes) return;

        const unread = notes.filter(n => !n.read).length;
        badge.style.display = unread > 0 ? 'block' : 'none';
        badge.textContent = unread;

        if (notes.length === 0) {
            list.innerHTML = '<div class="empty-state" style="padding: 24px; text-align: center; color: var(--apple-gray-2);">No new notifications</div>';
        } else {
            list.innerHTML = notes.map(n => `
                <div class="notification-item ${n.read ? '' : 'unread'}">
                    <div class="body-m">${n.message}</div>
                    <div class="caption" style="color: var(--apple-gray-2); margin-top: 4px;">${new Date(n.timestamp * 1000).toLocaleTimeString()}</div>
                </div>
            `).join('');
        }
    };

    markRead.addEventListener('click', async () => {
        await apiFetch('/notifications/read', { method: 'POST' });
        refreshNotifications();
    });

    refreshNotifications();
}

/**
 * VAPT Engine
 */
function initVAPTEngine() {
    const launchBtn = document.querySelector('#vapt .btn-primary');
    const targetInput = document.querySelector('#vapt input[placeholder="Add IP or domain..."]');
    const tagContainer = document.querySelector('#vapt .tag-input-container');

    if (!targetInput) return;

    targetInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && targetInput.value.trim()) {
            const val = targetInput.value.trim();
            const chip = document.createElement('span');
            chip.className = 'chip';
            chip.innerHTML = `<span class="mono">${val}</span><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="margin-left:8px; cursor:pointer;" onclick="this.parentElement.remove()"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
            tagContainer.insertBefore(chip, targetInput);
            targetInput.value = '';
        }
    });

    launchBtn.addEventListener('click', async () => {
        const chips = Array.from(tagContainer.querySelectorAll('.chip .mono')).map(c => c.textContent);
        if (targetInput.value) chips.push(targetInput.value);
        if (chips.length === 0) return alert('Please enter at least one target.');
        
        const res = await apiFetch('/scan', {
            method: 'POST',
            body: JSON.stringify({ target: chips.join(','), type: 'network' })
        });

        if (res && res.scan_id) {
            launchBtn.disabled = true;
            launchBtn.classList.add('btn-secondary');
            launchBtn.classList.remove('btn-primary');
            launchBtn.textContent = 'Scan in Progress...';
            
            const poll = setInterval(async () => {
                const status = await apiFetch(`/scan/${res.scan_id}`);
                if (!status) return;

                const progressText = document.querySelector('#vapt .risk-score-value');
                const progressRing = document.querySelector('#vapt .risk-score-container svg circle:last-child');
                const phaseText = document.querySelector('#vapt .overline:nth-of-type(2)');

                if (progressText) progressText.textContent = `${status.progress}%`;
                if (progressRing) {
                    const circumference = 465; // 2 * PI * 74
                    progressRing.style.strokeDashoffset = circumference - (circumference * status.progress / 100);
                }
                if (phaseText) phaseText.textContent = `Phase: ${status.phase}`;

                if (status.status === 'Completed') {
                    clearInterval(poll);
                    launchBtn.disabled = false;
                    launchBtn.classList.add('btn-primary');
                    launchBtn.classList.remove('btn-secondary');
                    launchBtn.textContent = 'Assessment Finished (View Findings)';
                    launchBtn.onclick = () => document.querySelector('.sidebar-item[data-view="findings"]').click();
                }
            }, 1000);
        }
    });
}

/**
 * Red Team Engine
 */
function initRedTeamEngine() {
    const dispatchBtn = document.getElementById('dispatch-task-btn');
    const taskInput = document.getElementById('red-team-task-input');
    const terminal = document.querySelector('.terminal-output');
    const taskQueue = document.querySelector('.task-queue');

    if (!dispatchBtn) return;

    dispatchBtn.addEventListener('click', async () => {
        const cmd = taskInput.value.trim();
        if (!cmd) return;

        // Add task to queue UI
        const taskId = `T-${Math.floor(Math.random()*1000)}`;
        const taskCard = document.createElement('div');
        taskCard.className = 'task-card card active-task';
        taskCard.innerHTML = `
            <div class="task-order mono">${taskId}</div>
            <div class="task-content">
                <div class="task-label">${cmd}</div>
                <div class="task-tool"><span class="chip">Executing...</span></div>
            </div>
            <div class="task-status">
                <svg class="spinner" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="var(--apple-blue)" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-linecap="round"></circle></svg>
            </div>
        `;
        taskQueue.prepend(taskCard);

        const res = await apiFetch('/task', {
            method: 'POST',
            body: JSON.stringify({ command: cmd })
        });

        if (res && res.task_id) {
            taskInput.value = '';
            let offset = 0;
            const poll = setInterval(async () => {
                const data = await apiFetch(`/task/${res.task_id}/logs?offset=${offset}`);
                if (!data) return;

                data.logs.forEach(log => {
                    const line = document.createElement('div');
                    line.className = 'term-line info';
                    line.textContent = log;
                    terminal.appendChild(line);
                });
                offset = data.next_offset;
                terminal.scrollTop = terminal.scrollHeight;

                if (data.status === 'Completed') {
                    clearInterval(poll);
                    taskCard.classList.remove('active-task');
                    taskCard.querySelector('.task-status').innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20" fill="var(--low-green)"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
                    taskCard.querySelector('.chip').textContent = 'Done';
                }
            }, 1000);
        }
    });
}

/**
 * Chat Engine (LLM)
 */
function initChatEngine() {
    const input = document.querySelector('.chat-input');
    const btn = document.querySelector('.send-btn');
    const container = document.querySelector('.chat-messages');

    const addMessage = (text, isUser = false, actions = []) => {
        const msgHtml = isUser ? `
            <div class="message user-message">
                <div class="msg-bubble">${text}</div>
            </div>
        ` : `
            <div class="message system-message">
                <div class="agent-label">
                    <span class="chip" style="background: #F0F6FF; color: var(--apple-blue);"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px"><circle cx="12" cy="12" r="10"></circle></svg> MAESTER Agent</span>
                </div>
                <div class="msg-card">
                    <p>${text}</p>
                    ${actions.length ? `<div style="margin-top:12px; display:flex; gap:8px;">${actions.map(a => `<button class="btn btn-secondary chat-action" data-action="${a.action}">${a.label}</button>`).join('')}</div>` : ''}
                </div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', msgHtml);
        container.scrollTop = container.scrollHeight;

        // Wire actions
        container.querySelectorAll('.chat-action').forEach(b => {
            b.onclick = () => {
                const action = b.getAttribute('data-action');
                if (action.startsWith('nav:')) {
                    const view = action.split(':')[1];
                    const navLink = document.querySelector(`.sidebar-item[data-view="${view}"]`);
                    if (navLink) navLink.click();
                }
            };
        });
    };

    btn.addEventListener('click', async () => {
        const msg = input.value.trim();
        if (!msg) return;
        input.value = '';
        addMessage(msg, true);
        
        const res = await apiFetch('/chat', {
            method: 'POST',
            body: JSON.stringify({ message: msg })
        });
        if (res) addMessage(res.response, false, res.actions);
    });

    input.onkeypress = (e) => { if (e.key === 'Enter') btn.click(); };
}

/**
 * SIEM Engine
 */
function initSIEM() {
    const queryBtn = document.querySelector('#siem .btn-secondary');
    const queryInput = document.querySelector('#siem .search-input');
    const logViewer = document.querySelector('.siem-log-viewer');

    if (!queryBtn) return;

    queryBtn.onclick = async () => {
        const q = queryInput.value || '*';
        logViewer.innerHTML = `<div class="siem-log-line">[SYSTEM] Running query: ${q}...</div>`;
        
        // Simulate logs after a delay
        setTimeout(() => {
            const logs = [
                `2026-05-12 15:10:01 INFO 10.0.1.5 ACCESS_GRANTED /admin/settings`,
                `2026-05-12 15:10:05 WARN 192.168.1.10 AUTH_FAILED root`,
                `2026-05-12 15:10:12 INFO 10.0.4.22 DB_QUERY SELECT * FROM users`,
                `2026-05-12 15:10:15 CRITICAL 185.x.x.x SQL_INJECTION_DETECTED ' OR 1=1`
            ];
            logViewer.innerHTML = logs.map(l => `<div class="siem-log-line">${l}</div>`).join('');
        }, 800);
    };
}

/**
 * Findings Module
 */
async function initFindings() {
    const list = document.querySelector('#findings tbody');
    if (!list) return;

    const refreshFindings = async () => {
        const findings = await apiFetch('/findings');
        if (!findings) return;

        list.innerHTML = findings.map(f => `
            <tr class="interactive-row" onclick="window.showFindingDetail('${f.id}')">
                <td style="padding-left: 24px;"><span class="badge-pill badge-${f.severity}">${f.severity}</span></td>
                <td class="mono">${f.id}</td>
                <td style="font-weight: 600;">${f.title}</td>
                <td class="mono">${f.asset}</td>
                <td>${f.tool}</td>
                <td style="font-weight: 600;">${f.cvss}</td>
                <td><span class="exploit-tag tag-red">Active</span></td>
                <td><span class="status-chip status-${f.status}">${f.status}</span></td>
                <td class="caption">${new Date(f.created_at * 1000).toLocaleDateString()}</td>
            </tr>
        `).join('');
    };

    window.showFindingDetail = async (fid) => {
        // Find finding in local data or fetch
        const findings = await apiFetch('/findings');
        const f = findings.find(x => x.id === fid);
        if (!f) return;

        const drawer = document.getElementById('detail-drawer');
        const content = document.getElementById('drawer-content');
        const title = document.getElementById('drawer-title');

        title.textContent = f.title;
        content.innerHTML = `
            <div class="card" style="margin-bottom: 16px;">
                <div class="overline">Asset</div>
                <div class="mono">${f.asset}</div>
            </div>
            <div class="card" style="margin-bottom: 16px;">
                <div class="overline">Severity</div>
                <span class="badge-pill badge-${f.severity}">${f.severity}</span>
            </div>
            <p class="body-m">${f.description}</p>
            <button class="btn btn-primary" style="width:100%; margin-top:24px;" onclick="window.remediateFinding('${f.id}')">Mark as Remediated</button>
        `;
        drawer.classList.add('active');
        document.getElementById('drawer-backdrop').classList.add('active');
    };

    window.remediateFinding = async (fid) => {
        await apiFetch(`/findings/${fid}`, {
            method: 'PATCH',
            body: JSON.stringify({ status: 'remediated' })
        });
        document.getElementById('detail-drawer').classList.remove('active');
        document.getElementById('drawer-backdrop').classList.remove('active');
        refreshFindings();
    };

    refreshFindings();
}

/**
 * Blue Team Module
 */
async function initBlueTeam() {
    const list = document.querySelector('.alerts-feed');
    if (!list) return;

    const refreshAlerts = async () => {
        const alerts = await apiFetch('/alerts');
        if (!alerts) return;

        list.innerHTML = alerts.map(a => `
            <div class="alert-item ${a.status === 'resolved' ? '' : 'active'}" onclick="window.selectAlert('${a.id}')">
                <div class="alert-indicator" style="background: var(--${a.severity === 'critical' ? 'critical-red' : 'high-orange'})"></div>
                <div class="alert-content">
                    <div class="alert-title" style="font-weight: 600;">${a.title}</div>
                    <div class="alert-meta">
                        <span class="caption">${a.source}</span>
                        <span class="caption" style="color: var(--apple-gray-2)">${new Date(a.created_at * 1000).toLocaleTimeString()}</span>
                    </div>
                </div>
            </div>
        `).join('');
    };

    window.selectAlert = (aid) => {
        const detailBtn = document.querySelector('.col-playbook .btn-primary');
        if (detailBtn) {
            detailBtn.onclick = async () => {
                const res = await apiFetch(`/playbook/${aid}/execute`, { method: 'POST' });
                if (res) refreshAlerts();
            };
        }
    };

    refreshAlerts();
}

/**
 * GRC & Reports
 */
function initGRC() {
    const genBtn = document.getElementById('generate-report-btn-view');
    if (genBtn) {
        genBtn.onclick = async () => {
            const res = await apiFetch('/reports/generate', { method: 'POST' });
            if (res) {
                genBtn.textContent = 'Report Generated!';
                setTimeout(() => genBtn.textContent = 'New Report', 2000);
                initReports(); // Refresh reports view
            }
        };
    }
}

async function initReports() {
    const list = document.getElementById('report-list');
    if (!list) return;

    const reports = await apiFetch('/reports');
    if (!reports) return;

    list.innerHTML = reports.map(r => `
        <tr>
            <td style="padding-left: 24px;">${r.name}</td>
            <td>${new Date(r.created_at * 1000).toLocaleString()}</td>
            <td><span class="status-chip status-remediated">Ready</span></td>
            <td><button class="btn btn-secondary" style="height:28px; font-size:12px;">Download</button></td>
        </tr>
    `).join('');
}

/**
 * Threat Intel
 */
async function initThreatIntel() {
    const list = document.getElementById('ioc-list');
    if (!list) return;

    const iocs = await apiFetch('/threat-intel');
    if (!iocs) return;

    list.innerHTML = iocs.map(i => `
        <tr>
            <td class="mono">${i.ioc_type.toUpperCase()}</td>
            <td class="mono">${i.value}</td>
            <td><span class="badge-pill badge-${i.severity}">${i.severity}</span></td>
            <td>${i.description}</td>
        </tr>
    `).join('');
}

/**
 * SOC Live Stream
 */
function initSOC() {
    const stream = document.getElementById('soc-event-stream');
    if (!stream) return;

    const refreshSOC = async () => {
        const events = await apiFetch('/soc/events');
        if (!events) return;

        stream.innerHTML = events.map(e => `
            <div class="term-line ${e.type.toLowerCase()}">
                [${e.type}] ${new Date(e.timestamp * 1000).toLocaleTimeString()} - ${e.message}
            </div>
        `).join('');
    };

    refreshSOC();
    setInterval(refreshSOC, 5000);
}

/**
 * Compliance Module
 */
async function initCompliance() {
    const container = document.querySelector('#compliance .compliance-bars');
    if (!container) return;

    const frameworks = await apiFetch('/compliance');
    if (!frameworks) return;

    container.innerHTML = frameworks.map(fw => {
        const total = fw.compliant + fw.non_compliant + fw.not_tested;
        const compPerc = (fw.compliant / total) * 100;
        const nonCompPerc = (fw.non_compliant / total) * 100;
        
        return `
            <div class="comp-row">
                <div class="card" style="padding: 16px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span class="body-m" style="font-weight: 600;">${fw.framework.toUpperCase().replace('_', ' ')}</span>
                        <span class="caption">${Math.round(compPerc)}% Compliant</span>
                    </div>
                    <div class="comp-bar">
                        <div style="width: ${compPerc}%; background: var(--low-green);"></div>
                        <div style="width: ${nonCompPerc}%; background: var(--critical-red);"></div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

/**
 * Purple Team Module
 */
async function initPurpleTeam() {
    const data = await apiFetch('/purple-team');
    if (!data) return;

    const attackVal = document.querySelector('#purple-team .split-left .display-s');
    const defenseVal = document.querySelector('#purple-team .split-right .display-s');
    
    if (attackVal) attackVal.textContent = `${data.attack_vectors} Active Vectors`;
    if (defenseVal) defenseVal.textContent = `${data.detection_coverage}% Detection Coverage`;
}

/**
 * Search
 */
function initSearch() {
    const searchInputs = document.querySelectorAll('.search-input');
    searchInputs.forEach(input => {
        input.onkeypress = async (e) => {
            if (e.key === 'Enter') {
                const results = await apiFetch(`/search?q=${input.value}`);
                if (results && results.length > 0) {
                    // Navigate to findings and highlight or filter?
                    // For now, let's just go to findings view if a finding is found
                    const navFindings = document.querySelector('.sidebar-item[data-view="findings"]');
                    if (navFindings) navFindings.click();
                    
                    // Simple highlight logic
                    setTimeout(() => {
                        const rows = document.querySelectorAll('#findings tbody tr');
                        rows.forEach(row => {
                            if (row.textContent.toLowerCase().includes(input.value.toLowerCase())) {
                                row.style.background = 'rgba(0, 113, 227, 0.1)';
                                row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            }
                        });
                    }, 500);
                } else {
                    alert('No results found for: ' + input.value);
                }
            }
        };
    });
}

/**
 * Drawer Controls
 */
function initDrawer() {
    const backdrop = document.getElementById('drawer-backdrop');
    const drawer = document.getElementById('detail-drawer');
    const close = document.getElementById('close-drawer');

    const hide = () => {
        backdrop.classList.remove('active');
        drawer.classList.remove('active');
    };

    backdrop.onclick = hide;
    close.onclick = hide;
}

function initInteractiveElements() {
    // Segmented Controls
    document.querySelectorAll('.segmented-control button').forEach(b => {
        b.onclick = () => {
            b.parentElement.querySelectorAll('button').forEach(x => x.classList.remove('active'));
            b.classList.add('active');
        };
    });
}
