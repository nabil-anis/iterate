/**
 * MAESTER Cybersecurity Platform - UI Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initDrawer();
    initInteractiveElements();
    initChatMock();
    initVAPTMock();
    initRedTeamEngine();
});

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
            
            // Handle active states on sidebar
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            // Handle view switching
            const targetViewId = item.getAttribute('data-view');
            views.forEach(view => {
                if (view.id === targetViewId) {
                    view.classList.add('active');
                    // Special case for chat view which has inline display handling in CSS
                    if (targetViewId === 'chat') {
                        view.style.display = 'block';
                    }
                } else {
                    view.classList.remove('active');
                    if (view.id === 'chat') {
                        view.style.display = 'none';
                    }
                }
            });

            // Update Breadcrumb
            const sectionLabel = item.closest('.sidebar-section').querySelector('.sidebar-label').textContent;
            const itemLabel = item.querySelector('span:not(.badge)').textContent;
            
            // Format breadcrumb based on view
            if (targetViewId === 'chat') {
                breadcrumb.textContent = `AI Interface / ${itemLabel}`;
            } else {
                // capitalize section label fully (it's already uppercase in HTML, but we want Title Case for breadcrumb)
                const sectionTitleCase = sectionLabel.charAt(0) + sectionLabel.slice(1).toLowerCase();
                breadcrumb.textContent = `${sectionTitleCase} / ${itemLabel}`;
            }
        });
    });
}

/**
 * Handle Detail Drawer Slide-in
 */
function initDrawer() {
    const drawer = document.getElementById('detail-drawer');
    const backdrop = document.getElementById('drawer-backdrop');
    const closeBtn = document.getElementById('close-drawer');
    const interactiveRows = document.querySelectorAll('.interactive-row');
    const drawerTitle = document.getElementById('drawer-title');
    const drawerContent = document.getElementById('drawer-content');

    const openDrawer = (title, contentHTML) => {
        drawerTitle.textContent = title;
        drawerContent.innerHTML = contentHTML;
        drawer.classList.add('open');
        backdrop.classList.add('open');
        document.body.style.overflow = 'hidden'; // Prevent background scrolling
    };

    const closeDrawer = () => {
        drawer.classList.remove('open');
        backdrop.classList.remove('open');
        document.body.style.overflow = '';
    };

    // Attach click listeners to rows (specifically in findings view)
    interactiveRows.forEach(row => {
        row.addEventListener('click', () => {
            const cells = row.querySelectorAll('td');
            if (cells.length < 3) return;
            
            const findingId = cells[1].textContent.trim();
            const findingTitle = cells[2].textContent.trim();
            const severityHtml = cells[0].innerHTML;
            const asset = cells[3].textContent.trim();
            
            // Mock content for the drawer based on the row clicked
            const mockContent = `
                <div style="margin-bottom: 24px;">
                    <div style="display: flex; gap: 12px; margin-bottom: 16px;">
                        ${severityHtml}
                        <span class="mono" style="color: var(--apple-gray-2); font-size: 13px; align-self: center;">${findingId}</span>
                    </div>
                    
                    <div class="card" style="margin-bottom: 24px;">
                        <div class="overline" style="margin-bottom: 16px;">Affected Asset</div>
                        <div class="mono" style="font-size: 15px;">${asset}</div>
                    </div>
                    
                    <div class="card" style="margin-bottom: 24px;">
                        <div class="overline" style="margin-bottom: 16px;">Vulnerability Description</div>
                        <p class="body-m" style="color: var(--apple-gray-1);">
                            This asset is affected by a critical vulnerability that could allow an unauthenticated, remote attacker to execute arbitrary code. 
                            The vulnerability is due to improper input validation in the affected component.
                        </p>
                    </div>

                    <div class="card" style="margin-bottom: 24px;">
                        <div class="overline" style="margin-bottom: 16px;">Remediation Guidance</div>
                        <ol class="body-m" style="color: var(--apple-gray-1); padding-left: 20px;">
                            <li style="margin-bottom: 8px;">Isolate the affected system from the network immediately.</li>
                            <li style="margin-bottom: 8px;">Apply the latest vendor patch corresponding to this CVE.</li>
                            <li style="margin-bottom: 8px;">Review system logs for indicators of compromise (IoCs) prior to patching.</li>
                        </ol>
                    </div>
                    
                    <button class="btn btn-primary" style="width: 100%;">Create Remediation Ticket</button>
                </div>
            `;
            
            openDrawer(findingTitle, mockContent);
        });
    });

    closeBtn.addEventListener('click', closeDrawer);
    backdrop.addEventListener('click', closeDrawer);
}

/**
 * Initialize miscellaneous interactive UI elements
 * (Toggles, Segmented Controls, Chat History selection)
 */
function initInteractiveElements() {
    // Toggles
    const toggles = document.querySelectorAll('.toggle');
    toggles.forEach(toggle => {
        toggle.addEventListener('click', () => {
            const thumb = toggle.querySelector('.thumb');
            if (toggle.style.background === 'var(--separator)' || !toggle.style.background) {
                // Turn ON
                toggle.style.background = 'var(--low-green)';
                thumb.style.left = '18px';
            } else {
                // Turn OFF
                toggle.style.background = 'var(--separator)';
                thumb.style.left = '2px';
            }
        });
    });

    // Segmented Controls
    const segmentedControls = document.querySelectorAll('.segmented-control');
    segmentedControls.forEach(control => {
        const buttons = control.querySelectorAll('button');
        buttons.forEach(btn => {
            btn.addEventListener('click', () => {
                buttons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            });
        });
    });

    // Chat History List
    const historyItems = document.querySelectorAll('.history-item');
    historyItems.forEach(item => {
        item.addEventListener('click', () => {
            historyItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
        });
    });

    // Team Selectors in Chat
    const teamChips = document.querySelectorAll('.team-selector-chip');
    teamChips.forEach(chip => {
        chip.addEventListener('click', () => {
            teamChips.forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
        });
    });
    
    // Alerts Feed in Blue Team
    const alertItems = document.querySelectorAll('.alert-item');
    alertItems.forEach(item => {
        item.addEventListener('click', () => {
            alertItems.forEach(a => a.classList.remove('active'));
            item.classList.add('active');
        });
    });
}

/**
 * Handle Chat Interactions — connected to /api/v1/chat
 */
function initChatMock() {
    const chatInput = document.querySelector('.chat-input');
    const sendBtn = document.querySelector('.send-btn');
    const chatMessages = document.querySelector('.chat-messages');

    if (!chatInput || !sendBtn || !chatMessages) {
        console.warn('[MAESTER] Chat init failed — missing elements:', {
            chatInput: !!chatInput, sendBtn: !!sendBtn, chatMessages: !!chatMessages
        });
        return;
    }

    const sendMessage = () => {
        const text = chatInput.value.trim();
        if (!text) return;

        // Clear input
        chatInput.value = '';

        // Create User Message (matches existing HTML structure)
        const userHtml = `
            <div class="message user-message" style="animation: fade-in 0.3s ease;">
                <div class="msg-bubble">${text}</div>
            </div>
        `;
        chatMessages.insertAdjacentHTML('beforeend', userHtml);
        chatMessages.scrollTop = chatMessages.scrollHeight;

        // Create Typing Indicator
        const typingId = 'typing-' + Date.now();
        const typingHtml = `
            <div id="${typingId}" class="message system-message" style="animation: fade-in 0.3s ease;">
                <div class="agent-label">
                    <span class="chip" style="background: #F0F6FF; color: var(--apple-blue); border-color: var(--apple-blue); padding: 2px 8px; font-size: 11px; box-shadow: none;"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px"><circle cx="12" cy="12" r="10"></circle></svg> MAESTER Agent</span>
                </div>
                <div class="msg-card">
                    <p style="font-style: italic; color: var(--apple-gray-2);">Agent is analyzing your request...</p>
                </div>
            </div>
        `;
        
        setTimeout(async () => {
            chatMessages.insertAdjacentHTML('beforeend', typingHtml);
            chatMessages.scrollTop = chatMessages.scrollHeight;
            
            // Call Real Backend API
            try {
                const res = await fetch('/api/v1/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: text })
                });
                const data = await res.json();
                
                const typingEl = document.getElementById(typingId);
                if (typingEl) typingEl.remove();
                
                let actionsHtml = '';
                if (data.actions && data.actions.length > 0) {
                    actionsHtml = '<div style="display: flex; gap: 8px; margin-top: 12px;">';
                    data.actions.forEach(action => {
                        actionsHtml += `<button class="btn btn-secondary" style="padding: 6px 14px; font-size: 13px;">${action.label}</button>`;
                    });
                    actionsHtml += '</div>';
                }
                
                const responseHtml = `
                    <div class="message system-message" style="animation: fade-in 0.3s ease;">
                        <div class="agent-label">
                            <span class="chip" style="background: #F0F6FF; color: var(--apple-blue); border-color: var(--apple-blue); padding: 2px 8px; font-size: 11px; box-shadow: none;"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px"><circle cx="12" cy="12" r="10"></circle></svg> MAESTER Agent</span>
                        </div>
                        <div class="msg-card">
                            <p>${data.response}</p>
                            ${actionsHtml}
                        </div>
                    </div>
                `;
                chatMessages.insertAdjacentHTML('beforeend', responseHtml);
                chatMessages.scrollTop = chatMessages.scrollHeight;
            } catch (err) {
                console.error("Backend Error:", err);
                const typingEl = document.getElementById(typingId);
                if (typingEl) typingEl.remove();
                chatMessages.insertAdjacentHTML('beforeend', `
                    <div class="message system-message">
                        <div class="msg-card" style="border-left: 3px solid var(--critical-red);">
                            <p>Error connecting to backend: ${err.message}</p>
                        </div>
                    </div>
                `);
            }
        }, 300);
    };

    sendBtn.addEventListener('click', sendMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            sendMessage();
        }
    });
    console.log('[MAESTER] Chat engine initialized successfully.');
}

/**
 * Handle VAPT Execution — connected to /api/v1/scan
 */
function initVAPTMock() {
    const launchBtn = document.querySelector('#vapt .btn-primary');
    const targetInput = document.querySelector('#vapt input[placeholder="Add IP or domain..."]');
    const tagContainer = document.querySelector('#vapt .tag-input-container');

    if (!launchBtn || !targetInput) return;

    // --- Make ALL chip X buttons removable (static + dynamic) ---
    function enableChipRemoval(container) {
        container.addEventListener('click', (e) => {
            const svg = e.target.closest('svg');
            if (svg && svg.closest('.chip')) {
                const chip = svg.closest('.chip');
                chip.style.transition = 'opacity 0.2s, transform 0.2s';
                chip.style.opacity = '0';
                chip.style.transform = 'scale(0.8)';
                setTimeout(() => chip.remove(), 200);
            }
        });
    }
    if (tagContainer) enableChipRemoval(tagContainer);

    // --- Add target on Enter key in target input ---
    targetInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const target = targetInput.value.trim();
            if (target) {
                const chipHtml = `<span class="chip" style="box-shadow: none; padding: 4px 8px; cursor: pointer; animation: fade-in 0.3s ease;"><span class="mono">${target}</span> <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="cursor:pointer"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></span>`;
                targetInput.insertAdjacentHTML('beforebegin', chipHtml);
                targetInput.value = '';
            }
        }
    });

    launchBtn.addEventListener('click', async () => {
        // Collect all targets from chips
        const chips = tagContainer ? tagContainer.querySelectorAll('.chip .mono') : [];
        const targets = Array.from(chips).map(c => c.textContent.trim());
        const inputTarget = targetInput.value.trim();
        if (inputTarget) {
            targets.push(inputTarget);
            // Add it as a chip too
            const chipHtml = `<span class="chip" style="box-shadow: none; padding: 4px 8px; animation: fade-in 0.3s ease;"><span class="mono">${inputTarget}</span> <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></span>`;
            targetInput.insertAdjacentHTML('beforebegin', chipHtml);
            targetInput.value = '';
        }

        const scanTarget = targets.join(', ') || 'demo.maester.io';

        // Animate Button
        launchBtn.innerHTML = '<svg class="spinner" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 8px;"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-linecap="round"></circle></svg> Initiating Scanner...';
        launchBtn.disabled = true;
        launchBtn.style.opacity = '0.7';

        // Find progress elements via more reliable selectors
        const progressScore = document.querySelector('#vapt .risk-score-value');
        const progressRings = document.querySelectorAll('#vapt svg circle');
        const progressRing = progressRings.length >= 2 ? progressRings[1] : null;
        // Find the phase text element by its current content
        const allOverlines = document.querySelectorAll('#vapt .overline');
        let phaseText = null;
        allOverlines.forEach(el => {
            if (el.textContent.includes('Phase:')) phaseText = el;
        });

        try {
            const res = await fetch('/api/v1/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: scanTarget, type: 'network' })
            });
            const data = await res.json();
            
            if (data.scan_id) {
                const interval = setInterval(async () => {
                    try {
                        const statusRes = await fetch(`/api/v1/scan/${data.scan_id}`);
                        const statusData = await statusRes.json();
                        
                        if (progressScore) progressScore.textContent = `${statusData.progress}%`;
                        if (progressRing) {
                            const circumference = 2 * Math.PI * 74; // r=74 from the SVG
                            const offset = circumference - (circumference * (statusData.progress / 100));
                            progressRing.style.strokeDashoffset = offset;
                        }
                        if (phaseText) phaseText.textContent = `Phase: ${statusData.phase}`;
                        
                        if (statusData.status === 'Completed') {
                            clearInterval(interval);
                            launchBtn.innerHTML = '✓ Scan Completed';
                            launchBtn.style.background = 'var(--low-green)';
                            launchBtn.style.color = 'white';
                            launchBtn.style.opacity = '1';
                            // Re-enable after 3s
                            setTimeout(() => {
                                launchBtn.disabled = false;
                                launchBtn.innerHTML = 'Launch Assessment';
                                launchBtn.style.background = '';
                                launchBtn.style.color = '';
                            }, 3000);
                        }
                    } catch (pollErr) {
                        console.error('Scan polling error:', pollErr);
                    }
                }, 1000);
            }
        } catch (err) {
            console.error(err);
            launchBtn.innerHTML = 'API Error — Retry';
            launchBtn.disabled = false;
            launchBtn.style.opacity = '1';
        }
    });
    console.log('[MAESTER] VAPT engine initialized successfully.');
}

/**
 * Handle Red Team Real-Time Execution Engine
 */
function initRedTeamEngine() {
    const taskInput = document.getElementById('red-team-task-input');
    const dispatchBtn = document.getElementById('dispatch-task-btn');
    const taskQueue = document.querySelector('.task-queue');
    const terminalOutput = document.querySelector('.terminal-output');
    
    if (!taskInput || !dispatchBtn || !taskQueue || !terminalOutput) return;

    let taskCounter = 3; // Starting after the 3 static ones

    dispatchBtn.addEventListener('click', async () => {
        const command = taskInput.value.trim();
        if (!command) return;

        taskCounter++;
        const displayId = taskCounter.toString().padStart(2, '0');

        // Append line
        const depLine = document.createElement('div');
        depLine.className = 'dependency-line';
        taskQueue.appendChild(depLine);

        // Append new task card to queue
        const taskCardHtml = `
            <div class="task-card card active-task" style="animation: fade-in 0.3s ease;">
                <div class="drag-handle"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="var(--apple-gray-2)" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line></svg></div>
                <div class="task-order mono" style="color: var(--apple-blue)">${displayId}</div>
                <div class="task-content">
                    <div class="task-label">Executing Target Command</div>
                    <div class="task-tool"><span class="chip" style="padding: 2px 8px; font-size: 11px;">Shell</span></div>
                </div>
                <div class="task-status">
                    <svg class="spinner" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="var(--apple-blue)" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-linecap="round"></circle></svg>
                </div>
            </div>
        `;
        taskQueue.insertAdjacentHTML('beforeend', taskCardHtml);
        const taskCardElement = taskQueue.lastElementChild;
        taskInput.value = '';

        try {
            // Dispatch to API
            const res = await fetch('/api/v1/task', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: command })
            });
            const data = await res.json();
            
            if (data.task_id) {
                let offset = 0;
                
                // Poll for logs
                const pollInterval = setInterval(async () => {
                    try {
                        const logRes = await fetch(`/api/v1/task/${data.task_id}/logs?offset=${offset}`);
                        const logData = await logRes.json();
                        
                        if (logData.logs && logData.logs.length > 0) {
                            logData.logs.forEach(log => {
                                const logType = log.toLowerCase().includes('error') ? 'critical' : 'info';
                                terminalOutput.insertAdjacentHTML('beforeend', `<div class="term-line ${logType}">${log}</div>`);
                            });
                            offset = logData.next_offset;
                            terminalOutput.scrollTop = terminalOutput.scrollHeight;
                        }
                        
                        if (logData.status === 'Completed' || logData.status === 'Failed') {
                            clearInterval(pollInterval);
                            const statusIcon = taskCardElement.querySelector('.task-status');
                            if (logData.status === 'Completed') {
                                statusIcon.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20" fill="var(--low-green)"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"></path></svg>';
                            } else {
                                statusIcon.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20" fill="var(--critical-red)"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
                            }
                            taskCardElement.classList.remove('active-task');
                        }
                    } catch (e) {
                        console.error('Polling error:', e);
                    }
                }, 500);
            }
        } catch (err) {
            console.error(err);
            terminalOutput.insertAdjacentHTML('beforeend', `<div class="term-line critical">[Error] Failed to dispatch task to backend.</div>`);
        }
    });
}
