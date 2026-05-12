/**
 * MAESTER Cybersecurity Platform - UI Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initDrawer();
    initInteractiveElements();
    initChatMock();
    initVAPTMock();
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
 * Handle Mock Chat Interactions
 */
function initChatMock() {
    const chatInput = document.querySelector('.chat-input');
    const sendBtn = document.querySelector('.send-btn');
    const chatStream = document.querySelector('.chat-stream');

    if (!chatInput || !sendBtn || !chatStream) return;

    const sendMessage = () => {
        const text = chatInput.value.trim();
        if (!text) return;

        // Clear input
        chatInput.value = '';

        // Create User Message
        const userHtml = `
            <div class="chat-bubble user" style="animation: fade-in 0.3s ease;">
                <div class="body-m">${text}</div>
            </div>
        `;
        chatStream.insertAdjacentHTML('beforeend', userHtml);
        chatStream.scrollTop = chatStream.scrollHeight;

        // Create Typing Indicator
        const typingId = 'typing-' + Date.now();
        const typingHtml = `
            <div id="${typingId}" class="chat-card system" style="animation: fade-in 0.3s ease;">
                <div class="chat-card-header">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="var(--apple-blue)"><circle cx="12" cy="12" r="10"></circle></svg>
                    <span style="font-weight: 600;">MAESTER Agent</span>
                </div>
                <div class="chat-card-body body-m" style="color: var(--apple-gray-1);">
                    <span style="font-style: italic;">Agent is analyzing your request...</span>
                </div>
            </div>
        `;
        
        setTimeout(async () => {
            chatStream.insertAdjacentHTML('beforeend', typingHtml);
            chatStream.scrollTop = chatStream.scrollHeight;
            
            // Call Real Backend API
            try {
                const res = await fetch('http://localhost:8000/api/v1/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: text })
                });
                const data = await res.json();
                
                const typingEl = document.getElementById(typingId);
                if (typingEl) typingEl.remove();
                
                let actionsHtml = '';
                if (data.actions && data.actions.length > 0) {
                    actionsHtml = '<div class="chat-card-footer">';
                    data.actions.forEach(action => {
                        const style = action.label.startsWith('Yes') || action.label.startsWith('Generate') 
                            ? 'background: var(--surface-white); border: 1px solid var(--separator); padding: 4px 12px; font-size: 13px;'
                            : 'background: transparent; color: var(--apple-blue); padding: 4px 12px; font-size: 13px;';
                        actionsHtml += `<button class="btn" style="${style}">${action.label}</button>`;
                    });
                    actionsHtml += '</div>';
                }
                
                const responseHtml = `
                    <div class="chat-card system" style="animation: fade-in 0.3s ease;">
                        <div class="chat-card-header">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="var(--apple-blue)"><circle cx="12" cy="12" r="10"></circle></svg>
                            <span style="font-weight: 600;">MAESTER Agent</span>
                        </div>
                        <div class="chat-card-body body-m" style="color: var(--apple-gray-1);">
                            ${data.response}
                        </div>
                        ${actionsHtml}
                    </div>
                `;
                chatStream.insertAdjacentHTML('beforeend', responseHtml);
                chatStream.scrollTop = chatStream.scrollHeight;
            } catch (err) {
                console.error("Backend Error:", err);
                const typingEl = document.getElementById(typingId);
                if (typingEl) typingEl.remove();
                chatStream.insertAdjacentHTML('beforeend', `<div class="chat-card system"><div class="chat-card-body">Error connecting to backend: ${err.message}. Ensure the FastAPI server is running.</div></div>`);
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
}

/**
 * Handle Mock VAPT Execution
 */
function initVAPTMock() {
    const launchBtn = document.querySelector('#vapt .btn-primary');
    const targetInput = document.querySelector('#vapt input[placeholder="Add IP or domain..."]');
    const tagContainer = document.querySelector('#vapt .tag-input-container');
    const progressScore = document.querySelector('#vapt .risk-score-value');
    const progressRing = document.querySelector('#vapt circle:nth-child(2)');
    const phaseText = document.querySelector('#vapt .overline:nth-of-type(2)'); // Approx selector for "Phase: Exploitation"
    const exploitCard = document.querySelector('#vapt .card[style*="border-color: transparent"]'); // Try to find running status

    if (!launchBtn || !targetInput) return;

    launchBtn.addEventListener('click', async () => {
        // Add target if input has text
        const target = targetInput.value.trim();
        if (target) {
            const chipHtml = `<span class="chip" style="box-shadow: none; padding: 4px 8px; animation: fade-in 0.3s ease;"><span class="mono">${target}</span> <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></span>`;
            targetInput.insertAdjacentHTML('beforebegin', chipHtml);
            targetInput.value = '';
        }

        // Animate Button
        launchBtn.innerHTML = '<svg class="spinner" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 8px;"><circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-linecap="round"></circle></svg> Initiating Scanner...';
        launchBtn.disabled = true;
        launchBtn.style.opacity = '0.7';

        try {
            // Call Backend to start scan
            const res = await fetch('http://localhost:8000/api/v1/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target || 'demo.maester.io', type: 'network' })
            });
            const data = await res.json();
            
            if (data.scan_id) {
                // Start polling
                const interval = setInterval(async () => {
                    const statusRes = await fetch(`http://localhost:8000/api/v1/scan/${data.scan_id}`);
                    const statusData = await statusRes.json();
                    
                    if (progressScore) progressScore.textContent = `${statusData.progress}%`;
                    if (progressRing) {
                        const offset = 465 - (465 * (statusData.progress / 100));
                        progressRing.style.strokeDashoffset = offset;
                    }
                    if (phaseText) phaseText.textContent = `Phase: ${statusData.phase}`;
                    
                    if (statusData.status === 'Completed') {
                        clearInterval(interval);
                        launchBtn.innerHTML = 'Scan Completed';
                        launchBtn.style.background = 'var(--low-green)';
                        launchBtn.style.color = 'white';
                    }
                }, 1000);
            }
        } catch (err) {
            console.error(err);
            launchBtn.innerHTML = 'API Error';
        }
    });
}
