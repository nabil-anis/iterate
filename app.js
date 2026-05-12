/**
 * Stitch Cybersecurity Platform - UI Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initDrawer();
    initInteractiveElements();
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
