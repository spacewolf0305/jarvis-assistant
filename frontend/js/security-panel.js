/* ═══════════════════════════════════════════════════════
   J.A.R.V.I.S — Security Panel
   Updates the security dashboard on the HUD
   ═══════════════════════════════════════════════════════ */

function updateSecurityPanel(data) {
    if (!data) return;

    // Update threat level
    const threatFill = document.getElementById('threat-fill');
    const threatLabel = document.getElementById('threat-label');

    if (threatFill && threatLabel) {
        const level = (data.threat_level || 'LOW').toUpperCase();
        threatFill.className = 'threat-fill ' + level.toLowerCase();
        threatLabel.className = 'threat-label ' + level.toLowerCase();
        threatLabel.textContent = 'THREAT: ' + level;
    }

    // Update connection counts
    updateStatValue('conn-count', data.established ?? '--');
    updateStatValue('suspicious-count', data.suspicious ?? '--',
        data.suspicious > 0 ? 'danger' : '');
    updateStatValue('listening-ports', data.listening ?? '--');

    // Update system stats
    if (data.cpu !== undefined) {
        updateStatValue('cpu-status', data.cpu + '%',
            data.cpu > 90 ? 'danger' : data.cpu > 70 ? 'warning' : '');
    }
    if (data.ram !== undefined) {
        updateStatValue('ram-status', data.ram + '%',
            data.ram > 90 ? 'danger' : data.ram > 80 ? 'warning' : '');
    }

    // Update security events log
    if (data.recent_events && data.recent_events.length > 0) {
        updateSecurityLog(data.recent_events);
    }
}

function updateStatValue(id, value, extraClass = '') {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = value;
        el.className = 'stat-value' + (extraClass ? ' ' + extraClass : '');
    }
}

function updateSecurityLog(events) {
    const logContainer = document.getElementById('security-log');
    if (!logContainer) return;

    logContainer.innerHTML = '';

    // Show last 10 events, newest first
    const recent = events.slice(-10).reverse();
    recent.forEach(event => {
        const entry = document.createElement('div');
        entry.className = 'log-entry';

        if (event.type === 'warning' || event.message?.includes('Warning')) {
            entry.classList.add('warning');
        }
        if (event.type === 'danger' || event.message?.includes('CRITICAL') || event.message?.includes('MALICIOUS')) {
            entry.classList.add('danger');
        }

        const time = new Date(event.timestamp);
        const timeStr = time.toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', hour12: false
        });

        entry.innerHTML = `
            <span class="log-time">${timeStr}</span>
            <span class="log-msg">${event.message || ''}</span>
        `;

        logContainer.appendChild(entry);
    });
}

function addSecurityEvent(type, message) {
    const logContainer = document.getElementById('security-log');
    if (!logContainer) return;

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    if (type === 'warning') entry.classList.add('warning');
    if (type === 'danger') entry.classList.add('danger');

    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', {
        hour: '2-digit', minute: '2-digit', hour12: false
    });

    entry.innerHTML = `
        <span class="log-time">${timeStr}</span>
        <span class="log-msg">${message}</span>
    `;

    // Insert at top
    logContainer.insertBefore(entry, logContainer.firstChild);

    // Limit entries
    while (logContainer.children.length > 15) {
        logContainer.removeChild(logContainer.lastChild);
    }
}

async function checkPasswordBreach() {
    const input = document.getElementById('password-check-input');
    if (!input || !input.value) return;

    const password = input.value;

    // SHA1 hash (using SubtleCrypto)
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    const prefix = hashHex.substring(0, 5);
    const suffix = hashHex.substring(5);

    try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const text = await response.text();

        let found = false;
        for (const line of text.split('\n')) {
            const [hashSuffix, count] = line.trim().split(':');
            if (hashSuffix === suffix) {
                alert(`⚠️ WARNING: This password has been found in ${parseInt(count).toLocaleString()} data breaches!\n\nChange it immediately and never reuse it.`);
                found = true;
                break;
            }
        }

        if (!found) {
            alert('✅ Good news! This password has NOT been found in any known data breaches.');
        }

        input.value = '';
    } catch (e) {
        alert('Error checking password: ' + e.message);
    }
}
