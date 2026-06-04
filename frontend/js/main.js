/* ═══════════════════════════════════════════════════════
   J.A.R.V.I.S — Main Application
   WebSocket, command handling, UI state management
   ═══════════════════════════════════════════════════════ */

let ws = null;
let currentState = 'idle';
let commandHistory = [];

// ─── Initialize ─────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    runBootSequence();

    // Wait for boot sequence to finish before initializing
    setTimeout(() => {
        connectWebSocket();
        initVisualizer();
        setupEventListeners();
        updateNetStatus();
    }, 3500);
});

// ─── WebSocket Connection ───────────────────────────────
function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${location.host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        updateStatus('ONLINE', 'active');
        updateStatValue('net-status', 'CONNECTED');
        updateStatValue('ai-status', 'READY');
        updateStatValue('mic-status', 'ACTIVE');
        addSecurityEvent('info', 'WebSocket connected. JARVIS online.');
    };

    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        handleServerMessage(message);
    };

    ws.onclose = () => {
        updateStatus('OFFLINE', '');
        updateStatValue('net-status', 'DISCONNECTED', 'offline');
        // Auto-reconnect after 3 seconds
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = () => {
        updateStatus('ERROR', 'error');
    };
}

// ─── Handle Server Messages ─────────────────────────────
function handleServerMessage(message) {
    switch (message.type) {
        case 'state':
            setState(message.data);
            break;

        case 'transcript':
            showTranscript(message.data);
            break;

        case 'response':
            showResponse(message.data);
            break;

        case 'command':
            addToHistory('USER', message.data?.target || message.data);
            break;

        case 'security_status':
            updateSecurityPanel(message.data);
            break;

        case 'error':
            showError(message.data);
            break;
    }
}

// ─── State Management ───────────────────────────────────
function setState(state) {
    currentState = state;
    const orb = document.getElementById('jarvis-orb');

    // Remove all state classes
    orb.className = 'orb';

    switch (state) {
        case 'listening':
            orb.classList.add('listening');
            updateStatus('LISTENING', 'listening');
            setVisualizerState('listening');
            break;
        case 'processing':
            orb.classList.add('processing');
            updateStatus('PROCESSING', 'processing');
            setVisualizerState('processing');
            break;
        case 'speaking':
            orb.classList.add('speaking');
            updateStatus('RESPONDING', 'speaking');
            setVisualizerState('speaking');
            break;
        case 'error':
            orb.classList.add('error');
            updateStatus('ERROR', 'error');
            setVisualizerState('idle');
            break;
        default:
            updateStatus('ONLINE', 'active');
            setVisualizerState('idle');
    }
}

function updateStatus(text, dotClass) {
    const statusText = document.getElementById('status-text');
    const statusDot = document.querySelector('.status-dot');
    if (statusText) statusText.textContent = text;
    if (statusDot) statusDot.className = 'status-dot ' + (dotClass || '');
}

function updateNetStatus() {
    const online = navigator.onLine;
    updateStatValue('net-status', online ? 'CONNECTED' : 'OFFLINE',
        online ? '' : 'offline');
}

// ─── Transcript & Response ──────────────────────────────
function showTranscript(text) {
    const el = document.getElementById('transcript-text');
    if (el) {
        el.textContent = text;
        el.style.color = 'var(--text)';
    }
}

function showResponse(text) {
    const el = document.getElementById('response-text');
    if (el) {
        typeText(el, text, 15);
    }
    addToHistory('JARVIS', text);

    // Log security-related responses
    const lower = text.toLowerCase();
    if (lower.includes('warning') || lower.includes('suspicious') || lower.includes('breach')) {
        addSecurityEvent('warning', text.substring(0, 100) + '...');
    } else if (lower.includes('malicious') || lower.includes('danger') || lower.includes('critical')) {
        addSecurityEvent('danger', text.substring(0, 100) + '...');
    } else if (lower.includes('scan') || lower.includes('security') || lower.includes('network')) {
        addSecurityEvent('info', text.substring(0, 100) + (text.length > 100 ? '...' : ''));
    }
}

function showError(text) {
    const el = document.getElementById('response-text');
    if (el) {
        el.textContent = text;
        el.style.color = 'var(--danger)';
    }
    setState('error');
    setTimeout(() => setState('idle'), 3000);
}

// ─── Command History ────────────────────────────────────
function addToHistory(sender, text) {
    if (!text) return;

    commandHistory.push({ sender, text, time: new Date() });

    const container = document.getElementById('history-container');
    if (!container) return;

    // Remove empty state
    const empty = container.querySelector('.history-empty');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = `history-item ${sender.toLowerCase()}`;

    item.innerHTML = `
        <div class="history-sender">${sender}</div>
        <div class="history-text">${text}</div>
    `;

    container.insertBefore(item, container.firstChild);

    // Limit history items in DOM
    while (container.children.length > 50) {
        container.removeChild(container.lastChild);
    }
}

// ─── Send Commands ──────────────────────────────────────
function sendCommand(command) {
    if (!command) return;

    // Show in transcript
    showTranscript(command);
    addToHistory('YOU', command);

    // Send to server
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'command',
            data: command
        }));
        setState('processing');
    } else {
        showError('Not connected to JARVIS server.');
    }
}

function sendInputCommand() {
    const input = document.getElementById('command-input');
    if (!input || !input.value.trim()) return;

    sendCommand(input.value.trim());
    input.value = '';
}

// ─── Settings ───────────────────────────────────────────
function saveSettings() {
    const geminiKey = document.getElementById('gemini-key-input')?.value || '';
    const vtKey = document.getElementById('vt-key-input')?.value || '';
    const abuseKey = document.getElementById('abuse-key-input')?.value || '';

    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'settings_update',
            data: {
                gemini_api_key: geminiKey,
                virustotal_api_key: vtKey,
                abuseipdb_api_key: abuseKey,
            }
        }));
    }

    // Save to localStorage for persistence
    if (geminiKey) localStorage.setItem('jarvis_gemini_key', geminiKey);
    if (vtKey) localStorage.setItem('jarvis_vt_key', vtKey);
    if (abuseKey) localStorage.setItem('jarvis_abuse_key', abuseKey);

    // Close modal
    document.getElementById('settings-modal')?.classList.add('hidden');
    showResponse('Settings saved, sir. API keys updated.');
}

function loadSettings() {
    const geminiKey = localStorage.getItem('jarvis_gemini_key') || '';
    const vtKey = localStorage.getItem('jarvis_vt_key') || '';
    const abuseKey = localStorage.getItem('jarvis_abuse_key') || '';

    const geminiInput = document.getElementById('gemini-key-input');
    const vtInput = document.getElementById('vt-key-input');
    const abuseInput = document.getElementById('abuse-key-input');

    if (geminiInput && geminiKey) geminiInput.value = geminiKey;
    if (vtInput && vtKey) vtInput.value = vtKey;
    if (abuseInput && abuseKey) abuseInput.value = abuseKey;

    // Send to server on connect
    if (geminiKey || vtKey || abuseKey) {
        setTimeout(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'settings_update',
                    data: {
                        gemini_api_key: geminiKey,
                        virustotal_api_key: vtKey,
                        abuseipdb_api_key: abuseKey,
                    }
                }));
            }
        }, 4000);
    }
}

// ─── Event Listeners ────────────────────────────────────
function setupEventListeners() {
    // Enter key to send command
    const commandInput = document.getElementById('command-input');
    if (commandInput) {
        commandInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                sendInputCommand();
            }
        });
    }

    // Settings modal
    const settingsBtn = document.getElementById('settings-btn');
    const settingsModal = document.getElementById('settings-modal');
    const settingsClose = document.getElementById('settings-close');

    if (settingsBtn && settingsModal) {
        settingsBtn.addEventListener('click', () => {
            settingsModal.classList.toggle('hidden');
            loadSettings();
        });
    }
    if (settingsClose && settingsModal) {
        settingsClose.addEventListener('click', () => {
            settingsModal.classList.add('hidden');
        });
    }

    // Click outside modal to close
    if (settingsModal) {
        settingsModal.addEventListener('click', (e) => {
            if (e.target === settingsModal) {
                settingsModal.classList.add('hidden');
            }
        });
    }

    // Push-to-talk button with native Web Speech API
    const pttBtn = document.getElementById('ptt-btn');
    if (pttBtn) {
        let recognition = null;
        if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
            const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
            recognition = new SpeechRec();
            recognition.continuous = false;
            recognition.interimResults = true;
            
            recognition.onstart = function() {
                setState('listening');
                pttBtn.classList.add('active');
            };
            
            recognition.onresult = function(event) {
                let interimTranscript = '';
                let finalTranscript = '';
                for (let i = event.resultIndex; i < event.results.length; ++i) {
                    if (event.results[i].isFinal) {
                        finalTranscript += event.results[i][0].transcript;
                    } else {
                        interimTranscript += event.results[i][0].transcript;
                    }
                }
                showTranscript(finalTranscript || interimTranscript);
                if (finalTranscript) {
                    let cmd = finalTranscript.trim().toLowerCase();
                    // Strip 'jarvis' if they said it
                    if (cmd.startsWith("jarvis")) {
                        cmd = cmd.substring(6).trim();
                    }
                    // Strip leading punctuation
                    cmd = cmd.replace(/^[,. ]+/, "");
                    
                    if (cmd) {
                        sendCommand(cmd);
                    }
                }
            };
            
            recognition.onerror = function(event) {
                showError('Mic error: ' + event.error);
                setState('idle');
                pttBtn.classList.remove('active');
            };
            
            recognition.onend = function() {
                if (currentState === 'listening') {
                    setState('idle');
                }
                pttBtn.classList.remove('active');
            };
        }

        pttBtn.addEventListener('click', () => {
            if (recognition) {
                try {
                    recognition.start();
                } catch(e) {
                    recognition.stop();
                }
            } else {
                showError('Browser does not support Web Speech API.');
            }
        });
    }

    // Spacebar for push-to-talk (when not focused on input)
    document.addEventListener('keydown', (e) => {
        if (e.code === 'Space' && document.activeElement.tagName !== 'INPUT') {
            e.preventDefault();
            pttBtn?.click();
        }
    });

    // Load saved settings
    loadSettings();

    // Network status listener
    window.addEventListener('online', updateNetStatus);
    window.addEventListener('offline', updateNetStatus);

    // Request security status refresh every 30 seconds
    setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'get_security_status' }));
        }
    }, 30000);
}
