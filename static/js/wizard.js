// Device onboarding wizard (extracted from templates/wizard.html).
// Classic script: the markup uses inline onclick handlers, so the functions
// stay on window.

const esc = (value) => String(value == null ? '' : value).replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
);
// New Wizard Implementation
let wizardCurrentStep = 1;
let wizardState = {
    selectedKeyId: null,
    selectedKeyName: null,
    keyContent: null,
    ips: [],
    usernames: [],
    validatedHosts: [],
    collectedInfo: [],
    addedDevices: [],
    sessionId: null
};
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function openWizard() {
    // Shared dialog chrome (static/js/modals.js) when available.
    if (typeof window.openAppModal === 'function') window.openAppModal('wizardModal');
    else document.getElementById('wizardModal').classList.remove('hidden');
    wizardCurrentStep = 1;
    wizardState = {
        selectedKeyId: null,
        selectedKeyName: null,
        keyContent: null,
        ips: [],
        usernames: [],
        validatedHosts: [],
        collectedInfo: [],
        addedDevices: [],
        sessionId: null,
        verificationStarted: false,
        collectionStarted: false,
        verificationComplete: false,
        collectionComplete: false,
        completionStarted: false,
        completionComplete: false
    };
    wizardLoadKeys();
    wizardLoadGroups();
    wizardLoadTags();
    wizardShowStep(1);
}

function closeWizard() {
    if (typeof window.closeAppModal === 'function') window.closeAppModal('wizardModal');
    else document.getElementById('wizardModal').classList.add('hidden');
}

function wizardShowStep(step) {
    // Hide all steps
    for (let i = 1; i <= 5; i++) {
        document.getElementById(`wizardStep${i}`).classList.add('hidden');
        document.getElementById(`progress${i}`).classList.remove('bg-purple-700');
        document.getElementById(`progress${i}`).classList.add('bg-white/10');
    }
    
    // Show current step
    document.getElementById(`wizardStep${step}`).classList.remove('hidden');
    document.getElementById(`progress${step}`).classList.remove('bg-white/10');
    document.getElementById(`progress${step}`).classList.add('bg-purple-700');
    
    // Update title
    const titles = [
        'Step 1 of 5: Select SSH Key',
        'Step 2 of 5: Enter Device Details',
        'Step 3 of 5: Verify Connectivity',
        'Step 4 of 5: Collect System Info',
        'Step 5 of 5: Complete'
    ];
    document.getElementById('stepTitle').textContent = titles[step - 1];
    
    // Update buttons
    const backBtn = document.getElementById('wizardBackBtn');
    const nextBtn = document.getElementById('wizardNextBtn');
    
    if (step === 1) {
        backBtn.classList.add('hidden');
        nextBtn.textContent = 'Next →';
        nextBtn.disabled = !wizardState.selectedKeyId;
    } else if (step === 5) {
        backBtn.classList.remove('hidden');
        nextBtn.textContent = wizardState.completionComplete ? 'Close' : 'Finish';
        nextBtn.disabled = false;
    } else {
        backBtn.classList.remove('hidden');
        nextBtn.textContent = 'Next →';
    }
    
    // Update step 2/3 key display
    if (step === 2 || step === 3) {
        document.getElementById(`wizardStep${step}KeyName`).textContent = wizardState.selectedKeyName || 'Unknown';
    }
    // Auto-run verification/collection when entering their steps
    if (step === 3 && !wizardState.verificationStarted) {
        wizardState.verificationStarted = true;
        wizardState.verificationComplete = false;
        const resultsDiv = document.getElementById('wizardVerificationResults');
        if (resultsDiv) { resultsDiv.innerHTML = '<p class="text-sm termix-muted text-center py-8">Starting...</p>'; }
        nextBtn.disabled = true;
        nextBtn.textContent = 'Running...';
        // Start async without blocking UI render
        setTimeout(() => wizardRunVerification(), 0);
    }
    if (step === 4 && !wizardState.collectionStarted) {
        wizardState.collectionStarted = true;
        wizardState.collectionComplete = false;
        const log = document.getElementById('wizardCollectionLog');
        if (log) { log.innerHTML = '<p class=\"termix-muted\">Starting collection...</p>'; }
        nextBtn.disabled = true;
        nextBtn.textContent = 'Running...';
        setTimeout(() => wizardRunCollection(), 0);
    }
}

async function wizardNext() {
    console.log('wizardNext click', { step: wizardCurrentStep, state: wizardState });

    if (wizardCurrentStep === 1) {
        if (!await wizardValidateStep1()) return;
    } else if (wizardCurrentStep === 2) {
        if (!await wizardValidateStep2()) return;
    } else if (wizardCurrentStep === 3) {
        if (!wizardState.verificationComplete) {
            const resultsDiv = document.getElementById('wizardVerificationResults');
            if (resultsDiv) {
                resultsDiv.innerHTML += '<p class="text-xs text-amber-300 mt-2">Not ready yet: verificationComplete=false (verification still running or never marked complete).</p>';
            }
            return;
        }
    } else if (wizardCurrentStep === 4) {
        if (!wizardState.collectionComplete) {
            const log = document.getElementById('wizardCollectionLog');
            if (log) {
                log.innerHTML += '<p class="text-xs text-amber-300 mt-2">Not ready yet: collectionComplete=false (collection still running or never marked complete).</p>';
            }
            return;
        }

        // Auto-run completion when moving from Step 4 -> Step 5
        wizardCurrentStep = 5;
        wizardShowStep(wizardCurrentStep);
        const msg = document.getElementById('wizardCompletionMessage');
        if (msg) msg.textContent = 'Adding devices...';
        const nextBtn = document.getElementById('wizardNextBtn');
        if (nextBtn) { nextBtn.disabled = true; nextBtn.textContent = 'Working...'; }
        await wizardComplete();
        return;
    } else if (wizardCurrentStep === 5) {
        if (wizardState.completionComplete) {
            closeWizard();
            return;
        }
        const nextBtn = document.getElementById('wizardNextBtn');
        if (nextBtn) { nextBtn.disabled = true; nextBtn.textContent = 'Working...'; }
        await wizardComplete();
        return;
    }
    
    wizardCurrentStep++;
    wizardShowStep(wizardCurrentStep);
}

function wizardGoBack() {
    if (wizardCurrentStep > 1) {
        wizardCurrentStep--;
        wizardShowStep(wizardCurrentStep);
    }
}

function wizardLoadKeys() {
    const status = document.getElementById('wizardKeyLoadStatus');
    if (status) status.textContent = 'Loading keys...';

    fetch('/ssh-keys')
        .then(r => {
            if (!r.ok) throw new Error('Failed to load keys (HTTP ' + r.status + ')');
            return r.json();
        })
        .then(keys => {
            console.log('[wizard] loaded keys', keys);
            const select = document.getElementById('wizardExistingKeySelect');
            if (!select) throw new Error('wizardExistingKeySelect not found in DOM');

            select.innerHTML = '<option value="">-- Select a key or upload new --</option>';

            // Store keys with their metadata for later reference
            wizardState.availableKeys = {};

            if (!Array.isArray(keys)) {
                throw new Error('Expected /ssh-keys to return an array');
            }

            keys.forEach(key => {
                const opt = document.createElement('option');
                opt.value = key.id;
                opt.textContent = key.key_name;
                select.appendChild(opt);
                wizardState.availableKeys[key.id] = key;
            });

            if (status) {
                status.textContent = keys.length ? (keys.length + ' key(s) loaded') : 'No keys saved yet.';
            }

            // Avoid stacking multiple listeners if wizardLoadKeys is called repeatedly
            select.onchange = () => {
                const keyId = select.value;
                if (keyId) {
                    const keyName = select.options[select.selectedIndex].text;
                    const keyData = wizardState.availableKeys[keyId];
                    wizardState.selectedKeyId = parseInt(keyId);
                    wizardState.selectedKeyName = keyName;
                    wizardState.selectedKeyIntegrity = (keyData && keyData.integrity_status) ? keyData.integrity_status : 'unknown';
                    wizardState.keyContent = null;
                    wizardShowSelectedKey();
                    document.getElementById('wizardKeyFile').value = '';
                    document.getElementById('wizardSaveKeyDiv').classList.add('hidden');
                    document.getElementById('wizardNextBtn').disabled = false;
                }
            };
        })
        .catch(err => {
            console.error('[wizard] failed to load keys', err);
            const select = document.getElementById('wizardExistingKeySelect');
            if (select) {
                select.innerHTML = '<option value="">-- Error loading keys --</option>';
            }
            if (status) {
                status.textContent = 'Error loading keys: ' + (err.message || err);
                status.className = 'text-xs text-red-300 mt-2';
            }
        });
}

document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('wizardKeyFile');
    if (fileInput) {
        fileInput.addEventListener('change', async (e) => {
            if (e.target.files.length) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    wizardState.keyContent = event.target.result;
                    wizardState.selectedKeyId = null;
                    document.getElementById('wizardExistingKeySelect').value = '';
                    document.getElementById('wizardSaveKeyDiv').classList.remove('hidden');
                    document.getElementById('wizardNewKeyName').style.display = 'block';
                    document.getElementById('wizardSelectedKeyDisplay').classList.add('hidden');
                    document.getElementById('wizardNextBtn').disabled = false;
                };
                reader.readAsText(e.target.files[0]);
            }
        });
    }
});

function wizardShowSelectedKey() {
    const display = document.getElementById('wizardSelectedKeyDisplay');
    const nameEl = document.getElementById('wizardSelectedKeyName');
    
    let statusText = '';
    const integrity = wizardState.selectedKeyIntegrity || 'unknown';
    
    if (integrity === 'verified') {
        statusText = ' ✓ (verified)';
        nameEl.className = 'text-sm text-green-200 mt-1';
    } else if (integrity === 'corrupted') {
        statusText = ' ⚠ (corrupted - do not use)';
        nameEl.className = 'text-sm text-red-200 mt-1';
    } else {
        statusText = '';
        nameEl.className = 'text-sm text-yellow-200 mt-1';
    }
    
    nameEl.textContent = wizardState.selectedKeyName + statusText;
    
    // Update the integrity status badge
    const statusBadge = document.getElementById('wizardIntegrityBadge');
    if (statusBadge) {
        if (integrity === 'verified') {
            statusBadge.className = 'inline-block px-2 py-1 rounded text-xs font-semibold bg-green-500/20 text-green-300';
            statusBadge.textContent = '✓ Verified';
        } else if (integrity === 'corrupted') {
            statusBadge.className = 'inline-block px-2 py-1 rounded text-xs font-semibold bg-red-500/20 text-red-300';
            statusBadge.textContent = '⚠ Corrupted';
        } else {
            statusBadge.className = 'inline-block px-2 py-1 rounded text-xs font-semibold bg-yellow-500/20 text-yellow-300';
            statusBadge.textContent = '? Unknown';
        }
    }
    
    display.classList.remove('hidden');
}

async function wizardSaveNewKey() {
    const keyName = document.getElementById('wizardNewKeyName').value.trim();
    const statusDiv = document.getElementById('wizardSaveKeyStatus');
    
    if (!keyName) {
        statusDiv.innerHTML = '<p class="text-red-300">Please enter a key name</p>';
        return;
    }
    
    if (!wizardState.keyContent) {
        statusDiv.innerHTML = '<p class="text-red-300">No key content loaded</p>';
        return;
    }
    
    const btn = document.getElementById('wizardSaveKeyBtn');
    btn.disabled = true;
    btn.textContent = 'Saving...';
    statusDiv.innerHTML = '<p class="text-yellow-300">Uploading key...</p>';
    
    try {
        const resp = await fetch('/ssh-keys/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                key_name: keyName, 
                key_content: wizardState.keyContent 
            })
        });
        
        const data = await resp.json();
        if (!resp.ok) {
            statusDiv.innerHTML = `<p class="text-red-300">Error: ${esc(data.error)}</p>`;
            btn.disabled = false;
            btn.textContent = 'Save SSH Key';
            return;
        }
        
        // Key saved! Now check its integrity
        statusDiv.innerHTML = '<p class="text-yellow-300">Verifying key integrity...</p>';
        
        // Refresh keys and show the saved key
        const keysResp = await fetch('/ssh-keys');
        const keys = await keysResp.json();
        
        // Find the key we just saved
        const savedKey = keys.find(k => k.key_name === keyName);
        if (savedKey) {
            wizardState.selectedKeyId = savedKey.id;
            wizardState.selectedKeyName = savedKey.key_name;
            wizardState.selectedKeyIntegrity = savedKey.integrity_status || 'unknown';
            wizardState.keyContent = null;
            
            // Show the selected key with its integrity status
            wizardShowSelectedKey();
            
            // Hide the save form
            document.getElementById('wizardSaveKeyDiv').classList.add('hidden');
            document.getElementById('wizardNewKeyName').value = '';
            
            // Enable next button
            document.getElementById('wizardNextBtn').disabled = false;
            
            // Show integrity status
            if (wizardState.selectedKeyIntegrity === 'verified') {
                statusDiv.innerHTML = '<p class="text-green-300">✓ Key saved and verified!</p>';
            } else if (wizardState.selectedKeyIntegrity === 'corrupted') {
                statusDiv.innerHTML = '<p class="text-red-300">⚠ Key integrity check failed - do not use</p>';
            } else {
                statusDiv.innerHTML = '<p class="text-yellow-300">? Key saved (integrity unknown)</p>';
            }
        }
    } catch (error) {
        statusDiv.innerHTML = `<p class="text-red-300">Error: ${esc(error.message)}</p>`;
        btn.disabled = false;
        btn.textContent = 'Save SSH Key';
    }
}

async function wizardValidateStep1() {
    // Just check if a key is selected
    if (!wizardState.selectedKeyId) {
        alert('Please select or save an SSH key');
        return false;
    }
    
    // Check integrity
    if (wizardState.selectedKeyIntegrity === 'corrupted') {
        alert('This SSH key is corrupted and cannot be used. Please upload a different key.');
        return false;
    }
    
    return true;
}

async function wizardValidateStep2() {
    const ips = document.getElementById('wizardStep2IPs').value.trim().split('\n').map(ip => ip.trim()).filter(ip => ip);
    const users = document.getElementById('wizardStep2Users').value.trim();
    
    if (!ips.length) {
        alert('Please enter at least one IP address');
        return false;
    }
    
    if (!users) {
        alert('Please enter SSH username(s)');
        return false;
    }
    
    wizardState.ips = ips;
    wizardState.usernames = users.includes(',') ? users.split(',').map(u => u.trim()) : [users];
    
    return true;
}


function wizardAbortVerification() {
    try {
        if (wizardState.verificationAbortController) {
            wizardState.verificationAbortController.abort();
        }
    } catch (e) {}
    try {
        if (wizardState.verificationTimeoutId) {
            clearTimeout(wizardState.verificationTimeoutId);
        }
    } catch (e) {}
    wizardState.verificationAbortController = null;
    wizardState.verificationTimeoutId = null;
}

function wizardRetryVerification() {
    // Allow retry after user fixes SSH issues outside the app
    wizardAbortVerification();

    wizardState.verificationComplete = false;
    wizardState.verificationStarted = true; // we are in step 3 already
    wizardState.validatedHosts = [];

    const nextBtn = document.getElementById('wizardNextBtn');
    if (nextBtn) {
        nextBtn.disabled = true;
        nextBtn.textContent = 'Running...';
    }

    const resultsDiv = document.getElementById('wizardVerificationResults');
    if (resultsDiv) {
        resultsDiv.innerHTML = '<p class="text-sm termix-muted text-center py-8">Retrying verification...</p>';
    }

    setTimeout(() => wizardRunVerification(), 0);
}

async function wizardRunVerification() {
    const resultsDiv = document.getElementById('wizardVerificationResults');
    console.log('Starting verification, resultsDiv:', resultsDiv);
    wizardAbortVerification();
    wizardState.validatedHosts = [];
    wizardState.sessionId = null;

    resultsDiv.innerHTML = '';
    resultsDiv.innerHTML = '<div class="space-y-2"><p class="text-yellow-300 font-semibold">🔍 Starting SSH verification...</p><p class="text-sm termix-muted">Step 1: Creating session...</p></div>';
    console.log('Verification UI updated');
    
    try {
        // Create session
        const sessionResp = await fetch('/wizard/session/create', { method: 'POST' });
        const sessionData = await sessionResp.json();
        wizardState.sessionId = sessionData.session_id;
        resultsDiv.innerHTML += '<p class="text-sm text-green-300">✓ Session created</p>';
        
        // Add timeout for verification
        
        // Build payload
        resultsDiv.innerHTML += '<p class="text-sm termix-muted">Step 2: Preparing to test ' + wizardState.ips.length + ' IP(s)...</p>';
        resultsDiv.innerHTML += '<div class="mt-2 ml-4 space-y-1">';
        wizardState.ips.forEach(ip => { resultsDiv.innerHTML += '<p class="text-xs text-gray-300">→ ' + ip + '</p>'; });
        const payload = {
            ips: wizardState.ips,
            usernames: wizardState.usernames
        };
        if (wizardState.selectedKeyId) {
            payload.ssh_key_id = wizardState.selectedKeyId;
        } else if (wizardState.keyContent) {
            payload.key_content = wizardState.keyContent;
        }
        
        // Stream validation
        const controller = new AbortController();
        wizardState.verificationAbortController = controller;
        wizardState.verificationTimeoutId = setTimeout(() => controller.abort(), 30000);
        const response = await fetch(`/wizard/session/${wizardState.sessionId}/validate-hosts-stream`, {
            signal: controller.signal,
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            const error = await response.json();
            resultsDiv.innerHTML += `<div class="p-3 mt-2 rounded bg-red-500/10 border border-red-500/30"><p class="text-red-300"><strong>Error:</strong> ${esc(error.error || 'Unknown error')}</p><p class="text-xs termix-muted mt-1">Server status: ${response.status}</p></div>`;
            return;
        }
        
        resultsDiv.innerHTML += '<p class="text-sm termix-muted">Step 4: Receiving SSH test results...</p>';
        resultsDiv.innerHTML += '<div class="mt-2 space-y-2">';
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        
        let buffer = '';
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            buffer += decoder.decode(value, { stream: true });
            const parts = buffer.split('\n\n');
            buffer = parts.pop() || ''; // keep incomplete event
            
            for (const line of parts) {
                if (!line.trim() || !line.startsWith('data: ')) continue;
                
                const jsonStr = line.substring(6);
                let data;
                try {
                    data = JSON.parse(jsonStr);
                } catch (e) {
                    continue;
                }
                
                if (data.type === 'result') {
                    const statusIcon = data.status === 'success' ? '✓' : data.status === 'auth_error' ? '⚠' : '✗';
                    const statusColor = data.status === 'success' ? 'text-green-300' : data.status === 'auth_error' ? 'text-amber-300' : 'text-red-300';
                    const bgColor = statusColor === 'text-green-300' ? 'border-green-500/30 bg-green-500/10' : statusColor === 'text-amber-300' ? 'border-amber-500/30 bg-amber-500/10' : 'border-red-500/30 bg-red-500/10';
                    
                    const userLabel = data.user || '(unknown user)';
                    const cmd = data.command ? escapeHtml(data.command) : '';
                    const cmdLine = cmd ? `<p class=\"text-xs termix-muted mt-1\"><span class=\"font-mono break-all\">${cmd}</span></p>` : '';
                    const det = data.details ? escapeHtml(data.details) : '';
                    const detLine = det ? `<p class=\"text-xs termix-muted mt-1\">${det}</p>` : '';
                    resultsDiv.innerHTML += `<div class=\"flex items-start justify-between gap-4 p-3 rounded border ${bgColor}\"><div class=\"min-w-0\"><p class=\"font-medium ${statusColor}\">${statusIcon} ${data.ip}</p><p class=\"text-sm termix-muted\">${userLabel}</p>${cmdLine}${detLine}</div><div class=\"text-right text-sm ${statusColor}\">${escapeHtml(data.message)}</div></div>`;
                    
                    if (data.status === 'success') {
                        wizardState.validatedHosts.push({ ip: data.ip, user: data.user });
                    }
                }
            }
        }

        wizardAbortVerification();
        // Flush any remaining buffered SSE event
        const tail = buffer.trim();
        if (tail.startsWith('data: ')) {
            try {
                const data = JSON.parse(tail.substring(6));
                if (data && data.type === 'complete') {
                    wizardState.verificationComplete = true;
                }
            } catch (e) {}
        }
        // Fallback: if stream ended but we never saw complete, allow user to proceed
        if (!wizardState.verificationComplete) {
            wizardState.verificationComplete = true;
            resultsDiv.innerHTML += '<p class="text-xs text-amber-300 mt-2">Stream ended without complete event; allowing Next.</p>';
        }

        // Verification finished: enable Next to proceed manually
        const nextBtn = document.getElementById('wizardNextBtn');
        if (nextBtn) {
            nextBtn.disabled = false;
            nextBtn.textContent = 'Next →';
        }
        wizardState.verificationComplete = true;
        // Stay on Step 3 until user clicks Next

    } catch (err) {
        wizardAbortVerification();
        wizardState.verificationStarted = false;
        wizardState.verificationComplete = false;
        console.error('Verification error:', err);
        resultsDiv.innerHTML = `<div class="p-4 rounded bg-red-500/10 border border-red-500/30"><p class="text-red-300"><strong>Error:</strong> ${esc((err.name === 'AbortError') ? 'Verification timed out after 30s' : (err.message || 'Verification failed'))}</p><p class="text-xs termix-muted mt-2">Check browser console for details</p></div>`;
    }
}

async function wizardRunCollection() {
    document.getElementById('wizardCollectionLog').innerHTML = '';
    
    try {
        const payload = {
            ips: wizardState.ips,
            usernames: wizardState.usernames
        };
        if (wizardState.selectedKeyId) {
            payload.ssh_key_id = wizardState.selectedKeyId;
        } else if (wizardState.keyContent) {
            payload.key_content = wizardState.keyContent;
        }
        
        const response = await fetch(`/wizard/session/${wizardState.sessionId}/collect-info-stream`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let totalDevices = 0;
        let currentDevice = 0;
        let buffer = '';
        const logDiv = document.getElementById('wizardCollectionLog');
        if (logDiv) {
            logDiv.innerHTML = '<p class="termix-muted">Starting collection...</p>';
        }
        
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            buffer += decoder.decode(value, { stream: true });
            const parts = buffer.split('\n\n');
            buffer = parts.pop() || '';
            
            for (const line of parts) {
                if (!line.trim() || !line.startsWith('data: ')) continue;
                
                const jsonStr = line.substring(6);
                let data;
                try {
                    data = JSON.parse(jsonStr);
                } catch (e) {
                    continue;
                }
                
                if (data.type === 'start') {
                    totalDevices = data.total;
                    if (logDiv) logDiv.innerHTML = `<p class="termix-muted">Collecting from ${totalDevices} device(s)...</p>`;
                } else if (data.type === 'progress') {
                    currentDevice = data.current;
                    const pct = totalDevices ? Math.round(((currentDevice) / totalDevices) * 100) : 0;
                    document.getElementById('wizardCollectionBar').style.width = `${pct}%`;
                    document.getElementById('wizardCollectionText').textContent = `${currentDevice}/${totalDevices}`;
                    if (logDiv) logDiv.innerHTML += `<p class="text-xs termix-muted">→ ${escapeHtml(data.message || '')}</p>`;
                } else if (data.type === 'log') {
                    if (logDiv) logDiv.innerHTML += `<p class="text-xs"><span class="text-purple-300">${escapeHtml(data.ip || '')}</span> <span class="termix-muted">${escapeHtml(data.message || '')}</span></p>`;
                } else if (data.type === 'host_complete') {
                    const pct = totalDevices ? Math.round((data.current / totalDevices) * 100) : 0;
                    document.getElementById('wizardCollectionBar').style.width = `${pct}%`;
                    document.getElementById('wizardCollectionText').textContent = `${data.current}/${totalDevices}`;
                    if (logDiv) logDiv.innerHTML += `<p class="text-xs text-green-300">✓ Finished ${escapeHtml(data.ip || '')}</p>`;
                } else if (data.type === 'complete') {
                    // Backend sends results
                    wizardState.collectedInfo = data.results || [];
                    wizardState.collectionComplete = true;
                    const nextBtn = document.getElementById('wizardNextBtn');
                    if (nextBtn) {
                        nextBtn.disabled = false;
                        nextBtn.textContent = 'Next →';
                    }
                    if (logDiv) logDiv.innerHTML += `<p class="text-xs text-green-300 mt-2">Collection complete.</p>`;
                } else if (data.type === 'error') {
                    if (logDiv) logDiv.innerHTML += `<p class="text-xs text-red-300">Error: ${escapeHtml(data.error || 'Unknown error')}</p>`;
                }
            }
        }

    } catch (err) {
        console.error('Collection error:', err);
        const log = document.getElementById('wizardCollectionLog');
        if (log) {
            log.innerHTML = `<div class="p-3 rounded bg-red-500/10 border border-red-500/30"><p class="text-red-300"><strong>Collection error:</strong> ${esc(err.message || 'Unknown error')}</p></div>`;
        }
    }
}

async function wizardComplete() {
    if (wizardState.completionStarted) return;
    wizardState.completionStarted = true;
    try {
        const devices = wizardState.collectedInfo.map(info => ({
            ip: info.ip,
            user: info.user,
            hostname: info.system_info?.hostname || info.ip,
            friendly_name: info.system_info?.hostname || info.ip,
            system_info: info.system_info,
            services: info.services
        }));
        
        const payload = { devices };
        if (wizardState.selectedKeyId) {
            payload.ssh_key_id = wizardState.selectedKeyId;
        }
        
        const response = await fetch('/wizard/add-devices', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        wizardState.addedDevices = data.devices || [];
        
        const counts = data.counts || { added: (data.devices || []).length, skipped: 0 };
        document.getElementById('wizardCompletionMessage').textContent = `${counts.added} device(s) added successfully!${counts.skipped ? ` (${counts.skipped} skipped)` : ''}`;
        
        const devicesList = document.getElementById('wizardAddedDevicesList');
        devicesList.innerHTML = '';
        (data.devices || []).forEach(device => {
            const div = document.createElement('div');
            div.className = 'glass-container border border-white/10 rounded-lg p-3 text-sm bg-white/5';
            div.innerHTML = `<p class="font-medium termix-text">${esc(device.hostname)}</p><p class="termix-muted">${esc(device.ip)}</p>`;
            devicesList.appendChild(div);
        });
        
        // Load groups and tags
        wizardLoadGroups();
        wizardLoadTags();

        // Refresh main host list so newly added nodes appear without a manual page refresh
        try {
            if (typeof window.refreshHostsSidebar === 'function') {
                await window.refreshHostsSidebar();
                if (typeof window.showToast === 'function') window.showToast('Hosts refreshed', 'success');
            } else {
                console.warn('[wizard] refreshHostsSidebar not available; falling back to page reload');
                if (typeof window.showToast === 'function') window.showToast('Refreshing page to show new hosts...', 'info');
                setTimeout(() => window.location.reload(), 250);
            }
        } catch (e) {
            console.warn('[wizard] host refresh failed; falling back to page reload', e);
            setTimeout(() => window.location.reload(), 250);
        }

        wizardState.completionComplete = true;
        const nextBtn = document.getElementById('wizardNextBtn');
        if (nextBtn) {
            nextBtn.disabled = false;
            nextBtn.textContent = 'Close';
        }
    } catch (err) {
        wizardState.completionStarted = false;
        alert(`Completion error: ${err.message}`);
        const nextBtn = document.getElementById('wizardNextBtn');
        if (nextBtn) {
            nextBtn.disabled = false;
            nextBtn.textContent = 'Finish';
        }
    }
}

function wizardLoadGroups() {
    fetch('/groups')
        .then(r => r.json())
        .then(groups => {
            const select = document.getElementById('wizardGroupSelect');
            if (select) {
                select.innerHTML = '<option value="">-- No group --</option>';
                groups.forEach(group => {
                    const opt = document.createElement('option');
                    opt.value = group.id;
                    opt.textContent = group.name;
                    select.appendChild(opt);
                });
            }
        });
}

function wizardLoadTags() {
    fetch('/tags')
        .then(r => r.json())
        .then(tags => {
            const div = document.getElementById('wizardTagCheckboxes');
            if (div) {
                div.innerHTML = '';
                tags.forEach(tag => {
                    const label = document.createElement('label');
                    label.className = 'flex items-center gap-2';
                    label.innerHTML = `<input type="checkbox" value="${tag.id}" class="rounded border-white/20"> ${String(tag.name ?? '')}`;
                    div.appendChild(label);
                });
            }
        });
}
