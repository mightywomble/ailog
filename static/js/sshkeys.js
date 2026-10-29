// SSH key list + form wiring (the last of the identical copies, whose globals
// previously won by being declared last). Moved verbatim; exports loadSshKeys
// for the core module.

// SSH Keys Management
async function loadSshKeys() {
    const listDiv = document.getElementById('ssh-keys-list');
    if (!listDiv) return;
    
    try {
        const response = await fetch('/ssh-keys');
        let keys = await response.json();
        
        // Handle error responses
        if (!response.ok || (keys && keys.error)) {
            listDiv.innerHTML = `<p class="text-sm text-red-400">Error loading keys: ${keys?.error || response.statusText}</p>`;
            return;
        }
        
        // Ensure keys is an array
        if (!Array.isArray(keys)) {
            keys = [];
        }
        
        if (keys.length === 0) {
            listDiv.innerHTML = '<p class="text-sm termix-muted text-center py-8">No SSH keys stored yet.</p>';
            return;
        }
        
        listDiv.innerHTML = keys.map(key => `
            <div class="flex items-center justify-between p-3 rounded border border-white/10 bg-white/5 hover:bg-white/10 transition">
                <div class="flex-1">
                    <p class="font-medium text-white">${key.key_name}</p>
                    <div class="flex gap-3 text-xs termix-muted mt-1">
                        <span>Type: ${key.key_type}</span>
                        <span>Encrypted: ${key.is_encrypted ? '✓' : '✗'}</span>
                        <span>Created: ${new Date(key.created_at).toLocaleDateString()}</span>
                    </div>
                </div>
                <button class="delete-ssh-key-btn bg-red-600 hover:bg-red-500 text-white px-3 py-1 text-xs rounded transition" data-key-id="${key.id}">Delete</button>
            </div>
        `).join('');
        
        // Add delete event listeners
        listDiv.querySelectorAll('.delete-ssh-key-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const keyId = btn.dataset.keyId;
                const keyName = btn.parentElement.querySelector('.font-medium').textContent;
                
                if (!confirm(`Delete SSH key "${keyName}"?`)) return;
                
                try {
                    const delResp = await fetch(`/ssh-keys/${keyId}`, { method: 'DELETE' });
                    const delData = await delResp.json();
                    
                    if (!delResp.ok) {
                        // Check if key is in use
                        if (delResp.status === 409) {
                            window.showToast(`Cannot delete: ${delData.error}`, 'error');
                        } else {
                            window.showToast(`Error: ${delData.error}`, 'error');
                        }
                    } else {
                        window.showToast(`Key "${keyName}" deleted`, 'success');
                        loadSshKeys();
                    }
                } catch (err) {
                    window.showToast(`Failed to delete key: ${err.message}`, 'error');
                }
            });
        });
    } catch (err) {
        listDiv.innerHTML = `<p class="text-sm text-red-400">Error loading keys: ${err.message}</p>`;
    }
}

// Setup SSH key form handlers
document.addEventListener('DOMContentLoaded', () => {
    const saveBtn = document.getElementById('save-new-ssh-key-btn');
    const clearBtn = document.getElementById('clear-new-ssh-key-btn');
    const nameInput = document.getElementById('new-key-name');
    const contentInput = document.getElementById('new-key-content');
    const statusDiv = document.getElementById('new-ssh-key-status');
    
    if (!saveBtn) return;
    
    const showStatus = (msg, type = 'info') => {
        statusDiv.classList.remove('hidden', 'bg-red-500/20', 'border-red-500/30', 'text-red-300', 'bg-green-500/20', 'border-green-500/30', 'text-green-300');
        if (type === 'error') {
            statusDiv.classList.add('bg-red-500/20', 'border-red-500/30', 'text-red-300');
        } else if (type === 'success') {
            statusDiv.classList.add('bg-green-500/20', 'border-green-500/30', 'text-green-300');
        } else {
            statusDiv.classList.add('bg-blue-500/20', 'border-blue-500/30', 'text-blue-300');
        }
        statusDiv.textContent = msg;
    };
    
    saveBtn.addEventListener('click', async () => {
        const name = nameInput.value.trim();
        const content = contentInput.value.trim();
        
        if (!name) {
            showStatus('Please enter a key name', 'error');
            return;
        }
        if (!content) {
            showStatus('Please paste the key content', 'error');
            return;
        }
        
        showStatus('Saving key...', 'info');
        
        try {
            const resp = await fetch('/ssh-keys/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key_name: name, key_content: content })
            });
            const data = await resp.json();
            
            if (!resp.ok) {
                showStatus(`Error: ${data.error}`, 'error');
            } else {
                showStatus(`Key saved! (ID: ${data.id})`, 'success');
                nameInput.value = '';
                contentInput.value = '';
                setTimeout(() => loadSshKeys(), 500);
            }
        } catch (err) {
            showStatus(`Failed: ${err.message}`, 'error');
        }
    });
    
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            nameInput.value = '';
            contentInput.value = '';
            statusDiv.classList.add('hidden');
        });
    }
});

export { loadSshKeys };
