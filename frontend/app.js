// State metrics trackers
let totalQueries = 0;
let blockedThreats = 0;
let auditLogs = [];
let threatChartInstance = null;

function switchView(viewName) {
    const chatView = document.getElementById('chat-view');
    const adminView = document.getElementById('admin-view');
    const btnChat = document.getElementById('btn-chat');
    const btnAdmin = document.getElementById('btn-admin');

    if (viewName === 'chat') {
        chatView.classList.remove('hidden');
        adminView.classList.add('hidden');
        btnChat.classList.add('active-nav');
        btnAdmin.classList.remove('active-nav');
    } else {
        chatView.classList.add('hidden');
        adminView.classList.remove('hidden');
        btnChat.classList.remove('active-nav');
        btnAdmin.classList.add('active-nav');
        updateDashboardUI();
    }
}

function sendPrompt() {
    const inputEl = document.getElementById('user-input');
    const promptText = inputEl.value.trim();
    if (!promptText) return;

    appendMessage('user', promptText);
    totalQueries++;
    inputEl.value = '';

    // Create immediate visual placeholder for scanning simulation
    const scanningId = appendMessage('system', "Aegis Gateway Engine: Evaluating lexical threat vector...");

    setTimeout(() => {
        // Clear scanning status message indicator
        scanningId.remove();

        // MOCK MALICIOUS WORD FILTERING
        const lowerPrompt = promptText.toLowerCase();
        if (lowerPrompt.includes('hack') || lowerPrompt.includes('ignore') || lowerPrompt.includes('system Override')) {
            blockedThreats++;
            appendMessage('security-alert', `⚠️ THREAT BLOCKED: Malicious prompt configuration string matching OWASP LLM01 pattern detected. Token transmission terminated.`);
            
            // Log local incident trace tracking data metrics
            auditLogs.unshift({
                timestamp: new Date().toLocaleTimeString(),
                user_id: `USR-${Math.floor(1000 + Math.random() * 9000)}`,
                prompt: promptText,
                risk_score: "0.98 HIGH"
            });
        } else {
            appendMessage('ai', `[Aegis Clean Response]: Your request processed safely. The system verified no command parameters were overwritten in your payload data.`);
        }
    }, 800);
}

function appendMessage(sender, text) {
    const history = document.getElementById('chat-history');
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${sender}`;
    msgDiv.innerText = text;
    history.appendChild(msgDiv);
    history.scrollTop = history.scrollHeight;
    return msgDiv;
}

function updateDashboardUI() {
    document.getElementById('stat-total').innerText = totalQueries;
    document.getElementById('stat-blocked').innerText = blockedThreats;

    // Repopulate dynamic HTML data logs audit rows
    const tableBody = document.getElementById('log-table-body');
    tableBody.innerHTML = '';
    
    auditLogs.forEach(log => {
        const row = `<tr>
            <td>${log.timestamp}</td>
            <td>${log.user_id}</td>
            <td><code>${escapeHTML(log.prompt)}</code></td>
            <td><span class="badge-high">${log.risk_score}</span></td>
        </tr>`;
        tableBody.insertAdjacentHTML('beforeend', row);
    });

    renderMetricsChart();
}

function renderMetricsChart() {
    const ctx = document.getElementById('threatChart').getContext('2d');
    if (threatChartInstance) {
        threatChartInstance.destroy();
    }

    const safeCount = totalQueries - blockedThreats;

    threatChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Authorized Queries', 'Blocked Injections'],
            datasets: [{
                data: [safeCount, blockedThreats],
                backgroundColor: ['#10b981', '#ef4444'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#f8fafc' } }
            }
        }
    });
}

function escapeHTML(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}