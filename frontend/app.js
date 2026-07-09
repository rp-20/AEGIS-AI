/* =========================================================================
   AEGIS PROMPT GATEWAY — LIVE BACKEND MODE
   Connected to FastAPI and SQLite. 
   ========================================================================= */

const BACKEND_URL = 'http://127.0.0.1:8000'; // Make sure this matches your uvicorn port!

// ---------- Global State ----------
let totalQueries = 0;
let blockedThreats = 0;
let auditLogs = [];
let threatChartInstance = null;
const SESSION_USER_ID = `EMP-${Math.floor(1000 + Math.random() * 9000)}`;

// ---------- View Navigation ----------
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
        
        // Fetch real database logs whenever the admin tab is opened
        fetchAdminLogs();
    }
}

// ---------- Chat API Connection ----------
async function sendPrompt() {
    const inputEl = document.getElementById('user-input');
    const promptText = inputEl.value.trim();
    if (!promptText) return;

    appendMessage('user', promptText);
    inputEl.value = '';

    const scanningId = appendMessage('system', "Aegis Gateway Engine: Transmitting payload to FastAPI backend...");

    try {
        // 1. Send the data to the backend
        const response = await fetch(`${BACKEND_URL}/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: SESSION_USER_ID, prompt: promptText })
        });

        if (!response.ok) throw new Error("Backend connection failed");
        
        // 2. Wait for the Python server to score it
        const result = await response.json();
        scanningId.remove();

        // 3. Render the correct chat UI based on the backend's decision
        if (result.decision === 'BLOCK') {
            appendMessage('security-alert', `⚠️ THREAT BLOCKED: ${result.category} detected. Risk Score: ${result.finalScore}/100. Token transmission terminated.`);
        } else if (result.decision === 'WARNING') {
            appendMessage('security-alert', `⚠️ WARNING: Suspicious activity flagged. Risk Score: ${result.finalScore}/100.`);
        } else {
            appendMessage('ai', `[Aegis Clean Response]: Your request processed safely. Risk Score: ${result.finalScore}/100. The system verified no command parameters were overwritten.`);
        }

    } catch (error) {
        scanningId.remove();
        appendMessage('security-alert', `⚠️ SERVER ERROR: Cannot connect to FastAPI backend at ${BACKEND_URL}. Ensure uvicorn is running.`);
        console.error("API Error:", error);
    }
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

// ---------- Dashboard API Connection ----------
async function fetchAdminLogs() {
    try {
        const response = await fetch(`${BACKEND_URL}/admin/logs`);
        if (!response.ok) throw new Error("Failed to fetch logs");
        
        // Pull the real SQLite database rows
        auditLogs = await response.json();
        
        // Calculate the real stats based on the database
        totalQueries = auditLogs.length;
        blockedThreats = auditLogs.filter(log => log.decision === 'BLOCK').length;
        
    } catch (error) {
        console.error("Could not fetch logs from backend:", error);
    }
    
    // Update the charts whether the fetch succeeded or failed
    updateDashboardUI();
}

function updateDashboardUI() {
    document.getElementById('stat-total').innerText = totalQueries;
    document.getElementById('stat-blocked').innerText = blockedThreats;

    // Repopulate HTML table with backend data
    const tableBody = document.getElementById('log-table-body');
    tableBody.innerHTML = '';
    
    auditLogs.forEach(log => {
        let badgeStyle = log.decision === 'BLOCK' 
            ? 'background-color: #991b1b; padding: 0.25rem 0.5rem; border-radius: 0.25rem; color: #f87171; font-weight: bold;' 
            : 'background-color: #065f46; padding: 0.25rem 0.5rem; border-radius: 0.25rem; color: #34d399; font-weight: bold;';

        const row = `<tr>
            <td>${log.timestamp || new Date().toLocaleTimeString()}</td>
            <td>${log.user_id}</td>
            <td><code>${escapeHTML(log.prompt)}</code></td>
            <td><span style="${badgeStyle}">${log.finalScore || log.risk_score} - ${log.decision}</span></td>
        </tr>`;
        tableBody.insertAdjacentHTML('beforeend', row);
    });

    renderMetricsChart();
}

function renderMetricsChart() {
    const ctx = document.getElementById('threatChart').getContext('2d');
    if (threatChartInstance) threatChartInstance.destroy();

    const safeCount = Math.max(0, totalQueries - blockedThreats);

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
    if (!str) return "";
    return str.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}