/* =========================================================================
   AEGIS PROMPT GATEWAY — LIVE FULL-STACK MODE
   Connected to FastAPI backend.
   ========================================================================= */

const BACKEND_URL = 'https://aegis-ai-o1un.onrender.com';
const SESSION_USER_ID = `USR-${Math.floor(1000 + Math.random() * 9000)}`;

// ---------- State ----------
let auditLogs = [];
let decisionChartInstance = null;
let categoryChartInstance = null;
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 60;

// ---------- API Calls ----------
async function analyzePrompt(text) {
    try {
        const response = await fetch(`${BACKEND_URL}/api/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt: text, user_id: SESSION_USER_ID })
        });
        if (!response.ok) throw new Error("Backend connection failed");
        return await response.json();
    } catch (error) {
        console.error(error);
        return { decision: 'ERROR' };
    }
}

async function fetchAuditLogs() {
    try {
        const response = await fetch(`${BACKEND_URL}/api/logs`);
        if (response.ok) {
            auditLogs = await response.json();
            updateDashboardUI();
        }
    } catch (error) {
        console.error("Failed to load logs:", error);
    }
}

// ---------- View switching ----------
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
        fetchAuditLogs(); // Fetch live logs when opening dashboard
    }
}

// ---------- Console interaction ----------
async function sendPrompt() {
    const inputEl = document.getElementById('user-input');
    const promptText = inputEl.value.trim();
    if (!promptText) return;

    appendMessage('user', promptText);
    inputEl.value = '';

    const sweepLabel = document.getElementById('sweep-label');
    sweepLabel.textContent = 'TRANSMITTING PAYLOAD…';
    const scanningNode = appendMessage('system', 'Aegis gateway — transmitting payload to FastAPI backend for analysis…');

    const result = await analyzePrompt(promptText);

    scanningNode.remove();
    sweepLabel.textContent = 'MONITORING';

    if (result.decision === 'ERROR') {
        appendMessage('security-alert', `⚠️ SERVER ERROR: Cannot connect to backend. Is uvicorn running at ${BACKEND_URL}?`);
        return;
    }

    renderAnalysisPanel(result);

    if (result.decision === 'BLOCK') {
        appendMessage('security-alert',
            `<span class="msg-badge block">BLOCKED · ${result.finalScore}</span><br>${escapeHTML(result.category)} — request halted before reaching the model.`, true);
    } else if (result.decision === 'WARNING') {
        appendMessage('security-warning',
            `<span class="msg-badge warn">WARNING · ${result.finalScore}</span><br>${escapeHTML(result.category)} — forwarded to the model with a flag.`, true);
    } else {
        appendMessage('ai', `[Model response] Request cleared the gateway (risk ${result.finalScore}) and was forwarded safely.`);
    }
}

function appendMessage(sender, text, isHTML) {
    const history = document.getElementById('chat-history');
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${sender}`;
    if (isHTML) msgDiv.innerHTML = text; else msgDiv.innerText = text;
    history.appendChild(msgDiv);
    history.scrollTop = history.scrollHeight;
    return msgDiv;
}

// ---------- Live analysis panel ----------
function decisionColor(decision) {
    if (decision === 'BLOCK') return getCSS('--red');
    if (decision === 'WARNING') return getCSS('--amber');
    return getCSS('--green');
}

function getCSS(varName) {
    return getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
}

function renderAnalysisPanel(result) {
    document.getElementById('gauge-value').textContent = result.finalScore;
    document.getElementById('gauge-decision').textContent = result.decision;

    const ring = document.getElementById('gauge-ring');
    const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * result.finalScore) / 100;
    ring.style.strokeDasharray = `${GAUGE_CIRCUMFERENCE}`;
    ring.style.strokeDashoffset = `${offset}`;
    ring.style.stroke = decisionColor(result.decision);

    document.getElementById('val-rule').textContent = result.ruleScore;
    document.getElementById('val-pattern').textContent = result.patternScore;
    document.getElementById('val-ai').textContent = result.aiScore;
    document.getElementById('bar-rule').style.width = result.ruleScore + '%';
    document.getElementById('bar-pattern').style.width = result.patternScore + '%';
    document.getElementById('bar-ai').style.width = result.aiScore + '%';

    const box = document.getElementById('explain-box');
    const keywordChips = result.matchedKeywords.length
        ? result.matchedKeywords.map(k => `<span class="chip">${escapeHTML(k)}</span>`).join('')
        : '<span class="chip">none</span>';
    const patternChips = result.matchedPatterns.length
        ? result.matchedPatterns.map(p => `<span class="chip">${escapeHTML(p)}</span>`).join('')
        : '<span class="chip">none</span>';

    box.innerHTML = `
        <div class="explain-title">Category</div>
        <div>${escapeHTML(result.category)} <span style="color:var(--text-faint)">(${result.confidence}% confidence)</span></div>
        <div class="explain-title">Matched Keywords</div>
        <div class="chip-row">${keywordChips}</div>
        <div class="explain-title">Matched Patterns</div>
        <div class="chip-row">${patternChips}</div>
        <div class="explain-title">Why</div>
        <div>${escapeHTML(result.reasoning)}</div>
        ${result.rewrite ? `<div class="explain-title">Suggested Safe Rewrite</div><div class="rewrite-box">${escapeHTML(result.rewrite)}</div>` : ''}
    `;
}

// ---------- Logging + Dashboard ----------
function updateDashboardUI() {
    const total = auditLogs.length;
    const blocked = auditLogs.filter(l => l.decision === 'BLOCK').length;
    const warned = auditLogs.filter(l => l.decision === 'WARNING').length;
    const avg = total ? Math.round(auditLogs.reduce((s, l) => s + l.finalScore, 0) / total) : 0;

    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-blocked').textContent = blocked;
    document.getElementById('stat-warned').textContent = warned;
    document.getElementById('stat-avg').textContent = avg;

    renderLogTable();
    renderDecisionChart(total - blocked - warned, warned, blocked);
    renderCategoryChart();
}

function renderLogTable() {
    const tableBody = document.getElementById('log-table-body');
    const emptyState = document.getElementById('log-empty');
    tableBody.innerHTML = '';

    if (!auditLogs.length) {
        emptyState.style.display = 'block';
        return;
    }
    emptyState.style.display = 'none';

    auditLogs.forEach((log, idx) => {
        const badgeClass = log.decision === 'BLOCK' ? 'badge-block' : log.decision === 'WARNING' ? 'badge-warn' : 'badge-allow';
        const row = document.createElement('tr');
        row.className = 'log-row';
        row.innerHTML = `
            <td>${log.timestamp}</td>
            <td>${log.user_id}</td>
            <td><code>${escapeHTML(truncate(log.prompt, 42))}</code></td>
            <td>${escapeHTML(log.category)}</td>
            <td>${log.finalScore}</td>
            <td><span class="badge ${badgeClass}">${log.decision}</span></td>
        `;
        row.addEventListener('click', () => toggleDetailRow(idx));
        tableBody.appendChild(row);
    });
}

function toggleDetailRow(idx) {
    const existing = document.getElementById(`detail-${idx}`);
    if (existing) { existing.remove(); return; }
    document.querySelectorAll('.detail-row').forEach(r => r.remove());

    const log = auditLogs[idx];
    const rows = document.querySelectorAll('#log-table-body tr.log-row');
    const targetRow = rows[idx];

    const detail = document.createElement('tr');
    detail.className = 'detail-row';
    detail.id = `detail-${idx}`;
    detail.innerHTML = `
        <td colspan="6">
            <div class="detail-grid">
                <div><b>Rule Score</b>${log.ruleScore}</div>
                <div><b>Pattern Score</b>${log.patternScore}</div>
                <div><b>AI Score</b>${log.aiScore}</div>
                <div><b>Confidence</b>${log.confidence}%</div>
                <div><b>Matched Keywords</b>${log.matchedKeywords.join(', ') || '—'}</div>
                <div><b>Matched Patterns</b>${log.matchedPatterns.join(', ') || '—'}</div>
            </div>
            <div class="detail-grid" style="margin-top:0.7rem;grid-template-columns:1fr;">
                <div><b>Reasoning</b>${escapeHTML(log.reasoning)}</div>
                ${log.rewrite && log.rewrite !== "null" ? `<div style="margin-top:0.5rem;"><b>Suggested Rewrite</b>${escapeHTML(log.rewrite)}</div>` : ''}
            </div>
        </td>
    `;
    targetRow.insertAdjacentElement('afterend', detail);
}

function renderDecisionChart(allow, warn, block) {
    const ctx = document.getElementById('decisionChart').getContext('2d');
    if (decisionChartInstance) decisionChartInstance.destroy();
    decisionChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Allowed', 'Warning', 'Blocked'],
            datasets: [{
                data: [Math.max(allow, 0), warn, block],
                backgroundColor: [getCSS('--green'), getCSS('--amber'), getCSS('--red')],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { color: getCSS('--text-dim'), font: { family: 'JetBrains Mono', size: 11 } } } }
        }
    });
}

function renderCategoryChart() {
    const counts = {};
    auditLogs.forEach(l => {
        if (l.decision === 'ALLOW') return;
        counts[l.category] = (counts[l.category] || 0) + 1;
    });
    const labels = Object.keys(counts);
    const data = Object.values(counts);

    const ctx = document.getElementById('categoryChart').getContext('2d');
    if (categoryChartInstance) categoryChartInstance.destroy();
    categoryChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.length ? labels : ['No threats yet'],
            datasets: [{
                data: data.length ? data : [0],
                backgroundColor: getCSS('--cyan'),
                borderRadius: 4,
                maxBarThickness: 34
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: getCSS('--text-dim'), stepSize: 1, font: { family: 'JetBrains Mono', size: 10 } }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: getCSS('--text-dim'), font: { family: 'JetBrains Mono', size: 10 } }, grid: { display: false } }
            }
        }
    });
}

function escapeHTML(str) { return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function truncate(str, len) { return str.length > len ? str.slice(0, len) + '…' : str; }