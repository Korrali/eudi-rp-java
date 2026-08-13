// Plain JavaScript, no build step, no framework — see the demo README for why: this is a single
// page with no routing/forms/state-management complexity that would justify Angular's overhead,
// and shipping hand-written JS avoids adding a Node/npm toolchain dependency for one HTML page.

const startBtn = document.getElementById('start-btn');
const flowBody = document.getElementById('flow-body');
const qrImage = document.getElementById('qr-image');
const sameDeviceLink = document.getElementById('same-device-link');
const mockWalletNote = document.getElementById('mock-wallet-note');
const simulateScanBtn = document.getElementById('simulate-scan-btn');
const statusTrack = document.querySelectorAll('.status-track li');
const resultPanel = document.getElementById('result-panel');
const resultTable = document.getElementById('result-table');
const errorPanel = document.getElementById('error-panel');
const errorText = document.getElementById('error-text');
const rawView = document.getElementById('raw-view');
const rawContent = document.getElementById('raw-content');

const STATES = ['AWAITING_SCAN', 'REQUEST_SENT', 'RESPONSE_RECEIVED', 'VERIFIED'];
let currentTransactionId = null;
let pollHandle = null;

startBtn.addEventListener('click', async () => {
  startBtn.disabled = true;
  resultPanel.hidden = true;
  errorPanel.hidden = true;
  rawContent.textContent = '';

  const res = await fetch('/api/presentations', { method: 'POST' });
  const data = await res.json();
  currentTransactionId = data.transactionId;

  qrImage.src = `/api/presentations/${data.transactionId}/qr.png`;
  sameDeviceLink.href = data.deepLink;
  mockWalletNote.hidden = data.walletMode !== 'mock';

  flowBody.hidden = false;
  setActiveState('AWAITING_SCAN');
  startPolling();
  startBtn.disabled = false;
});

simulateScanBtn.addEventListener('click', async () => {
  simulateScanBtn.disabled = true;
  await fetch(`/api/presentations/${currentTransactionId}/simulate-scan`, { method: 'POST' });
  simulateScanBtn.disabled = false;
});

function startPolling() {
  if (pollHandle) clearInterval(pollHandle);
  pollHandle = setInterval(async () => {
    if (!currentTransactionId) return;
    const res = await fetch(`/api/presentations/${currentTransactionId}`);
    const data = await res.json();
    setActiveState(data.state);

    if (data.state === 'VERIFIED') {
      clearInterval(pollHandle);
      showResult(data);
    } else if (data.state === 'FAILED') {
      clearInterval(pollHandle);
      showError(data);
    }
  }, 700);
}

function setActiveState(state) {
  const idx = STATES.indexOf(state);
  statusTrack.forEach((li, i) => {
    li.classList.toggle('done', i < idx);
    li.classList.toggle('active', i === idx);
  });
}

function showResult(data) {
  resultPanel.hidden = false;
  resultTable.innerHTML = '';
  addRow(resultTable, 'RP certificate issuer', data.rpCertificateIssuer);
  addRow(resultTable, 'Revocation checked', data.revocationCheckAttempted ? 'yes' : 'no');
  addRow(resultTable, 'Revocation outcome', data.revocationCheckOutcome);
  (data.credentials || []).forEach((cred) => {
    addRow(resultTable, 'Credential format', cred.format);
    Object.entries(cred.disclosedClaims || {}).forEach(([k, v]) => {
      addRow(resultTable, k, String(v));
    });
  });
}

function showError(data) {
  errorPanel.hidden = false;
  errorText.textContent = `${data.errorType}: ${data.errorMessage}`;
}

function addRow(table, label, value) {
  const tr = document.createElement('tr');
  const td1 = document.createElement('td');
  td1.textContent = label;
  const td2 = document.createElement('td');
  td2.textContent = value;
  tr.append(td1, td2);
  table.appendChild(tr);
}

rawView.addEventListener('toggle', async () => {
  if (!rawView.open || !currentTransactionId) return;
  const res = await fetch(`/api/presentations/${currentTransactionId}/raw`);
  const data = await res.json();
  rawContent.textContent = JSON.stringify(data, null, 2);
});

// --- Failure simulator ---

document.querySelectorAll('.sim-btn').forEach((btn) => {
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    const endpoint = btn.dataset.endpoint;
    try {
      const res = await fetch(endpoint, { method: 'POST' });
      const data = await res.json();
      renderSimResult(data);
    } finally {
      btn.disabled = false;
    }
  });
});

function renderSimResult(data) {
  const container = document.getElementById('sim-results');
  const outcome = (data.outcome || '').toString();
  const unexpected = outcome.startsWith('UNEXPECTED');

  const card = document.createElement('div');
  card.className = 'sim-result ' + (unexpected ? 'unexpected' : 'expected');

  const heading = document.createElement('strong');
  heading.textContent = data.scenario;
  card.appendChild(heading);

  const dl = document.createElement('dl');
  Object.entries(data).forEach(([key, value]) => {
    if (key === 'scenario') return;
    const dt = document.createElement('dt');
    dt.textContent = key;
    const dd = document.createElement('dd');
    dd.textContent = typeof value === 'object' ? JSON.stringify(value) : String(value);
    dl.append(dt, dd);
  });
  card.appendChild(dl);

  container.prepend(card);
}
