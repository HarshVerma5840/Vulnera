/* ============================================================================
   SCANNER MODULE — Scan Form, Live Polling, Results
   ============================================================================ */

const Scanner = (() => {
  let pollInterval = null;

  function render(container) {
    container.innerHTML = `
      <div class="page-enter">
        <div class="page-header">
          <h1>Launch Scan</h1>
          <p>Run a unified Nmap + OWASP ZAP vulnerability scan</p>
        </div>

        <!-- Scan Form -->
        <div class="card scan-form-card">
          <form id="scanForm">
            <div class="form-group">
              <label class="form-label" for="scan-target">Target URL / IP</label>
              <input class="form-input" type="text" id="scan-target"
                     value="http://demo.testfire.net" required
                     placeholder="e.g. https://example.com">
            </div>
            <div class="form-group">
              <label class="form-label" for="scan-mode">Scan Mode</label>
              <select class="form-select" id="scan-mode">
                <option value="quick">Quick — Top vulnerabilities, depth 3</option>
                <option value="full">Full — All plugins, depth 5, deep rescan</option>
              </select>
              <div class="mode-info" id="modeInfo">
                <span class="mode-tag">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                  Quick ≈ 2-5 min
                </span>
              </div>
            </div>
            <button class="btn btn-primary" type="submit" id="scanBtn">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              Launch Scan
            </button>
          </form>
        </div>

        <!-- Progress Card (hidden) -->
        <div id="progressCard" class="card progress-card hidden">
          <div class="progress-header">
            <h2>Scan Progress</h2>
            <span id="statusBadge" class="badge badge-starting">Starting</span>
          </div>
          <div class="progress-body">
            <div id="scanSpinner" class="spinner"></div>
            <span id="scanAction" class="progress-action">Initializing backend processes...</span>
          </div>
          <div class="progress-scanid">
            Scan ID: <code id="scanIdDisplay">—</code>
          </div>
        </div>

        <!-- Results Card (hidden) -->
        <div id="resultsCard" class="card results-card hidden">
          <h2 style="font-size:18px;font-weight:600;margin-bottom:4px;">Scan Complete</h2>
          <p style="font-size:14px;color:var(--text-muted);margin-bottom:16px;">Results are ready to review</p>
          <div class="results-grid">
            <div class="result-stat">
              <div class="result-stat-label">Duration</div>
              <div class="result-stat-value cyan" id="resDuration">—</div>
            </div>
            <div class="result-stat">
              <div class="result-stat-label">Web Targets</div>
              <div class="result-stat-value emerald" id="resTargets">—</div>
            </div>
            <div class="result-stat">
              <div class="result-stat-label">ZAP Reports</div>
              <div class="result-stat-value amber" id="resReports">—</div>
            </div>
          </div>
          <a id="viewReportBtn" class="btn btn-success" href="#" style="margin-top:8px;">
            View Full Report
          </a>
        </div>
      </div>
    `;

    // Mode info update
    const modeSelect = document.getElementById('scan-mode');
    const modeInfo = document.getElementById('modeInfo');
    modeSelect.addEventListener('change', () => {
      if (modeSelect.value === 'quick') {
        modeInfo.innerHTML = `<span class="mode-tag"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Quick ≈ 2-5 min</span>`;
      } else {
        modeInfo.innerHTML = `<span class="mode-tag"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Full ≈ 10-30 min</span>`;
      }
    });

    // Form submit
    document.getElementById('scanForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      await startScan();
    });
  }

  async function startScan() {
    const target = document.getElementById('scan-target').value.trim();
    const mode = document.getElementById('scan-mode').value;
    const btn = document.getElementById('scanBtn');
    const progressCard = document.getElementById('progressCard');
    const resultsCard = document.getElementById('resultsCard');

    // Reset UI
    btn.disabled = true;
    btn.innerHTML = `<div class="spinner" style="width:16px;height:16px;border-width:2px;"></div> Starting...`;
    progressCard.classList.remove('hidden', 'complete', 'failed');
    resultsCard.classList.add('hidden');
    document.getElementById('scanSpinner').style.display = '';
    document.getElementById('statusBadge').className = 'badge badge-starting';
    document.getElementById('statusBadge').textContent = 'Starting';
    document.getElementById('scanAction').textContent = 'Initializing backend processes...';

    try {
      const url = `/api/vulnerascan?target=${encodeURIComponent(target)}&zap_mode=${encodeURIComponent(mode)}`;
      const res = await fetch(url, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to start scan');
      }
      const data = await res.json();
      document.getElementById('scanIdDisplay').textContent = data.scan_id;

      // Start polling
      if (pollInterval) clearInterval(pollInterval);
      pollInterval = setInterval(() => pollStatus(data.scan_id), 2500);
    } catch (err) {
      document.getElementById('scanAction').textContent = 'Error: ' + err.message;
      document.getElementById('statusBadge').className = 'badge badge-failed';
      document.getElementById('statusBadge').textContent = 'Failed';
      document.getElementById('scanSpinner').style.display = 'none';
      resetBtn();
    }
  }

  async function pollStatus(scanId) {
    try {
      const res = await fetch(`/api/vulnerascan/${scanId}`);
      if (!res.ok) return;
      const data = await res.json();

      document.getElementById('scanAction').textContent = data.current_action || '—';
      const statusText = (data.status || '').replace(/_/g, ' ');

      const badge = document.getElementById('statusBadge');
      badge.textContent = statusText;
      badge.className = `badge badge-${data.status}`;

      if (data.status === 'failed') {
        document.getElementById('scanSpinner').style.display = 'none';
        document.getElementById('progressCard').classList.add('failed');
        clearInterval(pollInterval);
        pollInterval = null;
        resetBtn();
      } else if (data.status === 'complete') {
        document.getElementById('scanSpinner').style.display = 'none';
        document.getElementById('progressCard').classList.add('complete');
        clearInterval(pollInterval);
        pollInterval = null;
        await showResults(scanId);
        resetBtn();
      }
    } catch (err) {
      console.error('Polling error:', err);
    }
  }

  async function showResults(scanId) {
    const resultsCard = document.getElementById('resultsCard');

    try {
      const res = await fetch(`/api/vulnerascan/${scanId}/results`);
      if (res.ok) {
        const report = await res.json();
        document.getElementById('resDuration').textContent =
          report.timing ? `${report.timing.total_duration_seconds}s` : '—';
        document.getElementById('resTargets').textContent =
          report.discovered_web_targets ? report.discovered_web_targets.length : '0';
        document.getElementById('resReports').textContent =
          report.zap_reports ? report.zap_reports.length : '0';
      }
    } catch (err) {
      console.error('Could not fetch results:', err);
    }

    document.getElementById('viewReportBtn').href = `#/report/${scanId}`;
    resultsCard.classList.remove('hidden');
  }

  function resetBtn() {
    const btn = document.getElementById('scanBtn');
    btn.disabled = false;
    btn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      Launch New Scan
    `;
  }

  function cleanup() {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  }

  return { render, cleanup };
})();
