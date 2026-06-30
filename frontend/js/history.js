/* ============================================================================
   HISTORY MODULE — Past Scan Reports
   ============================================================================ */

const History = (() => {

  function render(container) {
    container.innerHTML = `
      <div class="page-enter">
        <div class="page-header">
          <h1>Scan History</h1>
          <p>Review your past vulnerability scans</p>
        </div>
        <div class="card" style="padding:0; overflow:hidden;">
          <div id="historyContent" style="padding:4px;">
            <div style="padding:40px;text-align:center;color:var(--text-muted);">Loading...</div>
          </div>
        </div>
      </div>
    `;
    loadHistory();
  }

  async function loadHistory() {
    const content = document.getElementById('historyContent');

    try {
      const res = await fetch('/api/scan-history');
      if (!res.ok) throw new Error('Failed to load history');
      const scans = await res.json();

      if (!scans || scans.length === 0) {
        content.innerHTML = renderEmpty();
        return;
      }

      content.innerHTML = renderTable(scans);

      // Attach row click handlers
      document.querySelectorAll('[data-scan-id]').forEach(row => {
        row.addEventListener('click', () => {
          const scanId = row.getAttribute('data-scan-id');
          const status = row.getAttribute('data-status');
          if (status === 'complete') {
            window.location.hash = `#/report/${scanId}`;
          }
        });
      });
    } catch (err) {
      content.innerHTML = `<div style="padding:32px;text-align:center;"><div class="alert alert-error">${err.message}</div></div>`;
    }
  }

  function renderTable(scans) {
    const rows = scans.map(s => {
      const date = s.started_at ? formatDate(s.started_at) : '—';
      const duration = s.total_duration_seconds ? `${s.total_duration_seconds}s` : '—';
      const statusClass = `badge-${s.status || 'starting'}`;
      const statusText = (s.status || 'unknown').replace(/_/g, ' ');
      const modeClass = `badge-${s.zap_mode || 'quick'}`;
      const clickable = s.status === 'complete' ? 'style="cursor:pointer;"' : 'style="opacity:0.6;"';

      return `
        <tr data-scan-id="${s.scan_id}" data-status="${s.status}" ${clickable}>
          <td><span class="history-target">${escapeHtml(s.target || '—')}</span></td>
          <td><span class="badge ${modeClass}">${s.zap_mode || '—'}</span></td>
          <td><span class="badge ${statusClass}">${statusText}</span></td>
          <td><span class="history-date">${date}</span></td>
          <td><span class="history-duration">${duration}</span></td>
        </tr>
      `;
    }).join('');

    return `
      <table class="history-table">
        <thead>
          <tr>
            <th>Target</th>
            <th>Mode</th>
            <th>Status</th>
            <th>Date</th>
            <th>Duration</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  }

  function renderEmpty() {
    return `
      <div class="empty-state">
        <div class="empty-state-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <line x1="16" y1="13" x2="8" y2="13"/>
            <line x1="16" y1="17" x2="8" y2="17"/>
          </svg>
        </div>
        <h3>No Scans Yet</h3>
        <p>Launch your first vulnerability scan to see results here.</p>
      </div>
    `;
  }

  function formatDate(isoStr) {
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit',
      });
    } catch {
      return isoStr;
    }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  return { render };
})();
