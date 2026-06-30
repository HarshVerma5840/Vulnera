/* ============================================================================
   REPORT MODULE — Detailed scan report view
   ============================================================================ */

const Report = (() => {

  // Store report data for download
  let _currentReport = null;
  let _currentMeta = null;

  function render(container, scanId) {
    _currentReport = null;
    _currentMeta = null;

    container.innerHTML = `
      <div class="page-enter">
        <button class="report-back" onclick="window.location.hash='#/history'">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
          Back to History
        </button>
        <div class="page-header">
          <h1>Scan Report</h1>
          <p id="reportSubtitle">Loading report data...</p>
        </div>
        <div id="reportContent">
          <div class="card" style="text-align:center;padding:40px;color:var(--text-muted);">
            <div class="spinner" style="margin:0 auto 16px;"></div>
            Fetching report...
          </div>
        </div>
      </div>
    `;

    loadReport(scanId);
  }

  async function loadReport(scanId) {
    const content = document.getElementById('reportContent');
    const subtitle = document.getElementById('reportSubtitle');

    try {
      // First get scan metadata
      const statusRes = await fetch(`/api/vulnerascan/${scanId}`);
      if (!statusRes.ok) throw new Error('Scan not found');
      const meta = await statusRes.json();
      _currentMeta = meta;

      subtitle.textContent = `${meta.target} — ${(meta.zap_mode || 'quick').toUpperCase()} mode`;

      if (meta.status !== 'complete') {
        content.innerHTML = `
          <div class="card">
            <div class="alert alert-error">
              This scan is not yet complete. Current status: <strong>${(meta.status || '').replace(/_/g, ' ')}</strong>
            </div>
            <p style="color:var(--text-muted);font-size:14px;">${meta.current_action || ''}</p>
          </div>
        `;
        return;
      }

      // Fetch full results
      const resultsRes = await fetch(`/api/vulnerascan/${scanId}/results`);
      if (!resultsRes.ok) throw new Error('Could not load report results');
      const report = await resultsRes.json();
      _currentReport = report;

      content.innerHTML = renderReport(meta, report);

      // Attach download button handler
      const dlBtn = document.getElementById('downloadJsonBtn');
      if (dlBtn) {
        dlBtn.addEventListener('click', (e) => {
          e.preventDefault();
          downloadFormattedJson(meta.scan_id);
        });
      }
    } catch (err) {
      content.innerHTML = `
        <div class="card">
          <div class="alert alert-error">${err.message}</div>
        </div>
      `;
    }
  }

  // ── Time formatting helpers ─────────────────────────────────
  function formatDuration(totalSeconds) {
    if (!totalSeconds && totalSeconds !== 0) return '—';
    const s = Math.round(totalSeconds);
    if (s < 60) return `${s}s`;
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h > 0) {
      return sec > 0 ? `${h}h ${m}m ${sec}s` : `${h}h ${m}m`;
    }
    return sec > 0 ? `${m}m ${sec}s` : `${m}m`;
  }

  function formatDurationMinutes(totalSeconds) {
    if (!totalSeconds && totalSeconds !== 0) return '—';
    const mins = (totalSeconds / 60).toFixed(1);
    return `${mins} min`;
  }

  function formatDateTime(isoStr) {
    if (!isoStr) return '—';
    try {
      // Backend stores UTC but omits the Z suffix — add it so JS converts to local time
      let str = isoStr;
      if (!str.endsWith('Z') && !str.includes('+') && !/\d{2}:\d{2}$/.test(str.slice(-6))) {
        str += 'Z';
      }
      const d = new Date(str);
      return d.toLocaleDateString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
      }) + ' at ' + d.toLocaleTimeString('en-US', {
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: true,
      });
    } catch { return isoStr; }
  }

  // ── Main report renderer ────────────────────────────────────
  function renderReport(meta, report) {
    const timing = report.timing || {};
    const nmap = report.nmap_results || [];
    const webTargets = report.discovered_web_targets || [];
    const zapReports = report.zap_reports || [];

    // Count ZAP alerts by risk
    let alertCounts = { High: 0, Medium: 0, Low: 0, Informational: 0 };
    let allAlerts = [];

    zapReports.forEach(zr => {
      if (zr.success && zr.data) {
        const alerts = zr.data.alerts || zr.data.site_alerts || [];
        alerts.forEach(a => {
          const risk = a.risk || 'Informational';
          if (alertCounts[risk] !== undefined) alertCounts[risk]++;
          allAlerts.push({ ...a, source_target: zr.target });
        });
      }
    });

    // Sort alerts: High → Medium → Low → Info
    const riskOrder = { 'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3 };
    allAlerts.sort((a, b) => (riskOrder[a.risk] || 3) - (riskOrder[b.risk] || 3));

    return `
      <!-- Scan Info -->
      <div class="card" style="margin-bottom:20px;">
        <h3 style="font-size:16px;font-weight:600;margin-bottom:16px;">Scan Information</h3>
        <div class="report-meta">
          <div class="report-meta-item">
            <span class="report-meta-label">Scan ID:</span>
            <span class="report-meta-value">${meta.scan_id}</span>
          </div>
          <div class="report-meta-item">
            <span class="report-meta-label">Target:</span>
            <span class="report-meta-value">${escapeHtml(meta.target)}</span>
          </div>
          <div class="report-meta-item">
            <span class="report-meta-label">Mode:</span>
            <span class="badge badge-${meta.zap_mode || 'quick'}">${meta.zap_mode || 'quick'}</span>
          </div>
        </div>
        <div class="report-meta" style="margin-top:12px;">
          <div class="report-meta-item">
            <span class="report-meta-label">Scan Started:</span>
            <span class="report-meta-value">${formatDateTime(meta.started_at)}</span>
          </div>
          <div class="report-meta-item">
            <span class="report-meta-label">Scan Ended:</span>
            <span class="report-meta-value">${formatDateTime(meta.completed_at)}</span>
          </div>
        </div>
      </div>

      <!-- Timing Stats -->
      <div class="results-grid" style="margin-bottom:20px;">
        <div class="result-stat">
          <div class="result-stat-label">Total Time</div>
          <div class="result-stat-value cyan">${formatDuration(timing.total_duration_seconds)}</div>
          <div class="result-stat-sub">${formatDurationMinutes(timing.total_duration_seconds)}</div>
        </div>
        <div class="result-stat">
          <div class="result-stat-label">Nmap Phase</div>
          <div class="result-stat-value emerald">${formatDuration(timing.nmap_duration_seconds)}</div>
          <div class="result-stat-sub">${formatDurationMinutes(timing.nmap_duration_seconds)}</div>
        </div>
        <div class="result-stat">
          <div class="result-stat-label">ZAP Phase</div>
          <div class="result-stat-value amber">${formatDuration(timing.zap_duration_seconds)}</div>
          <div class="result-stat-sub">${formatDurationMinutes(timing.zap_duration_seconds)}</div>
        </div>
        <div class="result-stat">
          <div class="result-stat-label">Web Targets</div>
          <div class="result-stat-value cyan">${webTargets.length}</div>
        </div>
      </div>

      <!-- Alert Summary -->
      <div class="card" style="margin-bottom:20px;">
        <h3 style="font-size:16px;font-weight:600;margin-bottom:16px;">Vulnerability Summary</h3>
        <div class="results-grid">
          <div class="result-stat">
            <div class="result-stat-label" style="color:var(--red);">High Risk</div>
            <div class="result-stat-value" style="color:var(--red);">${alertCounts.High}</div>
          </div>
          <div class="result-stat">
            <div class="result-stat-label" style="color:var(--amber);">Medium Risk</div>
            <div class="result-stat-value" style="color:var(--amber);">${alertCounts.Medium}</div>
          </div>
          <div class="result-stat">
            <div class="result-stat-label" style="color:var(--accent);">Low Risk</div>
            <div class="result-stat-value" style="color:var(--accent);">${alertCounts.Low}</div>
          </div>
          <div class="result-stat">
            <div class="result-stat-label">Informational</div>
            <div class="result-stat-value">${alertCounts.Informational}</div>
          </div>
        </div>
      </div>

      <!-- Vulnerability List -->
      ${allAlerts.length > 0 ? `
        <div class="card" style="margin-bottom:20px;">
          <h3 style="font-size:16px;font-weight:600;margin-bottom:16px;">Findings (${allAlerts.length})</h3>
          <div class="vuln-list">
            ${allAlerts.map(a => renderAlertCard(a)).join('')}
          </div>
        </div>
      ` : ''}

      <!-- Nmap Results — Proper Table -->
      ${nmap && nmap.length > 0 ? renderNmapSection(nmap) : ''}

      <!-- Download Full JSON Report -->
      <div style="text-align:center;margin-top:8px;">
        <button class="btn btn-secondary" id="downloadJsonBtn">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Download Full JSON Report
        </button>
      </div>
    `;
  }

  // ── Nmap Results Table ──────────────────────────────────────
  function renderNmapSection(nmapData) {
    let hostsHtml = '';

    nmapData.forEach(host => {
      const hostIp = escapeHtml(host.host || '—');
      const hostState = host.state || 'unknown';
      const ports = host.ports || [];

      const stateColor = hostState === 'up' ? 'var(--emerald)' : 'var(--red)';

      let portsRows = '';
      ports.forEach(p => {
        const portStateClass = p.state === 'open' ? 'nmap-open' : 'nmap-closed';
        const portStateDot = p.state === 'open'
          ? '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--emerald);margin-right:6px;"></span>'
          : '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--red);margin-right:6px;"></span>';

        portsRows += `
          <tr>
            <td style="font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--accent);">${p.port || '—'}</td>
            <td>${portStateDot}${escapeHtml(p.state || '—')}</td>
            <td>${escapeHtml(p.service || '—')}</td>
            <td>${escapeHtml(p.product || '—')}</td>
            <td style="font-family:'JetBrains Mono',monospace;">${escapeHtml(p.version || '—')}</td>
          </tr>
        `;
      });

      hostsHtml += `
        <div style="margin-bottom:16px;">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
            <span style="font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:600;color:var(--text-primary);">${hostIp}</span>
            <span style="font-size:12px;color:${stateColor};font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">● ${hostState}</span>
          </div>
          ${ports.length > 0 ? `
            <div style="overflow-x:auto;">
              <table class="history-table nmap-table">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                  </tr>
                </thead>
                <tbody>${portsRows}</tbody>
              </table>
            </div>
          ` : '<p style="color:var(--text-muted);font-size:14px;">No ports discovered</p>'}
        </div>
      `;
    });

    return `
      <div class="card" style="margin-bottom:20px;">
        <h3 style="font-size:16px;font-weight:600;margin-bottom:16px;">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--emerald)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:6px;"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
          Nmap Port Scan Results
        </h3>
        ${hostsHtml}
      </div>
    `;
  }

  // ── Vulnerability card ──────────────────────────────────────
  function renderAlertCard(alert) {
    const riskClass = {
      'High': 'risk-high',
      'Medium': 'risk-medium',
      'Low': 'risk-low',
      'Informational': 'risk-info',
    }[alert.risk] || 'risk-info';

    const desc = alert.description || alert.desc || '';
    const truncDesc = desc.length > 200 ? desc.substring(0, 200) + '...' : desc;

    return `
      <div class="vuln-item">
        <div class="vuln-item-header">
          <span class="vuln-item-name">${escapeHtml(alert.alert || alert.name || 'Unknown')}</span>
          <span class="badge badge-${(alert.risk || '').toLowerCase() === 'high' ? 'failed' : (alert.risk || '').toLowerCase() === 'medium' ? 'starting' : 'complete'}">
            <span class="${riskClass}">${alert.risk || 'Info'}</span>
          </span>
        </div>
        <div class="vuln-item-detail">${escapeHtml(truncDesc)}</div>
        ${alert.url ? `<div class="vuln-item-detail" style="margin-top:6px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent);">${escapeHtml(alert.url)}</div>` : ''}
      </div>
    `;
  }

  // ── Download properly formatted JSON ────────────────────────
  function downloadFormattedJson(scanId) {
    if (!_currentReport) return;

    // Build a clean structured report object
    const exportData = {
      scan_info: {
        scan_id: _currentMeta?.scan_id || scanId,
        target: _currentMeta?.target || '',
        zap_mode: _currentMeta?.zap_mode || '',
        status: _currentMeta?.status || '',
        started_at: _currentMeta?.started_at || null,
        completed_at: _currentMeta?.completed_at || null,
      },
      timing: _currentReport.timing || {},
      nmap_results: _currentReport.nmap_results || [],
      discovered_web_targets: _currentReport.discovered_web_targets || [],
      zap_reports: _currentReport.zap_reports || [],
    };

    const jsonStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `${scanId}_report.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── Utilities ───────────────────────────────────────────────
  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  return { render };
})();
