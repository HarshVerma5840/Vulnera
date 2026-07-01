import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Clock, Globe, FileText, Download, Loader2,
  Shield, AlertTriangle, Info, ChevronDown, ChevronUp, Zap,
  Server
} from 'lucide-react';
import { scanApi, type ScanStatus, type ScanResults, type ZapAlert, type ScoredAlert } from '@/lib/api';
import { AppLayout } from '@/components/app-layout';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

// ── Helpers ──────────────────────────────────────────────────
function formatDuration(seconds: number | null | undefined): string {
  if (!seconds && seconds !== 0) return '—';
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return sec > 0 ? `${h}h ${m}m ${sec}s` : `${h}h ${m}m`;
  return sec > 0 ? `${m}m ${sec}s` : `${m}m`;
}

function formatDateTime(isoStr: string | null): string {
  if (!isoStr) return '—';
  try {
    let str = isoStr;
    if (!str.endsWith('Z') && !str.includes('+')) str += 'Z';
    const d = new Date(str);
    return d.toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
    }) + ' at ' + d.toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true,
    });
  } catch {
    return isoStr;
  }
}

const RISK_CONFIG: Record<string, { color: string; bg: string; border: string; variant: "danger" | "warning" | "info" | "secondary" }> = {
  High: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', variant: 'danger' },
  Medium: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', variant: 'warning' },
  Low: { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20', variant: 'info' },
  Informational: { color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/20', variant: 'secondary' },
};

// ── Alert Card Component ─────────────────────────────────────
function AlertCard({ alert }: { alert: ZapAlert | ScoredAlert }) {
  const [expanded, setExpanded] = useState(false);
  const risk = alert.risk || 'Informational';
  const config = RISK_CONFIG[risk] || RISK_CONFIG.Informational;
  const desc = alert.description || alert.desc || '';
  const scored = alert as ScoredAlert;
  const hasAI = 'composite_score' in scored;

  return (
    <div className={`rounded-lg border ${config.border} ${config.bg} p-4 transition-all`}>
      <div
        className="flex items-start justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-medium text-foreground">
              {alert.alert || alert.name || 'Unknown Alert'}
            </span>
            <Badge variant={config.variant} className="text-[10px]">{risk}</Badge>
            {hasAI && scored.composite_score > 0 && (
              <span className="text-[10px] font-mono text-primary bg-primary/10 px-1.5 py-0.5 rounded">
                Score: {scored.composite_score.toFixed(1)}
              </span>
            )}
          </div>
          {!expanded && desc && (
            <p className="text-xs text-muted-foreground line-clamp-1">{desc}</p>
          )}
        </div>
        {expanded ? <ChevronUp className="h-4 w-4 text-muted-foreground shrink-0" /> : <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0" />}
      </div>

      {expanded && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="mt-3 space-y-3"
        >
          {desc && <p className="text-xs text-muted-foreground">{desc}</p>}

          {alert.url && (
            <div className="text-xs font-mono text-primary/80 break-all">{alert.url}</div>
          )}

          {/* AI enrichment data */}
          {hasAI && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {scored.cvss_score !== null && scored.cvss_score !== undefined && (
                <div className="text-center p-2 rounded bg-background/50 border border-border/50">
                  <div className="text-[10px] text-muted-foreground">CVSS</div>
                  <div className="text-sm font-bold text-foreground">{scored.cvss_score.toFixed(1)}</div>
                </div>
              )}
              {scored.epss_score !== null && scored.epss_score !== undefined && (
                <div className="text-center p-2 rounded bg-background/50 border border-border/50">
                  <div className="text-[10px] text-muted-foreground">EPSS</div>
                  <div className="text-sm font-bold text-foreground">{(scored.epss_score * 100).toFixed(1)}%</div>
                </div>
              )}
              {scored.endpoint_sensitivity > 0 && (
                <div className="text-center p-2 rounded bg-background/50 border border-border/50">
                  <div className="text-[10px] text-muted-foreground">Endpoint</div>
                  <div className="text-sm font-bold text-foreground">{scored.endpoint_sensitivity.toFixed(2)}</div>
                </div>
              )}
              {scored.amplification_factor > 1 && (
                <div className="text-center p-2 rounded bg-background/50 border border-border/50">
                  <div className="text-[10px] text-muted-foreground">Amplifier</div>
                  <div className="text-sm font-bold text-foreground">{scored.amplification_factor.toFixed(2)}x</div>
                </div>
              )}
            </div>
          )}

          {/* Plain English explanation */}
          {hasAI && scored.plain_english && (
            <div className="p-3 rounded-md bg-primary/5 border border-primary/15">
              <div className="flex items-center gap-1.5 mb-1.5">
                <Zap className="h-3 w-3 text-primary" />
                <span className="text-[11px] font-medium text-primary">AI Explanation</span>
              </div>
              <p className="text-xs text-muted-foreground">{scored.plain_english.what}</p>
              {scored.plain_english.impact && (
                <p className="text-xs text-muted-foreground mt-1">
                  <strong className="text-foreground">Impact:</strong> {scored.plain_english.impact}
                </p>
              )}
              {scored.plain_english.fix && (
                <p className="text-xs text-muted-foreground mt-1">
                  <strong className="text-foreground">Fix:</strong> {scored.plain_english.fix}
                </p>
              )}
            </div>
          )}

          {alert.solution && (
            <div className="text-xs text-muted-foreground">
              <strong className="text-foreground">Solution:</strong> {alert.solution}
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
}

// ── Main Report Page ─────────────────────────────────────────
export default function ReportPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [meta, setMeta] = useState<ScanStatus | null>(null);
  const [report, setReport] = useState<ScanResults | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!scanId) return;

    const loadReport = async () => {
      try {
        const statusRes = await scanApi.status(scanId);
        setMeta(statusRes.data);

        if (statusRes.data.status !== 'complete') {
          setError(`Scan is not yet complete. Status: ${statusRes.data.status}`);
          return;
        }

        const resultsRes = await scanApi.results(scanId);
        setReport(resultsRes.data);
      } catch {
        setError('Failed to load report');
      } finally {
        setLoading(false);
      }
    };

    loadReport();
  }, [scanId]);

  // Count alerts by risk
  const alertCounts = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  const allAlerts: (ZapAlert & { source_target?: string })[] = [];

  // Use AI-scored alerts if available, otherwise fall back to raw ZAP alerts
  if (report?.alerts && report.alerts.length > 0) {
    report.alerts.forEach((a) => {
      const risk = a.risk || 'Informational';
      if (risk in alertCounts) alertCounts[risk as keyof typeof alertCounts]++;
      allAlerts.push(a);
    });
  } else if (report?.zap_reports) {
    report.zap_reports.forEach((zr) => {
      if (zr.success && zr.data) {
        const alerts = zr.data.alerts || zr.data.site_alerts || [];
        alerts.forEach((a) => {
          const risk = a.risk || 'Informational';
          if (risk in alertCounts) alertCounts[risk as keyof typeof alertCounts]++;
          allAlerts.push({ ...a, source_target: zr.target });
        });
      }
    });
  }

  // Sort: High → Medium → Low → Info
  const riskOrder: Record<string, number> = { High: 0, Medium: 1, Low: 2, Informational: 3 };
  allAlerts.sort((a, b) => (riskOrder[a.risk] ?? 3) - (riskOrder[b.risk] ?? 3));

  const handleDownloadJson = () => {
    if (!report) return;
    const data = {
      scan_info: {
        scan_id: meta?.scan_id || scanId,
        target: meta?.target || '',
        zap_mode: meta?.zap_mode || '',
        status: meta?.status || '',
        started_at: meta?.started_at || null,
        completed_at: meta?.completed_at || null,
      },
      timing: report.timing || {},
      nmap_results: report.nmap_results || [],
      discovered_web_targets: report.discovered_web_targets || [],
      zap_reports: report.zap_reports || [],
      alerts: report.alerts || [],
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${scanId}_report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPdf = async () => {
    if (!scanId) return;
    try {
      const res = await scanApi.downloadReport(scanId);
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnera_${scanId}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // silently fail
    }
  };

  if (loading) {
    return (
      <AppLayout>
        <div className="flex items-center justify-center py-24">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        {/* Back button */}
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate('/history')}
          className="mb-4 text-muted-foreground"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to History
        </Button>

        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-foreground">Scan Report</h1>
          <p className="text-muted-foreground mt-1">
            {meta ? `${meta.target} — ${(meta.zap_mode || 'quick').toUpperCase()} mode` : 'Loading...'}
          </p>
        </div>

        {error && (
          <div className="glass-card p-6 mb-6">
            <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
              {error}
            </div>
          </div>
        )}

        {report && (
          <>
            {/* Scan Info */}
            <div className="glass-card p-6 mb-6">
              <h3 className="text-base font-semibold text-foreground mb-4 flex items-center gap-2">
                <Info className="h-4 w-4 text-primary" />
                Scan Information
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-muted-foreground">Scan ID:</span>{' '}
                  <span className="font-mono text-foreground">{meta?.scan_id}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Target:</span>{' '}
                  <span className="text-foreground">{meta?.target}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Started:</span>{' '}
                  <span className="text-foreground">{formatDateTime(meta?.started_at || null)}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Completed:</span>{' '}
                  <span className="text-foreground">{formatDateTime(meta?.completed_at || null)}</span>
                </div>
              </div>
            </div>

            {/* Timing Stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
              <div className="glass-card p-4 text-center">
                <div className="text-xs text-muted-foreground mb-1">Total Time</div>
                <div className="text-lg font-bold text-cyan-400 flex items-center justify-center gap-1">
                  <Clock className="h-4 w-4" />
                  {formatDuration(report.timing?.total_duration_seconds)}
                </div>
              </div>
              <div className="glass-card p-4 text-center">
                <div className="text-xs text-muted-foreground mb-1">Nmap Phase</div>
                <div className="text-lg font-bold text-emerald-400 flex items-center justify-center gap-1">
                  <Server className="h-4 w-4" />
                  {formatDuration(report.timing?.nmap_duration_seconds)}
                </div>
              </div>
              <div className="glass-card p-4 text-center">
                <div className="text-xs text-muted-foreground mb-1">ZAP Phase</div>
                <div className="text-lg font-bold text-amber-400 flex items-center justify-center gap-1">
                  <Shield className="h-4 w-4" />
                  {formatDuration(report.timing?.zap_duration_seconds)}
                </div>
              </div>
              <div className="glass-card p-4 text-center">
                <div className="text-xs text-muted-foreground mb-1">Web Targets</div>
                <div className="text-lg font-bold text-cyan-400 flex items-center justify-center gap-1">
                  <Globe className="h-4 w-4" />
                  {report.discovered_web_targets?.length || 0}
                </div>
              </div>
            </div>

            {/* Vulnerability Summary */}
            <div className="glass-card p-6 mb-6">
              <h3 className="text-base font-semibold text-foreground mb-4 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                Vulnerability Summary
              </h3>
              <div className="grid grid-cols-4 gap-4">
                {Object.entries(alertCounts).map(([risk, count]) => {
                  const config = RISK_CONFIG[risk] || RISK_CONFIG.Informational;
                  return (
                    <div key={risk} className={`text-center p-3 rounded-lg ${config.bg} border ${config.border}`}>
                      <div className={`text-xs ${config.color} mb-1`}>{risk}</div>
                      <div className={`text-2xl font-bold ${config.color}`}>{count}</div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Findings List */}
            {allAlerts.length > 0 && (
              <div className="glass-card p-6 mb-6">
                <h3 className="text-base font-semibold text-foreground mb-4">
                  Findings ({allAlerts.length})
                </h3>
                <div className="space-y-3">
                  {allAlerts.map((alert, i) => (
                    <AlertCard key={i} alert={alert} />
                  ))}
                </div>
              </div>
            )}

            {/* Nmap Results */}
            {report.nmap_results && report.nmap_results.length > 0 && (
              <div className="glass-card p-6 mb-6">
                <h3 className="text-base font-semibold text-foreground mb-4 flex items-center gap-2">
                  <Server className="h-4 w-4 text-emerald-400" />
                  Nmap Port Scan Results
                </h3>
                {report.nmap_results.map((host, hi) => (
                  <div key={hi} className="mb-4">
                    <div className="flex items-center gap-2 mb-3">
                      <span className="font-mono text-sm font-semibold text-foreground">{host.host}</span>
                      <span className={`text-xs font-semibold uppercase ${host.state === 'up' ? 'text-emerald-400' : 'text-red-400'}`}>
                        ● {host.state}
                      </span>
                    </div>
                    {host.ports && host.ports.length > 0 ? (
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-border/50">
                              <th className="text-left text-xs font-medium text-muted-foreground uppercase px-3 py-2">Port</th>
                              <th className="text-left text-xs font-medium text-muted-foreground uppercase px-3 py-2">State</th>
                              <th className="text-left text-xs font-medium text-muted-foreground uppercase px-3 py-2">Service</th>
                              <th className="text-left text-xs font-medium text-muted-foreground uppercase px-3 py-2">Product</th>
                              <th className="text-left text-xs font-medium text-muted-foreground uppercase px-3 py-2">Version</th>
                            </tr>
                          </thead>
                          <tbody>
                            {host.ports.map((p, pi) => (
                              <tr key={pi} className="border-b border-border/20">
                                <td className="px-3 py-2 font-mono font-semibold text-primary">{p.port}</td>
                                <td className="px-3 py-2">
                                  <span className={`inline-flex items-center gap-1 ${p.state === 'open' ? 'text-emerald-400' : 'text-red-400'}`}>
                                    <span className={`w-1.5 h-1.5 rounded-full ${p.state === 'open' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                                    {p.state}
                                  </span>
                                </td>
                                <td className="px-3 py-2 text-foreground">{p.service || '—'}</td>
                                <td className="px-3 py-2 text-foreground">{p.product || '—'}</td>
                                <td className="px-3 py-2 font-mono text-muted-foreground">{p.version || '—'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">No ports discovered</p>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Download Buttons */}
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <Button variant="outline" onClick={handleDownloadJson}>
                <Download className="h-4 w-4" />
                Download JSON Report
              </Button>
              <Button onClick={handleDownloadPdf}>
                <FileText className="h-4 w-4" />
                Download PDF Report
              </Button>
            </div>
          </>
        )}
      </motion.div>
    </AppLayout>
  );
}
