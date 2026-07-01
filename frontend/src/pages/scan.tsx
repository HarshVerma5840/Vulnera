import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Loader2, Clock, Globe, FileText, CheckCircle2, XCircle, Zap } from 'lucide-react';
import { scanApi, type ScanStatus } from '@/lib/api';
import { AppLayout } from '@/components/app-layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';

const STATUS_BADGE_VARIANT: Record<string, "default" | "success" | "warning" | "danger" | "info" | "secondary"> = {
  starting: 'info',
  nmap_scanning: 'warning',
  zap_scanning: 'warning',
  enriching: 'info',
  complete: 'success',
  failed: 'danger',
};

export default function ScanPage() {
  const navigate = useNavigate();
  const [target, setTarget] = useState('http://demo.testfire.net');
  const [mode, setMode] = useState('quick');
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [error, setError] = useState('');
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => stopPolling();
  }, [stopPolling]);

  const pollStatus = useCallback(async (id: string) => {
    try {
      const res = await scanApi.status(id);
      setStatus(res.data);

      if (res.data.status === 'complete' || res.data.status === 'failed') {
        stopPolling();
        setScanning(false);
      }
    } catch {
      // silently retry
    }
  }, [stopPolling]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setScanning(true);
    setStatus(null);

    try {
      const res = await scanApi.start(target.trim(), mode);
      const id = res.data.scan_id;
      setScanId(id);
      setStatus({
        scan_id: id,
        target: target.trim(),
        zap_mode: mode,
        status: 'starting',
        current_action: 'Initializing backend processes...',
        started_at: new Date().toISOString(),
        completed_at: null,
        error: null,
      });

      pollRef.current = setInterval(() => pollStatus(id), 2500);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Failed to start scan';
      setError(msg);
      setScanning(false);
    }
  };

  const isComplete = status?.status === 'complete';
  const isFailed = status?.status === 'failed';
  const isRunning = scanning && !isComplete && !isFailed;

  return (
    <AppLayout>
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        {/* Page header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-foreground">Launch Scan</h1>
          <p className="text-muted-foreground mt-1">
            Run a unified Nmap + OWASP ZAP vulnerability scan
          </p>
        </div>

        {/* Scan Form */}
        <div className="glass-card p-6 mb-6">
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="target">Target URL / IP</Label>
              <Input
                id="target"
                type="text"
                placeholder="e.g. https://example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required
                disabled={isRunning}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="mode">Scan Mode</Label>
              <select
                id="mode"
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                disabled={isRunning}
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
              >
                <option value="quick">Quick — Top vulnerabilities, depth 3</option>
                <option value="full">Full — All plugins, depth 5, deep rescan</option>
              </select>
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground mt-1">
                <Clock className="h-3 w-3" />
                {mode === 'quick' ? 'Quick ≈ 2-5 min' : 'Full ≈ 10-30 min'}
              </div>
            </div>

            {error && (
              <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                {error}
              </div>
            )}

            <Button type="submit" size="lg" className="w-full" disabled={isRunning}>
              {isRunning ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Search className="h-4 w-4" />
              )}
              {isRunning ? 'Scanning...' : 'Launch Scan'}
            </Button>
          </form>
        </div>

        {/* Progress Card */}
        <AnimatePresence>
          {status && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              className={`glass-card p-6 mb-6 ${isFailed ? 'border-red-500/30' : isComplete ? 'border-emerald-500/30' : ''}`}
            >
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-foreground">Scan Progress</h2>
                <Badge variant={STATUS_BADGE_VARIANT[status.status] || 'secondary'}>
                  {status.status.replace(/_/g, ' ')}
                </Badge>
              </div>

              <div className="flex items-center gap-3 mb-3">
                {isRunning && <Loader2 className="h-5 w-5 animate-spin text-primary" />}
                {isComplete && <CheckCircle2 className="h-5 w-5 text-emerald-400" />}
                {isFailed && <XCircle className="h-5 w-5 text-red-400" />}
                <span className="text-sm text-muted-foreground">
                  {status.current_action || 'Processing...'}
                </span>
              </div>

              <div className="text-xs text-muted-foreground">
                Scan ID: <code className="text-primary/80">{scanId}</code>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Results Card */}
        <AnimatePresence>
          {isComplete && status?.results && (
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass-card p-6"
            >
              <h2 className="text-lg font-semibold text-foreground mb-1">Scan Complete</h2>
              <p className="text-sm text-muted-foreground mb-5">Results are ready to review</p>

              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="text-center p-4 rounded-lg bg-background/50 border border-border/50">
                  <div className="text-xs text-muted-foreground mb-1">Duration</div>
                  <div className="text-xl font-bold text-cyan-400 flex items-center justify-center gap-1">
                    <Clock className="h-4 w-4" />
                    {status.results.timing?.total_duration_seconds
                      ? `${Math.round(status.results.timing.total_duration_seconds)}s`
                      : '—'}
                  </div>
                </div>
                <div className="text-center p-4 rounded-lg bg-background/50 border border-border/50">
                  <div className="text-xs text-muted-foreground mb-1">Web Targets</div>
                  <div className="text-xl font-bold text-emerald-400 flex items-center justify-center gap-1">
                    <Globe className="h-4 w-4" />
                    {status.results.discovered_web_targets?.length || 0}
                  </div>
                </div>
                <div className="text-center p-4 rounded-lg bg-background/50 border border-border/50">
                  <div className="text-xs text-muted-foreground mb-1">ZAP Reports</div>
                  <div className="text-xl font-bold text-amber-400 flex items-center justify-center gap-1">
                    <FileText className="h-4 w-4" />
                    {status.results.zap_reports?.length || 0}
                  </div>
                </div>
              </div>

              {/* AI Alerts Summary */}
              {status.results.alerts && status.results.alerts.length > 0 && (
                <div className="mb-5 p-4 rounded-lg bg-primary/5 border border-primary/20">
                  <div className="flex items-center gap-2 mb-2">
                    <Zap className="h-4 w-4 text-primary" />
                    <span className="text-sm font-medium text-foreground">AI Intelligence Analysis</span>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {status.results.alerts.length} vulnerabilities scored with CVSS, EPSS, and endpoint criticality analysis.
                  </p>
                </div>
              )}

              <Button
                className="w-full"
                size="lg"
                onClick={() => navigate(`/report/${scanId}`)}
              >
                View Full Report
              </Button>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </AppLayout>
  );
}
