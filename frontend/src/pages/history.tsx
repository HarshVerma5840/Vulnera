import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Clock, FileText, Loader2 } from 'lucide-react';
import { scanApi, type ScanHistoryItem } from '@/lib/api';
import { AppLayout } from '@/components/app-layout';
import { Badge } from '@/components/ui/badge';

const STATUS_VARIANT: Record<string, "success" | "warning" | "danger" | "info" | "secondary"> = {
  complete: 'success',
  failed: 'danger',
  starting: 'info',
  nmap_scanning: 'warning',
  zap_scanning: 'warning',
  enriching: 'info',
};

function formatDate(isoStr: string | null): string {
  if (!isoStr) return '—';
  try {
    const d = new Date(isoStr.endsWith('Z') ? isoStr : isoStr + 'Z');
    return d.toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return isoStr;
  }
}

export default function HistoryPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    scanApi.history()
      .then((res) => setScans(res.data))
      .catch(() => setError('Failed to load scan history'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <AppLayout>
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-foreground">Scan History</h1>
          <p className="text-muted-foreground mt-1">Review your past vulnerability scans</p>
        </div>

        <div className="glass-card overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
          ) : error ? (
            <div className="p-8 text-center">
              <div className="p-3 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                {error}
              </div>
            </div>
          ) : scans.length === 0 ? (
            <div className="py-16 text-center">
              <FileText className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-foreground mb-1">No Scans Yet</h3>
              <p className="text-sm text-muted-foreground">
                Launch your first vulnerability scan to see results here.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border/50">
                    <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-6 py-3">Target</th>
                    <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Mode</th>
                    <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Status</th>
                    <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Date</th>
                    <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider px-4 py-3">Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan) => (
                    <tr
                      key={scan.scan_id}
                      onClick={() => scan.status === 'complete' && navigate(`/report/${scan.scan_id}`)}
                      className={`border-b border-border/30 transition-colors ${
                        scan.status === 'complete'
                          ? 'hover:bg-accent/50 cursor-pointer'
                          : 'opacity-60'
                      }`}
                    >
                      <td className="px-6 py-4">
                        <span className="text-sm font-medium text-foreground">{scan.target}</span>
                      </td>
                      <td className="px-4 py-4">
                        <Badge variant="secondary" className="text-xs">
                          {scan.zap_mode}
                        </Badge>
                      </td>
                      <td className="px-4 py-4">
                        <Badge variant={STATUS_VARIANT[scan.status] || 'secondary'}>
                          {scan.status.replace(/_/g, ' ')}
                        </Badge>
                      </td>
                      <td className="px-4 py-4">
                        <span className="text-sm text-muted-foreground flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {formatDate(scan.started_at)}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <span className="text-sm text-muted-foreground font-mono">
                          {scan.total_duration_seconds ? `${scan.total_duration_seconds}s` : '—'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </motion.div>
    </AppLayout>
  );
}
