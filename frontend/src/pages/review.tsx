import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Brain, ShieldAlert, CheckCircle, XCircle, 
  Loader2, Activity, Info, AlertTriangle, TrendingUp, Bot
} from 'lucide-react';
import { agentApi, feedbackApi } from '@/lib/api';
import { AppLayout } from '@/components/app-layout';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';

const RISK_CONFIG: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20' },
  HIGH: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
  MEDIUM: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
  LOW: { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
};

export default function ReviewPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [agentLoading, setAgentLoading] = useState(false);
  const [stats, setStats] = useState<any>(null);
  
  // Per-alert state
  const [agentReviews, setAgentReviews] = useState<Record<string, any>>({});
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (scanId) {
      loadData();
    }
  }, [scanId]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [alertsRes, statsRes] = await Promise.all([
        agentApi.getAlerts(scanId!),
        feedbackApi.stats()
      ]);
      setAlerts(alertsRes.data || []);
      setStats(statsRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleAgentReview = async () => {
    try {
      setAgentLoading(true);
      const res = await agentApi.reviewBatch(scanId!, "Web Application");
      setAgentReviews(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setAgentLoading(false);
    }
  };

  const handleSubmitVerdict = async (alertId: string, verdict: 'TP' | 'FP') => {
    try {
      setSubmitting({ ...submitting, [alertId]: true });
      const agentRes = agentReviews[alertId];
      
      const res = await feedbackApi.submit(
        alertId,
        verdict,
        notes[alertId] || '',
        "Web Application",
        agentRes?.suggested_verdict
      );
      
      // Update local state to hide the alert or mark it reviewed
      setAlerts(alerts.map(a => 
        a.alert_id === alertId ? { ...a, feedback_verdict: verdict } : a
      ));
      
      if (res.data.retrained) {
        // Refresh stats to show new model checkpoint
        const statsRes = await feedbackApi.stats();
        setStats(statsRes.data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSubmitting({ ...submitting, [alertId]: false });
    }
  };

  if (loading) {
    return (
      <AppLayout>
        <div className="flex items-center justify-center h-[50vh]">
          <Loader2 className="h-8 w-8 animate-spin text-[#3D5A80]" />
        </div>
      </AppLayout>
    );
  }

  const unreviewedAlerts = alerts.filter(a => !a.feedback_verdict);

  return (
    <AppLayout>
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex items-center gap-4">
          <Button variant="outline" size="icon" onClick={() => navigate(`/report/${scanId}`)}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Agentic Review</h1>
            <p className="text-muted-foreground">Train the AI by reviewing alerts from {scanId}</p>
          </div>
        </div>

        {/* Stats Panel */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
              <Activity className="h-4 w-4" /> Progress to Next Model
            </div>
            <div className="text-2xl font-bold font-mono">
              {stats?.model_status?.next_retrain_in || 0} <span className="text-sm font-sans text-muted-foreground font-normal">reviews needed</span>
            </div>
            <div className="w-full bg-secondary h-2 mt-2 rounded-full overflow-hidden">
              <div 
                className="bg-[#3D5A80] h-full transition-all" 
                style={{ width: `${((50 - (stats?.model_status?.next_retrain_in || 50)) / 50) * 100}%` }}
              />
            </div>
          </div>
          
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
              <Brain className="h-4 w-4" /> Model Status
            </div>
            <div className="text-2xl font-bold">
              {stats?.model_status?.is_trained ? 'Active' : 'Learning'}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {stats?.model_status?.latest_f1 
                ? `Latest F1 Score: ${(stats.model_status.latest_f1 * 100).toFixed(1)}%` 
                : 'Waiting for first 50 reviews to train'}
            </p>
          </div>
          
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
              <TrendingUp className="h-4 w-4" /> Your Contributions
            </div>
            <div className="text-2xl font-bold font-mono">
              {stats?.user_feedback_count || 0}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Total reviews submitted</p>
          </div>
        </div>

        {unreviewedAlerts.length === 0 ? (
          <div className="text-center py-12 bg-card border rounded-lg">
            <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
            <h2 className="text-xl font-bold">All caught up!</h2>
            <p className="text-muted-foreground">You have reviewed all alerts for this scan.</p>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold">{unreviewedAlerts.length} Alerts to Review</h2>
              <Button 
                onClick={handleAgentReview} 
                disabled={agentLoading}
                className="bg-indigo-600 hover:bg-indigo-700"
              >
                {agentLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Bot className="mr-2 h-4 w-4" />}
                Run Agent Review
              </Button>
            </div>

            {unreviewedAlerts.map(alert => {
              const risk = alert.risk_level || 'LOW';
              const config = RISK_CONFIG[risk] || RISK_CONFIG.LOW;
              const agentRes = agentReviews[alert.alert_id];

              return (
                <div key={alert.alert_id} className="border rounded-lg bg-card overflow-hidden">
                  <div className={`p-4 border-b ${config.bg} flex justify-between items-start`}>
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant="outline" className={`${config.color} ${config.border} bg-background`}>
                          {risk}
                        </Badge>
                        <span className="font-semibold text-lg">{alert.plain_english?.title || alert.type}</span>
                      </div>
                      <p className="text-sm text-muted-foreground font-mono">{alert.path}</p>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-mono font-bold">{(alert.risk_score * 10).toFixed(1)}</div>
                      <div className="text-xs text-muted-foreground">Risk Score</div>
                    </div>
                  </div>

                  <div className="p-4 space-y-4">
                    <p className="text-sm">{alert.plain_english?.what}</p>

                    {/* Agent Suggestion Box */}
                    {agentRes && (
                      <motion.div 
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className={`p-4 rounded-md border ${
                          agentRes.suggested_verdict === 'TP' 
                            ? 'bg-red-500/10 border-red-500/20' 
                            : 'bg-green-500/10 border-green-500/20'
                        }`}
                      >
                        <div className="flex items-center gap-2 mb-2 font-semibold">
                          <Bot className="h-5 w-5" />
                          Agent Suggests: {agentRes.suggested_verdict === 'TP' ? 'True Positive' : 'False Positive'} 
                          <span className="text-sm font-normal text-muted-foreground">
                            ({(agentRes.confidence * 100).toFixed(0)}% confidence)
                          </span>
                        </div>
                        <p className="text-sm italic text-muted-foreground">"{agentRes.reasoning}"</p>
                      </motion.div>
                    )}

                    {/* Verdict Controls */}
                    <div className="bg-secondary/50 p-4 rounded-md space-y-4 border">
                      <h4 className="text-sm font-medium">Your Verdict</h4>
                      <Textarea 
                        placeholder="Optional notes (e.g., 'WAF blocks this' or 'Internal endpoint only')"
                        value={notes[alert.alert_id] || ''}
                        onChange={(e) => setNotes({ ...notes, [alert.alert_id]: e.target.value })}
                        className="h-20 bg-background"
                      />
                      <div className="flex gap-4">
                        <Button 
                          onClick={() => handleSubmitVerdict(alert.alert_id, 'TP')}
                          disabled={submitting[alert.alert_id]}
                          className="flex-1 bg-red-600 hover:bg-red-700 text-white"
                        >
                          {submitting[alert.alert_id] ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="mr-2 h-4 w-4" />}
                          Confirm True Positive
                        </Button>
                        <Button 
                          onClick={() => handleSubmitVerdict(alert.alert_id, 'FP')}
                          disabled={submitting[alert.alert_id]}
                          className="flex-1 bg-green-600 hover:bg-green-700 text-white"
                        >
                          {submitting[alert.alert_id] ? <Loader2 className="h-4 w-4 animate-spin" /> : <XCircle className="mr-2 h-4 w-4" />}
                          Mark False Positive
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppLayout>
  );
}
