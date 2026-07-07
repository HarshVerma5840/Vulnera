import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

// ── Attach JWT to every request ───────────────────────────────
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('vulnera_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ── Auth ──────────────────────────────────────────────────────
export interface AuthResponse {
  token: string;
  email: string;
  user_id: number;
}

export const authApi = {
  login: (email: string, password: string) =>
    api.post<AuthResponse>('/auth/login', { email, password }),

  register: (email: string, password: string) =>
    api.post<AuthResponse>('/auth/register', { email, password }),

  me: () => api.get<{ email: string; user_id: number }>('/auth/me'),
};

// ── Scan ──────────────────────────────────────────────────────
export interface ScanStartResponse {
  scan_id: string;
  status: string;
  message: string;
  target: string;
  zap_mode: string;
}

export interface ScanStatus {
  scan_id: string;
  target: string;
  zap_mode: string;
  status: string;
  current_action: string;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  results?: ScanResults;
}

export interface ScanResults {
  timing: {
    total_duration_seconds: number;
    nmap_duration_seconds: number;
    zap_duration_seconds: number;
  };
  nmap_results: NmapHost[];
  discovered_web_targets: string[];
  zap_reports: ZapReport[];
  alerts?: ScoredAlert[];
  report_file?: string;
}

export interface NmapHost {
  host: string;
  state: string;
  ports: {
    port: number;
    state: string;
    service: string;
    product: string;
    version: string;
  }[];
}

export interface ZapReport {
  target: string;
  success: boolean;
  data?: {
    alerts?: ZapAlert[];
    site_alerts?: ZapAlert[];
    raw_alerts?: unknown[];
  };
  error?: string;
}

export interface ZapAlert {
  alert?: string;
  name?: string;
  risk: string;
  description?: string;
  desc?: string;
  url?: string;
  confidence?: string;
  cweid?: string;
  wascid?: string;
  solution?: string;
  reference?: string;
}

export interface ScoredAlert extends ZapAlert {
  alert_id: string;
  source: string;
  path: string;
  cwe_id: string | null;
  composite_score: number;
  cvss_score: number | null;
  epss_score: number | null;
  endpoint_sensitivity: number;
  amplification_factor: number;
  plain_english?: {
    title: string;
    what: string;
    impact: string;
    fix: string;
  };
}

export interface ScanHistoryItem {
  scan_id: string;
  target: string;
  zap_mode: string;
  status: string;
  current_action: string;
  started_at: string | null;
  completed_at: string | null;
  total_duration_seconds: number | null;
  error: string | null;
}

export const scanApi = {
  start: (target: string, zapMode: string) =>
    api.post<ScanStartResponse>(
      `/vulnerascan?target=${encodeURIComponent(target)}&zap_mode=${encodeURIComponent(zapMode)}`
    ),

  status: (scanId: string) =>
    api.get<ScanStatus>(`/vulnerascan/${scanId}`),

  results: (scanId: string) =>
    api.get<ScanResults>(`/vulnerascan/${scanId}/results`),

  history: () =>
    api.get<ScanHistoryItem[]>('/scan-history'),

  downloadReport: (scanId: string) =>
    api.get(`/vulnerascan/${scanId}/report`, { responseType: 'blob' }),
};

// ── Feedback & Agent (Phase 4) ────────────────────────────────
export const feedbackApi = {
  submit: (alertId: string, verdict: 'TP' | 'FP', notes: string, appType: string, agentVerdict?: string) =>
    api.post('/feedback', { alert_id: alertId, verdict, notes, app_type: appType, agent_verdict: agentVerdict }),

  stats: () =>
    api.get('/feedback/stats'),

  learningCurve: () =>
    api.get('/feedback/learning-curve'),
};

export const agentApi = {
  reviewBatch: (scanId: string, appType: string) =>
    api.post(`/agent/review/${scanId}`, { app_type: appType }),

  reviewSingle: (alertId: string, appType: string) =>
    api.post('/agent/review-single', { alert_id: alertId, app_type: appType }),

  stats: () =>
    api.get('/agent/stats'),
    
  getAlerts: (scanId: string) =>
    api.get(`/alerts/${scanId}`),
};

export default api;
