export type Verdict = 'safe' | 'suspicious' | 'malicious';
export type Confidence = 'low' | 'medium' | 'high';

export interface AnalysisResponse {
  scan_id: number;
  normalized_url: string;
  domain: string;
  final_url: string | null;
  redirect_hops: number;
  risk_score: number;
  verdict: Verdict;
  confidence: Confidence;
  reasons: string[];
  signals: Record<string, unknown>;
  breakdown: { key: string; points: number; description: string }[];
  reputation?: string;
}

export interface ScanSummary {
  id: number;
  created_at: string;
  normalized_url: string;
  domain: string;
  final_url: string | null;
  risk_score: number;
  verdict: Verdict;
  confidence: Confidence;
  reasons: string[];
  breakdown: { key: string; points: number; description: string }[];
  reputation?: string;
  domain_reputation?: Record<string, unknown>;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export type AuthUser = { id?: number | string; email?: string; created_at?: string };
export type LoginResponse = { access_token: string; user?: AuthUser; api_key?: string };
export type RegisterResponse = { access_token: string; user?: AuthUser; api_key?: string };

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  process.env.NEXT_PUBLIC_API_BASE ||
  'http://localhost:8000';

let cachedAuthToken: string | null = null;
let cachedApiKey: string | null = null;

export const getAuthToken = (): string | null => {
  if (cachedAuthToken) return cachedAuthToken;
  if (typeof window === 'undefined') return null;
  const val = localStorage.getItem('jwt');
  cachedAuthToken = val;
  return val;
};

export const setAuthToken = (token: string | null) => {
  cachedAuthToken = token;
  if (typeof window !== 'undefined') {
    if (token) localStorage.setItem('jwt', token);
    else localStorage.removeItem('jwt');
  }
};

export const getApiKey = (): string | null => {
  if (cachedApiKey) return cachedApiKey;
  if (typeof window === 'undefined') return null;
  const val = localStorage.getItem('manual_api_key');
  cachedApiKey = val || null;
  return cachedApiKey;
};

export const setApiKey = (key: string | null) => {
  cachedApiKey = key;
  if (typeof window !== 'undefined') {
    if (key) localStorage.setItem('manual_api_key', key);
    else localStorage.removeItem('manual_api_key');
  }
};

const makeRequestId = () => {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return `req_${Math.random().toString(16).slice(2)}`;
};

const buildHeaders = (extra?: Record<string, string>) => {
  const h: Record<string, string> = { 'Content-Type': 'application/json', ...(extra || {}) };
  const token = getAuthToken();
  const key = getApiKey();
  if (token) h['Authorization'] = `Bearer ${token}`;
  else if (key) h['X-API-Key'] = key;
  h['X-Request-Id'] = makeRequestId();
  return h;
};

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: buildHeaders(init?.headers as Record<string, string>),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(text || res.statusText, res.status);
  }
  if (res.headers.get('Content-Type')?.includes('application/json')) {
    return (await res.json()) as T;
  }
  return (await res.text()) as unknown as T;
}

export async function analyzeUrl(url: string): Promise<AnalysisResponse> {
  return apiFetch<AnalysisResponse>('/v1/analyze', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

export async function fetchScans(limit: number): Promise<{ items: ScanSummary[]; count: number }> {
  return apiFetch<{ items: ScanSummary[]; count: number }>(`/v1/scans?limit=${limit}`, {
    method: 'GET',
  });
}

export async function downloadReport(scanId: number): Promise<Blob> {
  const res = await fetch(`${API_BASE}/v1/scans/${scanId}/report.pdf`, {
    method: 'GET',
    headers: buildHeaders(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(text || res.statusText, res.status);
  }
  return res.blob();
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) return false;
    const data = await res.json();
    return Boolean(data?.ok);
  } catch {
    return false;
  }
}

export async function authRegister(email: string, password: string): Promise<RegisterResponse> {
  return apiFetch<RegisterResponse>('/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function authLogin(email: string, password: string): Promise<LoginResponse> {
  return apiFetch<LoginResponse>('/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}
