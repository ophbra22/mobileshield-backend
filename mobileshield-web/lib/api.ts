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

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? 'http://localhost:8000';

const headers = (apiKey?: string) => ({
  'Content-Type': 'application/json',
  ...(apiKey ? { 'X-API-Key': apiKey } : {}),
});

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(text || res.statusText, res.status);
  }
  return res.json() as Promise<T>;
}

export async function analyzeUrl(url: string, apiKey: string): Promise<AnalysisResponse> {
  const res = await fetch(`${API_BASE}/v1/analyze`, {
    method: 'POST',
    headers: headers(apiKey),
    body: JSON.stringify({ url }),
  });
  return handle<AnalysisResponse>(res);
}

export async function fetchScans(limit: number, apiKey: string): Promise<{ items: ScanSummary[]; count: number }> {
  const res = await fetch(`${API_BASE}/v1/scans?limit=${limit}`, {
    method: 'GET',
    headers: headers(apiKey),
  });
  return handle<{ items: ScanSummary[]; count: number }>(res);
}

export async function downloadReport(scanId: number, apiKey: string): Promise<Blob> {
  const res = await fetch(`${API_BASE}/v1/scans/${scanId}/report.pdf`, {
    headers: headers(apiKey),
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
  } catch (err) {
    return false;
  }
}
