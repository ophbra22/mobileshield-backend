'use client';

import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, Shield } from 'lucide-react';
import { ApiKeyCard } from './components/ApiKeyCard';
import { AnalyzeForm } from './components/AnalyzeForm';
import { RecentScans } from './components/RecentScans';
import { ResultCard } from './components/ResultCard';
import { analyzeUrl, ApiError, fetchScans, ScanSummary, checkHealth, AnalysisResponse, downloadReport } from '@/lib/api';

const localStorageKey = 'mobileshield_api_key';

const isValidUrl = (value: string) => {
  try {
    const candidate = value.match(/^https?:\/\//i) ? value : `https://${value}`;
    const parsed = new URL(candidate);
    return Boolean(parsed.hostname && parsed.hostname.includes('.'));
  } catch (err) {
    return false;
  }
};

export default function Page() {
  const [apiKey, setApiKey] = useState('');
  const [rememberKey, setRememberKey] = useState(true);
  const [url, setUrl] = useState('');
  const [healthOk, setHealthOk] = useState<boolean | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [scansLoading, setScansLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    const saved = window.localStorage.getItem(localStorageKey);
    if (saved) setApiKey(saved);
    checkHealth().then(setHealthOk);
  }, []);

  useEffect(() => {
    if (!apiKey) {
      setScans([]);
      return;
    }
    setScansLoading(true);
    fetchScans(20, apiKey)
      .then((data) => setScans(data.items))
      .catch(() => {})
      .finally(() => setScansLoading(false));
  }, [apiKey]);

  const handleSaveKey = (value: string, remember: boolean) => {
    setApiKey(value);
    if (remember) {
      window.localStorage.setItem(localStorageKey, value);
    } else {
      window.localStorage.removeItem(localStorageKey);
    }
  };

  const loadScanDetails = (scan: ScanSummary) => {
    const mapped: AnalysisResponse = {
      scan_id: scan.id,
      normalized_url: scan.normalized_url,
      domain: scan.domain,
      final_url: scan.final_url,
      redirect_hops: 0,
      risk_score: scan.risk_score,
      verdict: scan.verdict,
      confidence: scan.confidence,
      reasons: scan.reasons,
      signals: {
        domain_reputation: scan.domain_reputation,
      },
      breakdown: scan.breakdown || [],
      reputation: scan.reputation,
    };
    setResult(mapped);
  };

  const submitAnalysis = async () => {
    setError(null);
    const trimmed = url.trim();
    if (!trimmed || !apiKey || !isValidUrl(trimmed)) {
      setError('Enter a valid URL and API key.');
      return;
    }
    setIsAnalyzing(true);
    try {
      const res = await analyzeUrl(trimmed, apiKey);
      setResult(res);
      const refreshed = await fetchScans(20, apiKey);
      setScans(refreshed.items);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 401) setError('Invalid or missing API key. Save a valid key to continue.');
        else if (err.status === 429) setError('Rate limit exceeded. Please wait a moment and try again.');
        else setError(err.message || 'Unexpected error while analyzing.');
      } else {
        setError('Network error. Please check connectivity and try again.');
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const healthBadge = useMemo(() => {
    if (healthOk === null) return 'Checking health…';
    return healthOk ? 'API online' : 'API offline';
  }, [healthOk]);

  const handleExport = async () => {
    if (!result?.scan_id || !apiKey) return;
    setDownloading(true);
    try {
      const blob = await downloadReport(result.scan_id, apiKey);
      const urlObj = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = urlObj;
      a.download = `mobileshield_scan_${result.scan_id}.pdf`;
      a.click();
      window.URL.revokeObjectURL(urlObj);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Failed to export PDF.';
      setError(message);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <main className="max-w-6xl mx-auto px-4 py-10 flex flex-col gap-6">
      <header className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-12 w-12 rounded-2xl bg-gradient-to-br from-blue-500 to-cyan-400 shadow-card flex items-center justify-center text-slate-900">
            <Shield size={22} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">MobileShield AI</h1>
            <p className="text-slate-400">Instant phishing insight for SMS links.</p>
          </div>
        </div>
        <div className={`inline-flex items-center gap-2 px-3 py-2 rounded-full border ${healthOk ? 'border-emerald-500/60 text-emerald-200' : 'border-amber-500/60 text-amber-200'}`}>
          <span className={`h-2.5 w-2.5 rounded-full ${healthOk ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
          <span className="text-sm font-semibold">{healthBadge}</span>
        </div>
      </header>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 flex flex-col gap-4">
          <AnalyzeForm
            url={url}
            onChange={setUrl}
            onSubmit={submitAnalysis}
            loading={isAnalyzing}
            disabled={isAnalyzing || !apiKey || !isValidUrl(url)}
          />
          {error && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-100 px-4 py-3 flex items-center gap-2">
              <AlertTriangle size={18} />
              <span>{error}</span>
            </div>
          )}
          <ResultCard result={result} onExport={handleExport} exporting={downloading} />
        </div>
        <div className="flex flex-col gap-4">
          <ApiKeyCard
            value={apiKey}
            remember={rememberKey}
            onChange={setApiKey}
            onToggleRemember={setRememberKey}
            onSave={handleSaveKey}
          />
          <RecentScans scans={scans} loading={scansLoading} onSelect={loadScanDetails} />
          <div className="gradient-card rounded-2xl p-5 text-sm text-slate-300 flex items-start gap-3">
            <CheckCircle2 className="text-emerald-300" size={18} />
            <div>
              <p className="font-semibold">How to use</p>
              <ol className="list-decimal list-inside text-slate-400 mt-1 space-y-1">
                <li>Mint an API key via <code>/admin/create-api-key</code> on the backend.</li>
                <li>Paste it into the card above and save.</li>
                <li>Drop in a URL and hit Analyze to view verdicts and signals.</li>
              </ol>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
