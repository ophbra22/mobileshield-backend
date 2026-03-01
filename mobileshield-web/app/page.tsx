/* eslint-disable @next/next/no-img-element */
'use client';

import { useEffect, useState } from 'react';
import { HeaderBar } from './components/HeaderBar';
import { ScanForm } from './components/ScanForm';
import { ResultPanel } from './components/ResultPanel';
import { SettingsDrawer } from './components/SettingsDrawer';
import { analyzeUrl, downloadReport, fetchScans, setApiKey, setAuthToken } from '@/lib/api';
import type { AnalysisResponse, ScanSummary } from '@/lib/api';
import { CheckCircle2, Shield, AlertTriangle } from 'lucide-react';
import { Card } from './components/ui/card';
import { Button } from './components/ui/button';
import { StatusPill } from './components/StatusPill';

export default function Home() {
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [requestId, setRequestId] = useState<string | null>(null);
  const [lang, setLang] = useState<'he' | 'en'>('he');
  const [isAuthed, setIsAuthed] = useState(true); // TEMP public mode
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await fetchScans(10);
      setHistory(res.items);
    } catch (e) {
      // ignore
    }
  };

  const onAnalyze = async (url: string) => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await analyzeUrl(url);
      setResult(res);
      const rid = (res as any).request_id;
      if (rid) setRequestId(rid);
      fetchHistory();
    } catch (e: any) {
      setErrorMsg(e.message || 'שגיאה');
    } finally {
      setLoading(false);
    }
  };

  const onExport = async (scanId: number) => {
    setExporting(true);
    try {
      const blob = await downloadReport(scanId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan_${scanId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      alert('Export failed');
    } finally {
      setExporting(false);
    }
  };

  const t = (he: string, en: string) => (lang === 'he' ? he : en);

  return (
    <main className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <HeaderBar
        onLoginClick={() => {}}
        onLogout={() => {
          setAuthToken(null);
          setApiKey(null);
          setIsAuthed(true);
        }}
        onOpenKeys={() => (window.location.href = '/keys')}
        onOpenSettings={() => setShowSettings(true)}
        isAuthenticated={isAuthed}
        lang={lang}
        onToggleLang={() => setLang(lang === 'he' ? 'en' : 'he')}
      />

      {errorMsg && <div className="rounded-xl border border-danger/30 bg-danger/5 text-danger px-4 py-2 text-sm">{errorMsg}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_1fr] gap-8 items-start">
        <section className="space-y-4">
          <Card className="p-6 space-y-3">
            <p className="text-3xl font-bold text-[var(--text)]">{t('ה-SMS חשוד? סרקו אותו!', 'Suspicious SMS? Scan it!')}</p>
            <p className="text-[var(--muted)]">
              {t('הדביקו טקסט או קישור ונזהה פישינג, הפניות ומוניטין דומיין בזמן אמת.', 'Paste text or a link to detect phishing, redirects and domain reputation.')}
            </p>
            <ScanForm onSubmit={onAnalyze} loading={loading} />
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <ExampleCard
              title="קישור עדין"
              verdict="benign"
              text="https://gov.il/info/covid"
              color="emerald"
              icon={<CheckCircle2 />}
            />
            <ExampleCard
              title="נראה חשוד"
              verdict="suspicious"
              text="http://pay-pal-secure-login.com"
              color="amber"
              icon={<AlertTriangle />}
            />
            <ExampleCard title="פישינג" verdict="malicious" text="http://bankleumi.secure-login.ru" color="rose" icon={<Shield />} />
          </div>
        </section>

        <section className="space-y-4">
          <ResultPanel result={result} onExport={onExport} exporting={exporting} requestId={requestId} />
          <Card className="p-4 space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-[var(--text)]">סריקות אחרונות</p>
              <Button variant="ghost" size="sm" onClick={() => (window.location.href = '/history')}>
                לכל ההיסטוריה →
              </Button>
            </div>
            <div className="space-y-1">
              {history.map((h) => (
                <button
                  key={h.id}
                  onClick={() => (window.location.href = `/history`)}
                  className="w-full text-left border border-border rounded-xl px-3 py-2 hover:bg-surface2 transition flex items-center gap-3"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold break-all">{h.domain}</p>
                    <p className="text-xs text-muted2">{new Date(h.created_at).toLocaleString('he-IL')}</p>
                  </div>
                  <StatusPill verdict={h.verdict} />
                  <span className="text-xs text-muted">{h.risk_score ?? ''}</span>
                </button>
              ))}
              {history.length === 0 && <p className="text-xs text-[var(--muted)]">אין סריקות עדיין.</p>}
            </div>
          </Card>
        </section>
      </div>

      <SettingsDrawer open={showSettings} onClose={() => setShowSettings(false)} initialApiBase={process.env.NEXT_PUBLIC_API_BASE ?? 'http://localhost:8000'} />
    </main>
  );
}

const ExampleCard = ({
  title,
  verdict,
  text,
  color,
  icon,
}: {
  title: string;
  verdict: string;
  text: string;
  color: 'emerald' | 'amber' | 'rose';
  icon: React.ReactNode;
}) => {
  const colors =
    color === 'emerald'
      ? 'bg-success/10 border border-success/30 text-success'
      : color === 'amber'
      ? 'bg-warning/10 border border-warning/30 text-warning-700'
      : 'bg-danger/10 border border-danger/30 text-danger';
  return (
    <div className={`rounded-2xl p-4 ${colors} space-y-1`}>
      <div className="flex items-center gap-2 text-sm font-semibold">
        {icon}
        {title}
      </div>
      <p className="text-xs text-text truncate">{text}</p>
      <span className="text-2xs uppercase opacity-75">{verdict}</span>
    </div>
  );
};
