"use client";

import { useEffect, useMemo, useRef, useState } from 'react';
import { extractUrls } from '@/lib/url';
import type { AnalysisResponse } from '@/lib/api';
import { Loader2, Link, ClipboardPaste } from 'lucide-react';
import { Button } from './ui/button';
import { Textarea } from './ui/textarea';
import { ResultDisplay } from './ResultDisplay';
import { useLanguage } from '../context/LanguageContext';

interface Props {
  onSubmit: (url: string) => void;
  loading: boolean;
  result?: AnalysisResponse | null;
  error?: string | null;
}

type ResultStatus = 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';

const mapStatus = (verdict: AnalysisResponse['verdict']): ResultStatus => {
  if (verdict === 'malicious') return 'MALICIOUS';
  if (verdict === 'suspicious') return 'SUSPICIOUS';
  return 'BENIGN';
};

export const ScanForm = ({ onSubmit, loading, result, error }: Props) => {
  const [text, setText] = useState('');
  const [selectedUrl, setSelectedUrl] = useState<string | null>(null);
  const [lastSubmitted, setLastSubmitted] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement | null>(null);
  const { t } = useLanguage();

  const urls = extractUrls(text);

  const handleSubmit = () => {
    const target = selectedUrl || urls[0] || text.trim();
    if (target) {
      const normalized = target.match(/^https?:\/\//i) ? target : `https://${target}`;
      setLastSubmitted(normalized);
      onSubmit(normalized);
    }
  };

  const displayResult = useMemo(() => {
    if (!result) return undefined;
    const status = mapStatus(result.verdict);
    const url = result.final_url || result.normalized_url || lastSubmitted || '';
    return { status, url, riskScore: result.risk_score };
  }, [result, lastSubmitted]);

  useEffect(() => {
    if ((loading || displayResult || error) && resultRef.current) {
      resultRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, [loading, displayResult, error]);

  return (
    <div className="rounded-2xl border border-border bg-surface p-5 md:p-6 shadow-sm space-y-4">
      <div className="flex items-center justify-between gap-3 text-[var(--muted)] text-sm">
        <p className="text-lg font-bold text-[var(--text)]">{t.scanTitle}</p>
        <div className="flex gap-2">
          <Button type="button" variant="secondary" size="sm" onClick={() => navigator.clipboard.readText().then(setText)}>
            <ClipboardPaste size={14} className="mr-1" /> {t.paste}
          </Button>
        </div>
      </div>
      <Textarea
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setSelectedUrl(null);
        }}
        rows={4}
        placeholder={t.placeholder}
      />
      {urls.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {urls.map((u) => (
            <Button
              key={u}
              type="button"
              variant={selectedUrl === u ? 'primary' : 'secondary'}
              size="sm"
              onClick={() => setSelectedUrl(u)}
              className="flex items-center gap-1"
            >
              <Link size={14} />
              {u}
            </Button>
          ))}
        </div>
      )}
      <Button onClick={handleSubmit} disabled={loading || (!selectedUrl && urls.length === 0 && !text.trim())} className="self-start">
        {loading && <Loader2 className="animate-spin" size={16} />} {loading ? t.scanning : t.scanButton}
      </Button>

      <div ref={resultRef} aria-live="polite">
        <ResultDisplay isLoading={loading} result={displayResult} error={error || undefined} />
      </div>
    </div>
  );
};
