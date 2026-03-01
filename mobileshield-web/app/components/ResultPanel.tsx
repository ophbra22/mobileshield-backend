"use client";

import { useState } from 'react';
import { FileDown, Copy, AlertCircle, Check } from 'lucide-react';
import type { AnalysisResponse } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Accordion } from './ui/accordion';
import { RiskMeter } from './RiskMeter';
import { StatusPill } from './StatusPill';

interface Props {
  result: AnalysisResponse | null;
  onExport: (scanId: number) => void;
  exporting: boolean;
  requestId?: string | null;
}

export const ResultPanel = ({ result, onExport, exporting, requestId }: Props) => {
  const [copied, setCopied] = useState(false);
  if (!result) {
    return (
      <Card className="p-6 text-muted">
        התוצאה תופיע כאן לאחר הסריקה.
      </Card>
    );
  }

  const displayScore = result.risk_score > 25 ? Math.ceil(result.risk_score) : result.risk_score;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(result.normalized_url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      setCopied(false);
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex items-start justify-between gap-3">
          <div className="space-y-1 min-w-0">
            <p className="text-sm text-muted">קישור מנורמל</p>
            <div className="flex items-center gap-2 flex-wrap">
              <p className="text-lg font-semibold break-all">{result.normalized_url}</p>
              <Button size="sm" variant="ghost" onClick={handleCopy} className="flex items-center gap-1">
                {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? 'הועתק' : 'העתק'}
              </Button>
            </div>
            {requestId && <p className="text-xs text-muted2">X-Request-Id: {requestId}</p>}
          </div>
          <div className="flex gap-2 items-center flex-wrap justify-end">
            <StatusPill verdict={result.verdict} />
            <Badge variant="neutral">מוניטין: {result.reputation || 'unknown'}</Badge>
          </div>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <StatCard title="ציון סיכון">
            <RiskMeter score={displayScore} />
          </StatCard>
          <StatCard title="רמת ביטחון" value={result.confidence} />
          <StatCard title="הפניות" value={`${result.redirect_hops}`} footer={result.final_url || 'לא זמין'} />
          <StatCard title="דומיין" value={result.domain} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>פירוט</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <p className="text-sm text-muted font-semibold mb-2">סיבות</p>
            <ul className="list-disc list-inside text-sm text-text space-y-1">
              {result.reasons.map((r, idx) => (
                <li key={idx}>{r}</li>
              ))}
            </ul>
          </div>
          <div>
            <p className="text-sm text-muted font-semibold mb-2">פירוק סיכונים</p>
            <div className="space-y-2">
              {result.breakdown?.length ? (
                result.breakdown.map((b, idx) => (
                  <div key={`${b.key}-${idx}`} className="flex items-center gap-3">
                    <div className="w-32 text-xs text-muted">{b.key}</div>
                    <div className="flex-1 h-2 rounded-full bg-surface2 overflow-hidden">
                      <div className="h-full bg-primary" style={{ width: `${Math.min(b.points, 100)}%` }} />
                    </div>
                    <span className="text-sm font-semibold">{b.points}</span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted2">אין פירוט זמין.</p>
              )}
            </div>
          </div>
          <Accordion title="Signals (JSON)" defaultOpen={false}>
            <pre className="text-xs text-muted break-all">{JSON.stringify(result.signals, null, 2)}</pre>
          </Accordion>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-muted text-sm">
              <AlertCircle size={16} />
              <span className="text-xs">הורד דוח PDF</span>
            </div>
            <Button onClick={() => onExport(result.scan_id)} disabled={exporting} variant="secondary" className="flex items-center gap-2">
              <FileDown size={18} /> {exporting ? 'מייצא...' : 'ייצוא PDF'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

const StatCard = ({ title, value, footer, children }: { title: string; value?: string | number; footer?: string; children?: React.ReactNode }) => (
  <div className="rounded-2xl border border-border bg-surface2/60 p-4 flex flex-col gap-1">
    <p className="text-xs text-muted">{title}</p>
    {children ? children : <p className="text-xl font-bold text-text break-words">{value}</p>}
    {footer && <p className="text-xs text-muted2 break-all">{footer}</p>}
  </div>
);
