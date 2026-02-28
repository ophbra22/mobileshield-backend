'use client';

import { useMemo, useState } from 'react';
import { ChevronDown, Download, Link2, ListChecks, ShieldAlert } from 'lucide-react';
import type { AnalysisResponse } from '@/lib/api';

interface Props {
  result?: AnalysisResponse | null;
  onExport?: () => void;
  exporting?: boolean;
}

const badgeStyles: Record<string, string> = {
  safe: 'bg-emerald-500/15 text-emerald-200 border border-emerald-500/40',
  suspicious: 'bg-amber-500/15 text-amber-200 border border-amber-500/40',
  malicious: 'bg-rose-500/15 text-rose-200 border border-rose-500/40',
};

export function ResultCard({ result, onExport, exporting = false }: Props) {
  const [showSignals, setShowSignals] = useState(false);

  const scoreColor = useMemo(() => {
    if (!result) return 'bg-slate-700';
    if (result.risk_score >= 70) return 'bg-rose-500';
    if (result.risk_score >= 30) return 'bg-amber-400';
    return 'bg-emerald-400';
  }, [result]);

  if (!result) {
    return (
      <div className="gradient-card rounded-2xl p-6 text-slate-400">
        No scan yet. Paste a URL to see MobileShield AI in action.
      </div>
    );
  }

  return (
    <div className="gradient-card rounded-2xl p-6 flex flex-col gap-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-slate-800 text-slate-200 flex items-center justify-center">
            <Link2 size={18} />
          </div>
          <div>
            <p className="text-sm text-slate-400">Normalized URL</p>
            <p className="text-lg font-semibold text-white break-all">{result.normalized_url}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {result.reputation && (
            <span className="badge bg-slate-800 text-slate-100 border border-slate-700 capitalize">
              Reputation: {result.reputation}
            </span>
          )}
          <span className={`badge ${badgeStyles[result.verdict]} capitalize`}>{result.verdict}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
          <p className="text-xs text-slate-400">Risk score</p>
          <div className="mt-2 flex items-center gap-3">
            <div className="flex-1 h-2 rounded-full bg-slate-800 overflow-hidden">
              <div className={`h-full ${scoreColor}`} style={{ width: `${result.risk_score}%` }} />
            </div>
            <span className="text-white font-semibold">{result.risk_score}</span>
          </div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
          <p className="text-xs text-slate-400">Confidence</p>
          <span className="badge bg-slate-800 text-slate-100 border border-slate-700 capitalize mt-2 inline-flex">
            {result.confidence}
          </span>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
          <p className="text-xs text-slate-400">Domain reputation</p>
          <p className="text-white font-semibold capitalize">{result.reputation || 'unknown'}</p>
          {(() => {
            const rep = (result.signals?.['domain_reputation'] as any) || {};
            const age = rep.signals?.domain_age_days;
            return (
              <p className="text-xs text-slate-500 mt-1">
                Age: {age !== undefined && age !== null ? `${age} days` : 'n/a'} | Hint: {rep.score_hint ?? 0}
              </p>
            );
          })()}
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 flex flex-col gap-1">
          <p className="text-xs text-slate-400">Redirects</p>
          <p className="text-white font-semibold">{result.redirect_hops} hop(s)</p>
          <p className="text-xs text-slate-500">Final URL: {result.final_url ?? 'n/a'}</p>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
        <div className="flex items-center gap-2 text-slate-200 font-semibold mb-2">
          <ListChecks size={18} /> Reasons
        </div>
        {result.reasons.length === 0 ? (
          <p className="text-slate-400 text-sm">No risk factors detected.</p>
        ) : (
          <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm text-slate-200 list-disc list-inside">
            {result.reasons.map((reason, idx) => (
              <li key={idx}>{reason}</li>
            ))}
          </ul>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
        <div className="flex items-center gap-2 text-slate-200 font-semibold mb-2">
          <ShieldAlert size={18} /> Risk breakdown
        </div>
        {result.breakdown && result.breakdown.length > 0 ? (
          <div className="space-y-2">
            {result.breakdown.map((item, idx) => (
              <div key={`${item.key}-${idx}`} className="flex items-center gap-3">
                <div className="w-24 text-xs text-slate-400 capitalize">{item.key}</div>
                <div className="flex-1 h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-blue-400 to-cyan-300"
                    style={{ width: `${Math.min(item.points, 40)}%` }}
                  />
                </div>
                <span className="text-sm text-white font-semibold">{item.points}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-slate-400">No breakdown available.</p>
        )}
      </div>

      {onExport && result.scan_id && (
        <button
          type="button"
          onClick={onExport}
          disabled={exporting}
          className="inline-flex items-center gap-2 self-start px-4 py-2 rounded-lg bg-gradient-to-r from-blue-500 to-cyan-400 text-slate-900 font-semibold shadow-card disabled:opacity-50"
        >
          <Download size={16} /> {exporting ? 'Generating…' : 'Export PDF'}
        </button>
      )}

      <button
        type="button"
        onClick={() => setShowSignals((s) => !s)}
        className="flex items-center justify-between w-full rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3 text-sm text-slate-200"
      >
        <span>Signals (raw JSON)</span>
        <ChevronDown size={18} className={`transition-transform ${showSignals ? 'rotate-180' : ''}`} />
      </button>
      {showSignals && (
        <pre className="rounded-xl bg-slate-900/80 border border-slate-800 p-4 text-xs text-slate-200 overflow-x-auto">
          {JSON.stringify(result.signals, null, 2)}
        </pre>
      )}
    </div>
  );
}
