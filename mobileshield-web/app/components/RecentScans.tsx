'use client';

import { Clock3 } from 'lucide-react';
import type { ScanSummary } from '@/lib/api';

interface Props {
  scans: ScanSummary[];
  loading: boolean;
  onSelect: (scan: ScanSummary) => void;
}

export function RecentScans({ scans, loading, onSelect }: Props) {
  return (
    <div className="gradient-card rounded-2xl p-6 flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <div className="h-10 w-10 rounded-xl bg-purple-500/15 text-purple-200 flex items-center justify-center">
          <Clock3 size={18} />
        </div>
        <div>
          <p className="text-sm text-slate-400">Recent scans</p>
          <p className="text-lg font-semibold text-white">Latest activity</p>
        </div>
      </div>

      {loading ? (
        <p className="text-sm text-slate-400">Loading scans…</p>
      ) : scans.length === 0 ? (
        <p className="text-sm text-slate-400">No scans yet. Run your first analysis!</p>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
          <table className="w-full text-sm">
            <thead className="text-slate-400 bg-slate-900/60">
              <tr>
                <th className="text-left px-4 py-3">Time</th>
                <th className="text-left px-4 py-3">Domain</th>
                <th className="text-left px-4 py-3">Verdict</th>
                <th className="text-left px-4 py-3">Score</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr
                  key={scan.id}
                  className="table-row cursor-pointer border-t border-slate-800"
                  onClick={() => onSelect(scan)}
                >
                  <td className="px-4 py-3 text-slate-300">{new Date(scan.created_at).toLocaleString()}</td>
                  <td className="px-4 py-3 text-white font-semibold">{scan.domain}</td>
                  <td className="px-4 py-3 capitalize text-slate-200">{scan.verdict}</td>
                  <td className="px-4 py-3 text-slate-200">{scan.risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
