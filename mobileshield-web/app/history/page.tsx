'use client';
import { useEffect, useMemo, useState } from 'react';
import { fetchScans, setApiKey, setAuthToken, type ScanSummary } from '@/lib/api';

const filtersOptions = [
  { label: 'כל התוצאות', value: 'all' },
  { label: 'Benign', value: 'safe' },
  { label: 'Suspicious', value: 'suspicious' },
  { label: 'Malicious', value: 'malicious' },
];

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const storedKey = localStorage.getItem('manual_api_key');
    if (storedKey) setApiKey(storedKey);
    const token = localStorage.getItem('jwt');
    if (token) setAuthToken(token);
    load();
  }, []);

  const load = async () => {
    try {
      const res = await fetchScans(200);
      setScans(res.items);
    } catch (e) {
      // ignore
    }
  };

  const filtered = useMemo(() => {
    return scans.filter((s) => (filter === 'all' ? true : s.verdict === filter) && s.domain.includes(search));
  }, [scans, filter, search]);

  return (
    <main className="max-w-5xl mx-auto px-4 py-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl text-white font-bold">היסטוריית סריקות</h1>
        <input
          placeholder="חיפוש דומיין..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="rounded-xl bg-slate-900 border border-slate-800 text-slate-100 px-3 py-2"
        />
      </div>
      <div className="flex gap-2 text-sm">
        {filtersOptions.map((f) => (
          <button
            key={f.value}
            onClick={() => setFilter(f.value)}
            className={`px-3 py-2 rounded-xl ${filter === f.value ? 'bg-emerald-500 text-slate-900' : 'bg-slate-800 text-slate-100'}`}
          >
            {f.label}
          </button>
        ))}
      </div>
      <div className="rounded-3xl bg-slate-900/60 border border-slate-800 overflow-hidden">
        <table className="w-full text-sm text-slate-100">
          <thead className="bg-slate-900/80 text-slate-300">
            <tr>
              <th className="p-3 text-right">דומיין</th>
              <th className="p-3 text-right">תאריך</th>
              <th className="p-3 text-right">ציון</th>
              <th className="p-3 text-right">פסק</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => (
              <tr
                key={s.id}
                className="border-t border-slate-800 hover:bg-slate-800/60 cursor-pointer"
                onClick={() => (window.location.href = `/history/${s.id}`)}
              >
                <td className="p-3">{s.domain}</td>
                <td className="p-3">{new Date(s.created_at).toLocaleString('he-IL')}</td>
                <td className="p-3">{s.risk_score}</td>
                <td className="p-3 capitalize">{s.verdict}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}
