'use client';
import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { AnalysisResponse, downloadReport, setApiKey, setAuthToken } from '@/lib/api';

export default function HistoryDetail() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<AnalysisResponse | null>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const storedKey = localStorage.getItem('manual_api_key');
    if (storedKey) setApiKey(storedKey);
    const token = localStorage.getItem('jwt');
    if (token) setAuthToken(token);
    load();
  }, [params?.id]);

  const load = async () => {
    if (!params?.id) return;
    const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'}/v1/scans/${params.id}`, {
      headers: { Accept: 'application/json' },
    });
    if (res.ok) {
      const json = await res.json();
      setData(json as any);
    }
  };

  const exportPdf = async () => {
    if (!params?.id) return;
    const blob = await downloadReport(Number(params.id));
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_${params.id}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!data) return <p className="p-6 text-slate-100">טוען...</p>;

  return (
    <main className="max-w-4xl mx-auto px-4 py-6 space-y-4">
      <div className="rounded-3xl bg-slate-900/60 border border-slate-800 p-6 space-y-3">
        <h1 className="text-2xl text-white font-bold">פרטי סריקה #{params?.id}</h1>
        <p className="text-slate-200 break-all">{data.normalized_url}</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm text-slate-200">
          <Stat label="ציון" value={data.risk_score} />
          <Stat label="פסק" value={data.verdict} />
          <Stat label="ביטחון" value={data.confidence} />
          <Stat label="הפניות" value={data.redirect_hops} />
        </div>
        <div>
          <p className="text-slate-300 text-sm font-semibold mb-2">סיבות</p>
          <ul className="list-disc list-inside text-slate-200 space-y-1">
            {data.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
        <button
          onClick={exportPdf}
          className="px-4 py-3 rounded-full bg-gradient-to-l from-emerald-400 to-cyan-400 text-slate-900 font-semibold"
        >
          ייצוא PDF
        </button>
      </div>
    </main>
  );
}

const Stat = ({ label, value }: { label: string; value: string | number }) => (
  <div className="rounded-2xl bg-slate-800/70 border border-slate-700 p-3">
    <p className="text-xs text-slate-400">{label}</p>
    <p className="text-white font-bold">{value}</p>
  </div>
);
