'use client';
import { useEffect, useState } from 'react';
import { setApiKey, setAuthToken } from '@/lib/api';

interface KeyItem {
  id: number;
  name: string;
  created_at: string;
  is_active: boolean;
  key_prefix: string;
  last4: string;
  api_key?: string | null;
}

export default function KeysPage() {
  const [keys, setKeys] = useState<KeyItem[]>([]);
  const [name, setName] = useState('mobile');
  const [error, setError] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const storedKey = localStorage.getItem('manual_api_key');
    if (storedKey) setApiKey(storedKey);
    const token = localStorage.getItem('jwt');
    if (token) setAuthToken(token);
    load();
  }, []);

  const load = async () => {
    const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'}/v1/keys`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      setError('נדרש להתחבר כדי לראות מפתחות');
      return;
    }
    const data = await res.json();
    setKeys(data);
  };

  const createKey = async () => {
    setError(null);
    const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'}/v1/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) {
      setError('יצירת מפתח נכשלה');
      return;
    }
    const data = await res.json();
    if (data.api_key) {
      setShowRaw(data.api_key);
      setApiKey(data.api_key);
      localStorage.setItem('manual_api_key', data.api_key);
    }
    load();
  };

  const revokeKey = async (id: number) => {
    await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'}/v1/keys/${id}/revoke`, { method: 'POST' });
    load();
  };

  return (
    <main className="max-w-4xl mx-auto px-4 py-6 space-y-4">
      <h1 className="text-2xl text-white font-bold">המפתחות שלי</h1>
      <div className="rounded-3xl bg-slate-900/60 border border-slate-800 p-5 space-y-3">
        <div className="flex gap-2 items-center">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="rounded-xl bg-slate-900 border border-slate-800 text-slate-100 px-3 py-2"
          />
          <button
            onClick={createKey}
            className="px-4 py-2 rounded-full bg-gradient-to-l from-emerald-400 to-cyan-400 text-slate-900 font-semibold"
          >
            יצירת מפתח
          </button>
        </div>
        {showRaw && (
          <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-400 text-amber-100 text-sm">
            שמור את המפתח החדש: <span className="font-mono">{showRaw}</span>
          </div>
        )}
        {error && <p className="text-rose-400 text-sm">{error}</p>}
        <div className="space-y-2">
          {keys.map((k) => (
            <div key={k.id} className="flex items-center justify-between px-3 py-2 rounded-2xl bg-slate-800/70 border border-slate-700">
              <div className="text-slate-200 text-sm">
                <p className="font-semibold">{k.name}</p>
                <p className="text-xs text-slate-400">
                  {k.key_prefix}****{k.last4}
                </p>
                <p className="text-xs text-slate-500">{new Date(k.created_at).toLocaleString('he-IL')}</p>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-1 rounded-full text-xs ${k.is_active ? 'bg-emerald-500/20 text-emerald-200' : 'bg-rose-500/20 text-rose-200'}`}>
                  {k.is_active ? 'פעיל' : 'מבוטל'}
                </span>
                {k.is_active && (
                  <button onClick={() => revokeKey(k.id)} className="text-rose-300 text-xs">
                    ביטול
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}
