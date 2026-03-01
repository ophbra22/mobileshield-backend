"use client";

import { useState } from 'react';
import { authLogin, authRegister, setApiKey, setAuthToken } from '@/lib/api';

interface Props {
  onClose: () => void;
  onRegisteredApiKey: (key: string) => void;
}

export const AuthModal = ({ onClose, onRegisteredApiKey }: Props) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    setLoading(true);
    try {
      if (mode === 'register') {
        const data = await authRegister(email, password);
        setAuthToken(data.access_token);
        if (data.api_key) {
          setApiKey(data.api_key);
          onRegisteredApiKey(data.api_key);
        }
      } else {
        const data = await authLogin(email, password);
        setAuthToken(data.access_token);
      }
      onClose();
    } catch (e: any) {
      setError(e?.message || 'שגיאה');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 flex items-center justify-center px-4">
      <div className="w-full max-w-md rounded-3xl bg-slate-900 border border-slate-800 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <p className="text-lg text-white font-bold">{mode === 'login' ? 'כניסה' : 'הרשמה'}</p>
          <button onClick={onClose} className="text-slate-400 text-sm">סגור</button>
        </div>

        <div className="flex gap-2 text-sm">
          <button
            onClick={() => setMode('login')}
            className={`flex-1 py-2 rounded-xl ${mode === 'login' ? 'bg-emerald-500 text-slate-900' : 'bg-slate-800 text-slate-200'}`}
          >
            כניסה
          </button>
          <button
            onClick={() => setMode('register')}
            className={`flex-1 py-2 rounded-xl ${mode === 'register' ? 'bg-emerald-500 text-slate-900' : 'bg-slate-800 text-slate-200'}`}
          >
            הרשמה
          </button>
        </div>

        <input
          type="email"
          placeholder={'דוא"ל'}
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full rounded-2xl bg-slate-950 border border-slate-800 text-slate-100 px-4 py-3"
        />

        <input
          type="password"
          placeholder="סיסמה"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full rounded-2xl bg-slate-950 border border-slate-800 text-slate-100 px-4 py-3"
        />

        {error && <p className="text-sm text-rose-400">{error}</p>}

        <button
          onClick={submit}
          disabled={loading}
          className="w-full py-3 rounded-2xl bg-gradient-to-l from-emerald-400 to-cyan-400 text-slate-900 font-semibold disabled:opacity-60"
        >
          {loading ? 'טוען...' : mode === 'login' ? 'כניסה' : 'הרשמה'}
        </button>
      </div>
    </div>
  );
};
