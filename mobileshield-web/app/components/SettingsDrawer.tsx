"use client";

import { useState } from 'react';
import { setApiKey } from '@/lib/api';

interface Props {
  open: boolean;
  onClose: () => void;
  initialApiBase: string;
}

export const SettingsDrawer = ({ open, onClose, initialApiBase }: Props) => {
  const [apiBase, setApiBase] = useState(initialApiBase);
  const [apiKey, setApiKeyLocal] = useState('');

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50 backdrop-blur-sm">
      <div className="w-full max-w-md h-full bg-slate-950 border-l border-slate-800 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <p className="text-lg text-white font-bold">הגדרות</p>
          <button onClick={onClose} className="text-slate-400 text-sm">
            סגור
          </button>
        </div>
        <label className="text-sm text-slate-300">API Base URL</label>
        <input
          value={apiBase}
          onChange={(e) => setApiBase(e.target.value)}
          className="w-full rounded-2xl bg-slate-900 border border-slate-800 text-slate-100 px-4 py-3"
        />
        <label className="text-sm text-slate-300">מפתח API ידני</label>
        <input
          value={apiKey}
          onChange={(e) => setApiKeyLocal(e.target.value)}
          className="w-full rounded-2xl bg-slate-900 border border-slate-800 text-slate-100 px-4 py-3"
          placeholder="ms_live_..."
        />
        <button
          onClick={() => {
            setApiKey(apiKey || null);
            localStorage.setItem('manual_api_key', apiKey || '');
            localStorage.setItem('api_base', apiBase || '');
            onClose();
          }}
          className="w-full py-3 rounded-2xl bg-gradient-to-l from-emerald-400 to-cyan-400 text-slate-900 font-semibold"
        >
          שמירה
        </button>
      </div>
    </div>
  );
};
