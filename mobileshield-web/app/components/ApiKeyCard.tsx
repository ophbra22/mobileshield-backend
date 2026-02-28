'use client';

import { useEffect, useState } from 'react';
import { Check, KeyRound } from 'lucide-react';

interface Props {
  value: string;
  remember: boolean;
  onChange: (value: string) => void;
  onToggleRemember: (remember: boolean) => void;
  onSave: (value: string, remember: boolean) => void;
}

export function ApiKeyCard({ value, remember, onChange, onToggleRemember, onSave }: Props) {
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (saved) {
      const timeout = setTimeout(() => setSaved(false), 1600);
      return () => clearTimeout(timeout);
    }
  }, [saved]);

  return (
    <div className="gradient-card rounded-2xl p-6 flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <div className="h-10 w-10 rounded-xl bg-blue-500/15 text-blue-300 flex items-center justify-center">
          <KeyRound size={20} />
        </div>
        <div>
          <p className="text-sm text-slate-400">API Key</p>
          <p className="text-lg font-semibold text-white">Authenticate requests</p>
        </div>
      </div>
      <div className="flex flex-col md:flex-row gap-3">
        <input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="ms_live_..."
          className="flex-1 rounded-xl bg-slate-900/70 border border-slate-700 px-4 py-3 text-white placeholder:text-slate-500 focus:border-blue-400 focus:ring-1 focus:ring-blue-400"
        />
        <button
          onClick={() => {
            onSave(value.trim(), remember);
            setSaved(true);
          }}
          className="px-5 py-3 rounded-xl bg-gradient-to-r from-blue-500 to-cyan-400 text-slate-900 font-semibold shadow-card disabled:opacity-50"
          disabled={!value.trim()}
        >
          Save key
        </button>
      </div>
      <div className="flex items-center justify-between text-sm text-slate-400">
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            className="accent-blue-400 h-4 w-4"
            checked={remember}
            onChange={(e) => onToggleRemember(e.target.checked)}
          />
          Remember in this browser
        </label>
        {saved && (
          <span className="inline-flex items-center gap-1 text-emerald-300 font-semibold">
            <Check size={16} /> Saved
          </span>
        )}
      </div>
    </div>
  );
}
