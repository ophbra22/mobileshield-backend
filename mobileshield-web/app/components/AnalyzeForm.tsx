'use client';

import { FormEvent } from 'react';
import { Loader2, ShieldCheck } from 'lucide-react';

interface Props {
  url: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  disabled: boolean;
  loading: boolean;
}

export function AnalyzeForm({ url, onChange, onSubmit, disabled, loading }: Props) {
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!disabled) onSubmit();
  };

  return (
    <form onSubmit={submit} className="gradient-card rounded-2xl p-6 flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <div className="h-10 w-10 rounded-xl bg-emerald-500/15 text-emerald-300 flex items-center justify-center">
          <ShieldCheck size={20} />
        </div>
        <div>
          <p className="text-sm text-slate-400">URL Analyzer</p>
          <p className="text-lg font-semibold text-white">Inspect a link in seconds</p>
        </div>
      </div>
      <div className="flex flex-col md:flex-row gap-3">
        <input
          value={url}
          onChange={(e) => onChange(e.target.value)}
          placeholder="https://example.com/reset"
          className="flex-1 rounded-xl bg-slate-900/70 border border-slate-700 px-4 py-3 text-white placeholder:text-slate-500 focus:border-emerald-400 focus:ring-1 focus:ring-emerald-400"
        />
        <button
          type="submit"
          disabled={disabled}
          className="px-5 py-3 rounded-xl bg-gradient-to-r from-emerald-400 to-green-500 text-slate-900 font-semibold shadow-card flex items-center justify-center gap-2 disabled:opacity-50"
        >
          {loading && <Loader2 className="animate-spin" size={18} />} Analyze
        </button>
      </div>
    </form>
  );
}
