"use client";

import { Loader2 } from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';

type ResultDisplayProps = {
  isLoading: boolean;
  result?: {
    status: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
    url: string;
    riskScore?: number;
  };
  error?: string;
};

const palette = {
  MALICIOUS: {
    bg: 'bg-red-50',
    text: 'text-red-800',
    border: 'border-red-300',
    gradient: 'from-red-500 via-red-500 to-red-600',
    defaultWidth: 95,
  },
  SUSPICIOUS: {
    bg: 'bg-orange-50',
    text: 'text-orange-800',
    border: 'border-orange-300',
    gradient: 'from-orange-400 via-orange-400 to-orange-500',
    defaultWidth: 55,
  },
  BENIGN: {
    bg: 'bg-green-50',
    text: 'text-green-800',
    border: 'border-green-300',
    gradient: 'from-green-400 via-green-400 to-green-500',
    defaultWidth: 15,
  },
} as const;

export function ResultDisplay({ isLoading, result, error }: ResultDisplayProps) {
  const { t } = useLanguage();
  if (!isLoading && !result && !error) return null;

  if (isLoading) {
    return (
      <div
        className="w-full rounded-2xl border border-border bg-surface p-6 flex items-center justify-center gap-3 shadow-sm transition-all duration-300 ease-in-out"
        aria-live="polite"
      >
        <Loader2 className="animate-spin text-muted" size={20} />
        <span className="text-sm text-muted">{t.checking}</span>
      </div>
    );
  }

  if (error) {
    return (
      <div
        className="w-full rounded-2xl border border-red-300 bg-red-50 text-red-800 p-6 shadow-sm transition-all duration-300 ease-in-out"
        aria-live="polite"
      >
        {error}
      </div>
    );
  }

  if (!result) return null;

  const cfg = palette[result.status];
  const domain = deriveDomain(result.url);
  const title =
    result.status === 'MALICIOUS' ? t.malicious : result.status === 'SUSPICIOUS' ? t.suspicious : t.benign;
  const description =
    result.status === 'MALICIOUS'
      ? t.phishingWarning
      : result.status === 'SUSPICIOUS'
        ? t.suspiciousWarning
        : t.benignMessage;
  const label =
    result.status === 'MALICIOUS'
      ? t.malicious
      : result.status === 'SUSPICIOUS'
        ? t.suspicious
        : t.benign;

  return (
    <div
      className={`w-full rounded-2xl border ${cfg.border} ${cfg.bg} ${cfg.text} p-6 md:p-8 shadow-lg transition-all duration-300 ease-in-out space-y-5`}
      aria-live="polite"
    >
      <div className="space-y-1">
        <p className="text-3xl font-black leading-tight">{title}</p>
        <p className="text-xs uppercase tracking-[0.3em] font-semibold opacity-80">{label}</p>
        <p className="text-sm font-medium break-all opacity-90">{domain}</p>
      </div>

      <p className="text-base leading-relaxed font-semibold">{description}</p>
    </div>
  );
}

function deriveDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}
