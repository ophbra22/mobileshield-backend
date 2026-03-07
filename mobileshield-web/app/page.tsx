/* eslint-disable @next/next/no-img-element */
'use client';

import { useState } from 'react';
import { HeaderBar } from './components/HeaderBar';
import { ScanForm } from './components/ScanForm';
import { analyzeUrl } from '@/lib/api';
import type { AnalysisResponse } from '@/lib/api';

export default function Home() {
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const onAnalyze = async (url: string) => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await analyzeUrl(url);
      setResult(res);
    } catch (e: any) {
      setErrorMsg(e.message || 'שגיאה');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="max-w-6xl mx-auto px-4 py-8 space-y-8">
      <HeaderBar />

      <div className="space-y-6">
        <ScanForm onSubmit={onAnalyze} loading={loading} result={result} error={errorMsg} />
      </div>
    </main>
  );
}
