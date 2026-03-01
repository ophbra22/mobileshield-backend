"use client";

import { useState } from 'react';
import { extractUrls } from '@/lib/url';
import { Loader2, Link, ClipboardPaste } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Textarea } from './ui/textarea';

interface Props {
  onSubmit: (url: string) => void;
  loading: boolean;
}

export const ScanForm = ({ onSubmit, loading }: Props) => {
  const [text, setText] = useState('');
  const [selectedUrl, setSelectedUrl] = useState<string | null>(null);

  const urls = extractUrls(text);

  const handleSubmit = () => {
    const target = selectedUrl || urls[0] || text.trim();
    if (target) {
      const normalized = target.match(/^https?:\/\//i) ? target : `https://${target}`;
      onSubmit(normalized);
    }
  };

  return (
    <Card className="p-5 flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3 text-[var(--muted)] text-sm">
        <p className="text-lg font-bold text-[var(--text)]">ה-SMS חשוד? סרקו אותו!</p>
        <div className="flex gap-2">
          <Button type="button" variant="secondary" size="sm" onClick={() => navigator.clipboard.readText().then(setText)}>
            <ClipboardPaste size={14} className="mr-1" /> הדבק
          </Button>
        </div>
      </div>
      <Textarea
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setSelectedUrl(null);
        }}
        rows={4}
        placeholder="הדביקו כאן את ה-SMS או הקישור..."
      />
      {urls.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {urls.map((u) => (
            <Button
              key={u}
              type="button"
              variant={selectedUrl === u ? 'primary' : 'secondary'}
              size="sm"
              onClick={() => setSelectedUrl(u)}
              className="flex items-center gap-1"
            >
              <Link size={14} />
              {u}
            </Button>
          ))}
        </div>
      )}
      <Button onClick={handleSubmit} disabled={loading || (!selectedUrl && urls.length === 0 && !text.trim())} className="self-start">
        {loading && <Loader2 className="animate-spin" size={16} />} {loading ? 'סורק…' : 'שלח לבדיקה'}
      </Button>
    </Card>
  );
};
