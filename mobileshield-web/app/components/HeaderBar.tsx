"use client";

import { useState } from 'react';
import { Globe2, Languages, Mail, Copy, Check } from 'lucide-react';
import { Button, buttonVariants } from './ui/button';
import { useLanguage } from '../context/LanguageContext';
import { twMerge } from 'tailwind-merge';

export const HeaderBar = () => {
  const [contactOpen, setContactOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const { lang, toggleLanguage, t } = useLanguage();
  const email = 'MobileShield@gmail.com';

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(email);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  };

  return (
    <header className="flex items-center justify-between py-4 border-b border-border">
      <div className="flex items-center gap-2 text-text">
        <div className="h-10 w-10 rounded-full bg-primary/15 flex items-center justify-center text-primary">
          <Globe2 size={22} />
        </div>
        <div>
          <p className="text-lg font-bold">MobileShield AI</p>
          <p className="text-xs text-muted">{t.headerTagline}</p>
        </div>
      </div>
      <div className="flex items-center gap-2 relative">
        <Button variant="ghost" size="sm" onClick={toggleLanguage} className="flex items-center gap-1">
          <Languages size={16} />
          {lang === 'he' ? 'EN' : 'עברית'}
        </Button>
        <a
          href="https://www.linkedin.com/in/ophir-braude-188252378/"
          target="_blank"
          rel="noopener noreferrer"
          className={twMerge(buttonVariants({ variant: 'secondary', size: 'sm' }), 'flex items-center gap-1')}
        >
          LinkedIn
        </a>
        <div className="relative">
          <Button variant="primary" size="sm" onClick={() => setContactOpen((o) => !o)} className="flex items-center gap-1">
            <Mail size={16} />
            {t.contact}
          </Button>
          {contactOpen && (
            <div className="absolute right-0 mt-2 w-64 rounded-xl bg-surface border border-border shadow-md z-30 p-3 space-y-2">
              <p className="text-sm font-semibold text-text break-all">{email}</p>
              <div className="flex gap-2">
                <Button variant="secondary" size="sm" onClick={handleCopy} className="flex items-center gap-1">
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                  {copied ? t.copied : t.copy}
                </Button>
                <Button variant="primary" size="sm" className="flex-1" onClick={() => (window.location.href = `mailto:${email}`)}>
                  {t.openEmail}
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
