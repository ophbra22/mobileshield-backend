"use client";

import { createContext, useContext, useEffect, useMemo, useState } from 'react';

type Lang = 'he' | 'en';

const translations = {
  he: {
    phishingWarning: 'זהו קישור פישינג. אל תלחץ עליו ואל תזין פרטים אישיים.',
    suspiciousWarning: 'מומלץ לבדוק ידנית את מקור הקישור לפני שממשיכים.',
    benignMessage: 'לא נמצאו סימנים חשודים. הקישור נראה בטוח.',
    scanButton: 'שלח לבדיקה',
    scanning: 'סורק…',
    scanTitle: 'ה-SMS חשוד? סרקו אותו!',
    paste: 'הדבק',
    placeholder: 'הדביקו כאן את ה-SMS או הקישור...',
    malicious: 'פישינג',
    suspicious: 'נראה חשוד',
    benign: 'קישור תקין',
    riskLevel: 'רמת סיכון',
    checking: 'בודק את אבטחת הקישור...',
    headerTagline: 'הגנה חכמה על קישורים ב-SMS',
    copied: 'הועתק',
    copy: 'העתק',
    openEmail: 'פתח מייל',
    contact: 'צור קשר',
  },
  en: {
    phishingWarning: 'This link is highly likely to be a phishing attempt. Do not click or provide any personal information.',
    suspiciousWarning: 'This link shows suspicious indicators. Verify the source before proceeding.',
    benignMessage: 'No suspicious indicators were detected. The link appears safe.',
    scanButton: 'Scan Now',
    scanning: 'Scanning...',
    scanTitle: 'Suspicious SMS? Scan it!',
    paste: 'Paste',
    placeholder: 'Paste the SMS or link here...',
    malicious: 'Phishing',
    suspicious: 'Suspicious',
    benign: 'Safe Link',
    riskLevel: 'Risk level',
    checking: 'Checking link security...',
    headerTagline: 'Smart protection for SMS links',
    copied: 'Copied',
    copy: 'Copy',
    openEmail: 'Open Email',
    contact: 'Contact Us',
  },
} as const;

type LanguageContextType = {
  lang: Lang;
  t: (typeof translations)[Lang];
  toggleLanguage: () => void;
  setLanguage: (lang: Lang) => void;
};

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export const LanguageProvider = ({ children }: { children: React.ReactNode }) => {
  const [lang, setLang] = useState<Lang>('he');

  useEffect(() => {
    const saved = typeof window !== 'undefined' ? (localStorage.getItem('ms_lang') as Lang | null) : null;
    if (saved === 'he' || saved === 'en') setLang(saved);
  }, []);

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = lang;
      document.documentElement.dir = lang === 'he' ? 'rtl' : 'ltr';
      localStorage.setItem('ms_lang', lang);
    }
  }, [lang]);

  const value = useMemo(
    () => ({
      lang,
      t: translations[lang],
      toggleLanguage: () => setLang((prev) => (prev === 'he' ? 'en' : 'he')),
      setLanguage: setLang,
    }),
    [lang]
  );

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
};

export const useLanguage = () => {
  const ctx = useContext(LanguageContext);
  if (!ctx) throw new Error('useLanguage must be used within LanguageProvider');
  return ctx;
};

export const getTranslations = (lang: Lang) => translations[lang];
