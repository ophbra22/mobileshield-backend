"use client";

import { useState } from 'react';
import { Globe2, LogIn, LogOut, UserRound, KeyRound, Settings, Languages } from 'lucide-react';
import { Button } from './ui/button';

interface Props {
  onLoginClick: () => void;
  onLogout: () => void;
  onOpenKeys: () => void;
  onOpenSettings: () => void;
  isAuthenticated: boolean;
  lang: 'he' | 'en';
  onToggleLang: () => void;
}

export const HeaderBar = ({
  onLoginClick,
  onLogout,
  onOpenKeys,
  onOpenSettings,
  isAuthenticated,
  lang,
  onToggleLang,
}: Props) => {
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <header className="flex items-center justify-between py-4 border-b border-border">
      <div className="flex items-center gap-2 text-text">
        <div className="h-10 w-10 rounded-full bg-primary/15 flex items-center justify-center text-primary">
          <Globe2 size={22} />
        </div>
        <div>
          <p className="text-lg font-bold">MobileShield AI</p>
          <p className="text-xs text-muted">הגנה חכמה על קישורים ב-SMS</p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={onToggleLang} className="flex items-center gap-1">
          <Languages size={16} />
          {lang === 'he' ? 'עברית' : 'EN'}
        </Button>
        <Button variant="secondary" size="sm" onClick={onOpenSettings} className="flex items-center gap-1">
          <Settings size={16} />
          הגדרות
        </Button>
        <div className="relative">
          <Button variant="primary" size="sm" onClick={() => setMenuOpen((o) => !o)} className="flex items-center gap-1">
            <UserRound size={16} />
            {isAuthenticated ? 'החשבון שלי' : 'התחברות'}
          </Button>
          {menuOpen && (
            <div className="absolute left-0 mt-2 w-44 rounded-xl bg-surface border border-border shadow-md z-20 text-sm">
              {!isAuthenticated && (
                <button
                  onClick={() => {
                    onLoginClick();
                    setMenuOpen(false);
                  }}
                  className="w-full flex items-center gap-2 px-3 py-2 hover:bg-surface2 text-text"
                >
                  <LogIn size={16} /> כניסה / הרשמה
                </button>
              )}
              {isAuthenticated && (
                <>
                  <button
                    onClick={() => {
                      onOpenKeys();
                      setMenuOpen(false);
                    }}
                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-surface2 text-text"
                  >
                    <KeyRound size={16} /> המפתחות שלי
                  </button>
                  <button
                    onClick={() => {
                      onLogout();
                      setMenuOpen(false);
                    }}
                    className="w-full flex items-center gap-2 px-3 py-2 hover:bg-surface2 text-text"
                  >
                    <LogOut size={16} /> יציאה
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
