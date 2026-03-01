import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'MobileShield AI | URL Risk Scanner',
  description: 'Assess SMS links in seconds with MobileShield AI.',
  icons: [{ rel: 'icon', url: '/favicon.svg' }],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="he" dir="rtl">
      <body className="bg-bg text-text">{children}</body>
    </html>
  );
}
