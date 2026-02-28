import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'MobileShield AI | URL Risk Scanner',
  description: 'Assess SMS links in seconds with MobileShield AI.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
