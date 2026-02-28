import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#f0f7ff',
          100: '#d9e8ff',
          200: '#b3d0ff',
          300: '#84b5ff',
          400: '#4f92f6',
          500: '#2d73d9',
          600: '#1f57b0',
          700: '#17428a',
          800: '#12346c',
          900: '#0d2752',
        },
      },
      boxShadow: {
        card: '0 15px 40px rgba(0,0,0,0.08)',
      },
    },
  },
  plugins: [],
};

export default config;
