import React, { useState } from 'react';
import { twMerge } from 'tailwind-merge';
import { ChevronDown } from 'lucide-react';

interface AccordionProps {
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}

export const Accordion: React.FC<AccordionProps> = ({ title, children, defaultOpen }) => {
  const [open, setOpen] = useState(!!defaultOpen);
  return (
    <div className="border border-[var(--border)] rounded-xl">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-3 py-2 text-sm font-semibold text-[var(--text)]"
      >
        <span>{title}</span>
        <ChevronDown size={18} className={twMerge('transition-transform', open ? 'rotate-180' : '')} />
      </button>
      {open && <div className="border-t border-[var(--border)] px-3 py-2 text-sm text-[var(--muted)]">{children}</div>}
    </div>
  );
};
