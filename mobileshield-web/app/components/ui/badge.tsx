import { cva, type VariantProps } from 'class-variance-authority';
import { twMerge } from 'tailwind-merge';

const badgeVariants = cva('inline-flex items-center rounded-full px-3.5 py-1.5 text-sm font-semibold', {
  variants: {
    variant: {
      safe: 'bg-success/10 text-success border border-success/20',
      suspicious: 'bg-warning/10 text-warning border border-warning/20',
      phishing: 'bg-danger/10 text-danger border border-danger/20',
      neutral: 'bg-surface2 text-muted border border-border',
    },
  },
  defaultVariants: {
    variant: 'neutral',
  },
});

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={twMerge(badgeVariants({ variant }), className)} {...props} />;
}

export { badgeVariants };
