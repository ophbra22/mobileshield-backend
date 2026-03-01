export function RiskMeter({ score }: { score: number }) {
  const display = score > 25 ? Math.ceil(score) : score;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-[var(--muted)]">
        <span>Risk score</span>
        <span>{display}</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100">
        <div
          className="h-full rounded-full bg-gradient-to-r from-green-500 via-amber-400 to-red-500"
          style={{ width: `${Math.min(display, 100)}%` }}
        />
      </div>
    </div>
  );
}
