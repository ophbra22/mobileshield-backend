import { Badge } from './ui/badge';

export function StatusPill({ verdict }: { verdict: string }) {
  const variant = verdict === 'safe' ? 'safe' : verdict === 'malicious' ? 'phishing' : 'suspicious';
  const label = verdict === 'malicious' ? 'phishing' : verdict;
  return <Badge variant={variant as any}>{label}</Badge>;
}
