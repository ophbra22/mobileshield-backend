export function extractUrls(text: string): string[] {
  const urlRegex =
    /https?:\/\/(?:www\.)?[^\s/$.?#].[^\s]*/gi;
  const matches = text.match(urlRegex);
  if (!matches) return [];
  // de-duplicate
  return Array.from(new Set(matches));
}
