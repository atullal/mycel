/** Each whitespace-separated term can match anywhere in a name or title. */
export function matchesSearch(query: string, ...values: string[]): boolean {
  const normalize = (value: string) => value.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase();
  const terms = normalize(query).trim().split(/\s+/u).filter(Boolean);
  const text = normalize(values.join(" "));
  return terms.every((term) => text.includes(term));
}
