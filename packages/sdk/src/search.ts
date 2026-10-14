// Local filtering for search fields (contacts, people nearby, conversations).
// Nothing here leaves the device.

/**
 * True when every whitespace-separated term of `query` appears somewhere in
 * `values`, ignoring case and accents ("zoe" finds "Zoë"). An empty query
 * matches everything.
 */
export function matchesSearch(query: string, ...values: string[]): boolean {
  const normalize = (value: string) => value.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase();
  const terms = normalize(query).trim().split(/\s+/u).filter(Boolean);
  const text = normalize(values.join(" "));
  return terms.every((term) => text.includes(term));
}
