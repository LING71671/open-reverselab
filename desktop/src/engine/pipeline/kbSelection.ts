import type { SecurityTrack } from "../../core/contracts/track";
import type { KbTechnique } from "../../services/native/nativeBridge";

function normalize(value: string): string {
  return value.toLowerCase().replace(/[-_]+/g, " ").replace(/\s+/g, " ").trim();
}

function containsSignal(query: string, value: string): boolean {
  const signal = normalize(value);
  if (!signal) return false;
  if (/^[a-z0-9 .]+$/.test(signal)) {
    const escaped = signal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`(^|[^a-z0-9])${escaped}($|[^a-z0-9])`).test(query);
  }
  return query.includes(signal);
}

/** Select only indexed paths, including exact counterpart documents in both mode. */
export function selectKbTechniques(
  catalog: KbTechnique[],
  track: SecurityTrack,
  query: string,
  board?: string,
): KbTechnique[] {
  const text = normalize(query);
  const eligible = catalog.filter((item) =>
    (track === "both" || item.track === "both" || item.track === track) &&
    (!board || item.board === board),
  );
  const ranked = eligible.map((item) => {
    const signals = item.signals.filter((signal) => containsSignal(text, signal));
    const titleWords = normalize(`${item.title} ${item.path.split("/").pop() || ""}`)
      .split(/[^\p{L}\p{N}]+/u)
      .filter((word) => word.length > 2 && !/^[0-9]+$/.test(word) && word !== "defense");
    const titleScore = [...new Set(titleWords)].filter((word) => containsSignal(text, word)).length * 4;
    return { item, score: Math.min(signals.length * 5, 50) + titleScore };
  }).filter(({ score }) => score > 0)
    .sort((left, right) => right.score - left.score || left.item.path.localeCompare(right.item.path));

  const selected = new Map<string, KbTechnique>();
  const byPath = new Map(eligible.map((item) => [item.path, item]));
  for (const { item } of ranked) {
    if (selected.has(item.path)) continue;
    if (selected.size >= (track === "both" ? 8 : 4)) break;
    selected.set(item.path, item);
    if (track === "both") {
      for (const path of item.related_paths) {
        const paired = byPath.get(path);
        if (paired && selected.size < 8) selected.set(path, paired);
      }
    }
  }
  return [...selected.values()];
}

export function inferKbBoard(target: string): string | undefined {
  const clean = target.trim().replace(/^["']|["']$/g, "").toLowerCase();
  if (/^https?:\/\//.test(clean)) return "ctf-website";
  if (/\.(exe|dll|sys|msi)$/.test(clean)) return "pe-reverse";
  if (/\.(apk|dex|aab)$/.test(clean)) return "apk-reverse";
  return undefined;
}
