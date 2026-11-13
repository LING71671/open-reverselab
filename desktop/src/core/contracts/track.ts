export const SECURITY_TRACKS = ["red", "blue", "both"] as const;
export type SecurityTrack = (typeof SECURITY_TRACKS)[number];

export function isSecurityTrack(value: unknown): value is SecurityTrack {
  return SECURITY_TRACKS.some((track) => track === value);
}

export function matchesTrack(track: SecurityTrack, selected: SecurityTrack): boolean {
  return selected === "both" || track === "both" || track === selected;
}
