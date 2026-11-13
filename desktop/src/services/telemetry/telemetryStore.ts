import { HEALTH_CODES, HEALTH_LAYERS } from "../../core/contracts/health.ts";
import type { HealthEvent } from "../../core/contracts/health.ts";

export interface TelemetryPreferences { enabled: boolean; traceSampleRate: number }
const key = "reverselab_remote_diagnostics";
let preferences: TelemetryPreferences = { enabled: false, traceSampleRate: 0 };
let restored = false;
try {
  const saved = JSON.parse(localStorage.getItem(key) || "null");
  if (saved && typeof saved.enabled === "boolean" && Number.isFinite(saved.traceSampleRate) && saved.traceSampleRate >= 0 && saved.traceSampleRate <= 1) { preferences = saved; restored = true; }
} catch { /* Default to local-only operation. */ }
const listeners = new Set<() => void>();
export function configureTelemetryDefaults(defaults: TelemetryPreferences) {
  if (!Number.isFinite(defaults.traceSampleRate) || defaults.traceSampleRate < 0 || defaults.traceSampleRate > 1) throw new Error("Invalid remote diagnostic policy");
  if (!restored) preferences = Object.freeze({ enabled: defaults.enabled === true, traceSampleRate: defaults.traceSampleRate });
}
export const telemetryPreference = {
  getSnapshot: () => preferences,
  subscribe(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; },
  set(next: TelemetryPreferences) {
    if (typeof next.enabled !== "boolean" || !Number.isFinite(next.traceSampleRate) || next.traceSampleRate < 0 || next.traceSampleRate > 1) throw new Error("采样比例应在 0% 到 100% 之间");
    preferences = Object.freeze({ enabled: next.enabled, traceSampleRate: next.traceSampleRate });
    restored = true;
    try { localStorage.setItem(key, JSON.stringify(preferences)); } catch { /* Session-only preference. */ }
    for (const listener of listeners) listener();
  },
};

export interface Diagnostic { layer: string; code?: string; status: string; durationMs?: number }
let receiver: ((event: Diagnostic) => void) | undefined;
export function setDiagnosticReceiver(next?: (event: Diagnostic) => void) { receiver = next; }
export function reportHealth(event: HealthEvent) {
  if (!preferences.enabled || !receiver || !HEALTH_LAYERS.includes(event.layer)) return;
  // IDs, paths, messages, evidence and arbitrary attributes never cross this boundary.
  const diagnostic: Diagnostic = { layer: event.layer, status: event.status };
  if (event.code && HEALTH_CODES.includes(event.code)) diagnostic.code = event.code;
  if (Number.isFinite(event.durationMs) && event.durationMs! >= 0) diagnostic.durationMs = event.durationMs;
  try { receiver(diagnostic); } catch { /* Diagnostics cannot interrupt a Goal. */ }
}
