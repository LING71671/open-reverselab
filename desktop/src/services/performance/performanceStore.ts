const key = "reverselab_performance_monitor";
let enabled = false;
try { enabled = localStorage.getItem(key) === "true"; } catch { /* Session preference. */ }
const listeners = new Set<() => void>();
export const performancePreference = {
  getSnapshot: () => enabled,
  subscribe: (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; },
  setEnabled(value: boolean) { enabled = value; try { localStorage.setItem(key, String(value)); } catch { /* Session preference. */ } for (const listener of listeners) listener(); },
};
