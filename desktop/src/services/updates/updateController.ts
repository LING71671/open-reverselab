export type InstallationMode = "installed" | "portable" | "development" | "unsupported" | "browser";
export interface InstallationInfo { version: string; mode: InstallationMode }
export interface Release { version: string; notes: string }
export interface UpdateProgress { downloaded: number; total?: number }
export interface UpdateFailure { code: string; message: string }
export type UpdatePhase = "idle" | "checking" | "current" | "available" | "downloading" | "ready" | "installing" | "error";
export interface UpdatePreferences { automatic: boolean; skippedVersion: string; lastChecked: number }
export interface UpdateSnapshot {
  info: InstallationInfo;
  phase: UpdatePhase;
  release?: Release;
  progress: UpdateProgress;
  preferences: UpdatePreferences;
  error?: UpdateFailure;
}
export interface UpdateAdapter {
  info(): Promise<InstallationInfo>;
  check(): Promise<Release | null>;
  download(onProgress: (progress: UpdateProgress) => void): Promise<void>;
  install(): Promise<void>;
}
export interface UpdateStorage { getItem(key: string): string | null; setItem(key: string, value: string): void }
export const UPDATE_STORAGE_KEY = "reverselab_updates_v1";
export const UPDATE_INTERVAL = 24 * 60 * 60 * 1000;
const defaults: UpdatePreferences = { automatic: true, skippedVersion: "", lastChecked: 0 };
const failure = (error: unknown, fallback: string): UpdateFailure => {
  if (error && typeof error === "object" && "code" in error && "message" in error) return { code: String(error.code), message: String(error.message) };
  return { code: fallback, message: error instanceof Error ? error.message : String(error) };
};

/** Owns update state independently of navigation. Installation always requires an explicit call. */
export class UpdateController {
  private state: UpdateSnapshot;
  private listeners = new Set<() => void>();
  private initialized?: Promise<void>;
  private adapter: UpdateAdapter;
  private storage?: UpdateStorage;
  private workload: () => number;
  private persist: () => Promise<void>;
  constructor(adapter: UpdateAdapter, version: string, storage: UpdateStorage | undefined, workload: () => number, persist: () => Promise<void>) {
    this.adapter = adapter; this.storage = storage; this.workload = workload; this.persist = persist;
    let preferences = { ...defaults };
    try {
      const saved = JSON.parse(storage?.getItem(UPDATE_STORAGE_KEY) || "null");
      if (saved) preferences = { automatic: saved.automatic !== false, skippedVersion: typeof saved.skippedVersion === "string" ? saved.skippedVersion : "", lastChecked: Number.isFinite(saved.lastChecked) ? saved.lastChecked : 0 };
    } catch { /* Damaged preferences do not block manual checks. */ }
    this.state = { info: { version, mode: "browser" }, phase: "idle", progress: { downloaded: 0 }, preferences };
  }
  getSnapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private change(changes: Partial<UpdateSnapshot>) { this.state = { ...this.state, ...changes }; this.listeners.forEach(listener => listener()); }
  private preferences(changes: Partial<UpdatePreferences>) {
    const preferences = { ...this.state.preferences, ...changes };
    try { this.storage?.setItem(UPDATE_STORAGE_KEY, JSON.stringify(preferences)); } catch { /* The current session preference still applies. */ }
    this.change({ preferences });
  }
  initialize = () => this.initialized ||= this.adapter.info().then(info => { this.change({ info }); }).catch(error => { this.change({ phase: "error", error: failure(error, "UPDATE_UNSUPPORTED") }); });
  setAutomatic = (automatic: boolean) => this.preferences({ automatic });
  skip = () => { if (this.state.release && this.state.phase === "available") this.preferences({ skippedVersion: this.state.release.version }); };
  unskip = () => this.preferences({ skippedVersion: "" });
  async check(manual = true, now = Date.now()) {
    await this.initialize();
    if (["checking", "downloading", "ready", "installing"].includes(this.state.phase) || this.state.info.mode === "browser") return;
    if (!manual && (!this.state.preferences.automatic || now - this.state.preferences.lastChecked < UPDATE_INTERVAL)) return;
    this.change({ phase: "checking", error: undefined, release: undefined, progress: { downloaded: 0 } });
    // Failed checks are also throttled, so an unreachable endpoint does not create a retry loop.
    this.preferences({ lastChecked: now });
    try {
      const release = await this.adapter.check();
      if (manual && release?.version === this.state.preferences.skippedVersion) this.preferences({ skippedVersion: "" });
      this.change({ phase: release ? "available" : "current", release: release || undefined });
    } catch (error) { this.change({ phase: "error", error: failure(error, "UPDATE_NETWORK") }); }
  }
  async download() {
    if (this.state.phase !== "available" || this.state.info.mode !== "installed") return;
    this.change({ phase: "downloading", progress: { downloaded: 0 }, error: undefined });
    try {
      await this.adapter.download(progress => this.change({ progress }));
      this.change({ phase: "ready" });
    } catch (error) { this.change({ phase: "available", error: failure(error, "UPDATE_DOWNLOAD") }); }
  }
  async install() {
    if (this.state.phase !== "ready" || this.state.info.mode !== "installed") return;
    if (this.workload()) { this.change({ error: { code: "UPDATE_TASKS_ACTIVE", message: "请等待所有工作区的 Goal 结束后再安装。" } }); return; }
    this.change({ phase: "installing", error: undefined });
    try {
      try { await this.persist(); } catch (error) { throw failure(error, "UPDATE_STORAGE"); }
      if (this.workload()) throw { code: "UPDATE_TASKS_ACTIVE", message: "仍有 Goal 运行或排队，请结束后重试。" };
      await this.adapter.install();
    } catch (error) {
      const classified = failure(error, "UPDATE_INSTALL");
      this.change({ phase: ["UPDATE_TASKS_ACTIVE", "UPDATE_STORAGE", "UPDATE_BUSY"].includes(classified.code) ? "ready" : "available", error: classified });
    }
  }
}
