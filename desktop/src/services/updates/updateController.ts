export type InstallationMode = "installed" | "portable" | "development" | "unsupported" | "browser";
export interface InstallationInfo { version: string; mode: InstallationMode }
export type UpdateChannel = "stable" | "beta";
export interface Release { version: string; notes: string; url: string }
export interface UpdateCheck { status: "available" | "current" | "unpublished"; release?: Release }
export interface UpdateProgress { downloaded: number; total?: number }
export interface UpdateFailure { code: string; message: string }
export type UpdatePhase = "idle" | "checking" | "current" | "unpublished" | "available" | "downloading" | "ready" | "installing" | "error";
export interface UpdatePreferences { automatic: boolean; channel: UpdateChannel; skippedVersion: string; lastChecked: number }
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
  check(channel: UpdateChannel): Promise<UpdateCheck>;
  download(onProgress: (progress: UpdateProgress) => void): Promise<void>;
  install(): Promise<void>;
}
export interface UpdateStorage { getItem(key: string): string | null; setItem(key: string, value: string): void }
export const UPDATE_STORAGE_KEY = "reverselab_updates_v1";
export const UPDATE_INTERVAL = 24 * 60 * 60 * 1000;
const defaultChannel = (version: string): UpdateChannel => version.split("+")[0].includes("-") ? "beta" : "stable";
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
    let preferences: UpdatePreferences = { automatic: true, channel: defaultChannel(version), skippedVersion: "", lastChecked: 0 };
    try {
      const saved = JSON.parse(storage?.getItem(UPDATE_STORAGE_KEY) || "null");
      if (saved) {
        const sameChannel = saved.channel === "stable" || saved.channel === "beta" || preferences.channel === "stable";
        preferences = { automatic: saved.automatic !== false, channel: saved.channel === "stable" || saved.channel === "beta" ? saved.channel : preferences.channel, skippedVersion: sameChannel && typeof saved.skippedVersion === "string" ? saved.skippedVersion : "", lastChecked: sameChannel && Number.isFinite(saved.lastChecked) ? saved.lastChecked : 0 };
      }
    } catch { /* Damaged preferences do not block manual checks. */ }
    this.state = { info: { version, mode: "browser" }, phase: "idle", progress: { downloaded: 0 }, preferences };
  }
  getSnapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private change(changes: Partial<UpdateSnapshot>) { this.state = { ...this.state, ...changes }; this.listeners.forEach(listener => listener()); }
  private preferences(changes: Partial<UpdatePreferences>, snapshot: Partial<UpdateSnapshot> = {}) {
    const preferences = { ...this.state.preferences, ...changes };
    try { this.storage?.setItem(UPDATE_STORAGE_KEY, JSON.stringify(preferences)); } catch { /* The current session preference still applies. */ }
    this.change({ ...snapshot, preferences });
  }
  initialize = () => this.initialized ||= this.adapter.info().then(info => { this.change({ info }); }).catch(error => { this.change({ phase: "error", error: failure(error, "UPDATE_UNSUPPORTED") }); });
  setAutomatic = (automatic: boolean) => this.preferences({ automatic });
  setChannel = (channel: UpdateChannel) => {
    if (!["stable", "beta"].includes(channel) || channel === this.state.preferences.channel || ["checking", "downloading", "installing"].includes(this.state.phase)) return;
    // A package belongs to the channel that was checked; switching requires a fresh check.
    this.preferences({ channel, skippedVersion: "", lastChecked: 0 }, { phase: "idle", release: undefined, progress: { downloaded: 0 }, error: undefined });
  };
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
      const result = await this.adapter.check(this.state.preferences.channel);
      const release = result.release;
      if (result.status === "available" && !release) throw { code: "UPDATE_MANIFEST", message: "The update service returned no release for an available update" };
      if (manual && release?.version === this.state.preferences.skippedVersion) this.preferences({ skippedVersion: "" });
      this.change({ phase: result.status, release: result.status === "available" ? release : undefined });
    } catch (error) { this.change({ phase: "error", error: failure(error, "UPDATE_NETWORK") }); }
  }
  async download() {
    if (this.state.phase !== "available" || this.state.info.mode !== "installed") return;
    const release = this.state.release;
    this.change({ phase: "downloading", progress: { downloaded: 0 }, error: undefined });
    try {
      await this.adapter.download(progress => {
        if (this.state.phase === "downloading" && this.state.release === release) this.change({ progress });
      });
      this.change({ phase: "ready" });
    } catch (error) { this.change({ phase: "available", error: failure(error, "UPDATE_DOWNLOAD") }); }
  }
  async install() {
    if (this.state.phase !== "ready" || this.state.info.mode !== "installed") return;
    if (this.workload()) { this.change({ error: { code: "UPDATE_TASKS_ACTIVE", message: "请等待所有工作区的 Goal 结束后再安装。" } }); return; }
    this.change({ phase: "installing", error: undefined });
    let installerInvoked = false;
    try {
      try { await this.persist(); } catch (error) { throw failure(error, "UPDATE_STORAGE"); }
      if (this.workload()) throw { code: "UPDATE_TASKS_ACTIVE", message: "仍有 Goal 运行或排队，请结束后重试。" };
      installerInvoked = true;
      await this.adapter.install();
    } catch (error) {
      const classified = failure(error, "UPDATE_INSTALL");
      const retained = ["UPDATE_TASKS_ACTIVE", "UPDATE_BUSY"].includes(classified.code) || (classified.code === "UPDATE_STORAGE" && !installerInvoked);
      this.change({ phase: retained ? "ready" : "available", error: classified });
    }
  }
}
