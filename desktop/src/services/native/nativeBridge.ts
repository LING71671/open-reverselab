/**
 * Unified Native Bridge
 * Seamlessly interfaces with Tauri IPC in native desktop app mode,
 * and with Vite system middleware in browser dev mode.
 */
import type { SecurityTrack } from "../../core/contracts/track";

async function tryTauriInvoke<T>(cmd: string, args?: Record<string, any>): Promise<T | null> {
  if (typeof window !== "undefined" && (window as any).__TAURI_INTERNALS__) {
    const { invoke } = await import("@tauri-apps/api/core");
    return await invoke<T>(cmd, args);
  }
  return null;
}

export interface KbTechnique {
  id: string;
  board: string;
  title: string;
  category: string;
  signals: string[];
  mcp_tools: string[];
  path: string;
  track: SecurityTrack;
  related_paths: string[];
}

export interface TriageResult {
  board: string;
  fileType: string;
  target?: string;
  targetPath?: string;
  resolvedBinary?: string;
  containerDirectory?: string;
  arch?: string;
  compiler?: string;
  subsystem?: string;
  packer?: string;
  entryPoint?: string;
  sha256?: string;
  md5?: string;
  sha1?: string;
  sizeBytes?: number;
  sections?: Array<{
    name: string;
    entropy: number;
    virtualSize: string;
    rawSize: number;
    isExecutable: boolean;
  }>;
  executableSections?: string[];
  importedDlls?: string[];
  isContainerDirectory?: boolean;
  discoveredSamples?: Array<{
    name: string;
    path: string;
    sizeBytes: number;
    ext: string;
    type: string;
    isPrimary?: boolean;
  }>;
  capabilities?: Record<string, string[]>;
  stringsSample?: string[];
  error?: string;
  parseWarning?: string;
  httpError?: string;
  httpStatus?: number;
  targetUrl?: string;
}

export interface PythonExecResult {
  success: boolean;
  stdout: string;
  stderr: string;
  executionTimeMs?: number;
  durationMs?: number;
}

export class NativeBridge {
  public async workspace<T>(request: Record<string, unknown>): Promise<T> {
    const native = await tryTauriInvoke<T>("workspace_operation", { request });
    if (native !== null) return native;
    const response = await fetch("/api/workspace", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request) });
    const payload = await response.json();
    if (!response.ok || payload?.error) throw new Error(payload.error || `Workspace HTTP ${response.status}`);
    return payload as T;
  }
  /**
   * Run deep static triage on target file or directory
   */
  public async triage(target: string, options: { timeoutMs?: number; signal?: AbortSignal; executionId?: string } = {}): Promise<TriageResult> {
    if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
    const executionId = options.executionId || crypto.randomUUID();
    const timeoutMs = Math.max(1, Math.min(15000, Math.floor(options.timeoutMs || 15000)));
    const cancel = () => { void tryTauriInvoke("cancel_python_execution", { executionId }).catch(() => {}); };
    options.signal?.addEventListener("abort", cancel, { once: true });
    let tauriRes;
    try { tauriRes = await tryTauriInvoke<TriageResult>("triage_target", { target, timeoutMs, executionId }); }
    finally { options.signal?.removeEventListener("abort", cancel); }
    if (tauriRes) {
      if (tauriRes.error) throw new Error(tauriRes.error);
      return tauriRes;
    }

    // Browser dev mode fallback to Vite reverseLabNativePlugin
    try {
      const res = await fetch("/api/system/triage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, timeoutMs }),
        signal: options.signal,
      });
      if (res.ok) {
        const data: TriageResult = await res.json();
        if (data.error) throw new Error(data.error);
        return data;
      }
      throw new Error(`Triage service returned HTTP ${res.status}`);
    } catch (error) {
      throw new Error(`Target triage unavailable: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Execute real Python script against target binary in host environment
   */
  public async execPython(script: string, options: { timeoutMs?: number; executionId?: string; signal?: AbortSignal } = {}): Promise<PythonExecResult> {
    if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
    const executionId = options.executionId || crypto.randomUUID();
    const timeoutMs = Math.max(1, Math.min(60000, Math.floor(options.timeoutMs || 15000)));
    const cancel = () => { void tryTauriInvoke("cancel_python_execution", { executionId }).catch(() => {}); };
    options.signal?.addEventListener("abort", cancel, { once: true });
    let tauriRes;
    try { tauriRes = await tryTauriInvoke<any>("run_python_code", { code: script, timeoutMs, executionId }); }
    finally { options.signal?.removeEventListener("abort", cancel); }
    if (tauriRes) {
      return {
        success: tauriRes.success,
        stdout: tauriRes.stdout || "",
        stderr: tauriRes.stderr || "",
        executionTimeMs: tauriRes.execution_time_ms,
      };
    }

    try {
      const res = await fetch("/api/system/exec-python", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ script, timeoutMs, executionId }),
        signal: options.signal,
      });
      if (res.ok) {
        const data = await res.json();
        return {
          success: data.success,
          stdout: data.stdout || "",
          stderr: data.stderr || "",
          executionTimeMs: data.executionTimeMs || data.durationMs,
        };
      }
    } catch {
      // offline fallback
    }

    return {
      success: false,
      stdout: "",
      stderr: "Execution service unavailable",
    };
  }

  /**
   * List the repository's indexed techniques for the selected track.
   */
  public async listKb(track: SecurityTrack = "blue"): Promise<KbTechnique[]> {
    const tauriRes = await tryTauriInvoke<KbTechnique[]>("list_kb_techniques", { track });
    if (tauriRes !== null) return tauriRes;

    const res = await fetch(`/api/kb/techniques?track=${encodeURIComponent(track)}`);
    if (!res.ok) throw new Error(`Knowledge base unavailable (HTTP ${res.status})`);
    const data: unknown = await res.json();
    if (!Array.isArray(data)) throw new Error("Invalid knowledge base catalog response");
    return data as KbTechnique[];
  }

  /**
   * Read a repository knowledge base document.
   */
  public async readKb(relativePath: string): Promise<string | null> {
    const tauriRes = await tryTauriInvoke<string>("read_kb_doc", { relativePath });
    if (tauriRes !== null) {
      return tauriRes;
    }

    const res = await fetch(`/api/kb/doc?path=${encodeURIComponent(relativePath)}`);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`Knowledge base document unavailable (HTTP ${res.status})`);
    const data = await res.json();
    if (typeof data.content !== "string") throw new Error("Invalid knowledge base document response");
    return data.content;
  }

  /**
   * Persist analysis report and script to reports/ and exports/
   */
  public async saveReport(data: {
    target: string;
    summary: string;
    script: string;
    key?: string;
    flag?: string;
    track?: SecurityTrack;
    executionOutput?: PythonExecResult;
    goalId?: string;
    attempt?: number;
    workspaceRoot?: string;
    goalVerification?: unknown;
  }): Promise<{ status: string; report_path?: string; script_path?: string }> {
    if (data.workspaceRoot) return this.workspace({ action: "report", root: data.workspaceRoot, report: data });
    const tauriRes = await tryTauriInvoke<any>("save_analysis_report", data);
    if (tauriRes && tauriRes.status === "saved") {
      return tauriRes;
    }

    try {
      const res = await fetch("/api/system/save-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // ignore
    }

    return { status: "offline" };
  }
}

export const nativeBridge = new NativeBridge();
