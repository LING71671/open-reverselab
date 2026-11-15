/**
 * Unified Native Bridge
 * Seamlessly interfaces with Tauri IPC in native desktop app mode,
 * and with Vite system middleware in browser dev mode.
 */
import type { SecurityTrack } from "../../core/contracts/track";
import { HealthFault } from "../../core/contracts/health";
import { executionTimeout, type ExecutionOptions } from "../../core/contracts/execution";
import { proxyPool, nativeRoute, usesNativeNetwork } from "../network/networkService";

function toolRoute() {
  const route = proxyPool.routes("tools")[0];
  if (!usesNativeNetwork() && route.mode !== "system") throw new Error("PROXY_CONFIG: 指定 Python 代理需要桌面应用");
  return nativeRoute(route);
}

async function tryTauriInvoke<T>(cmd: string, args?: Record<string, any>): Promise<T | undefined> {
  if (typeof window !== "undefined" && (window as any).__TAURI_INTERNALS__) {
    const { invoke } = await import("@tauri-apps/api/core");
    return await invoke<T>(cmd, args);
  }
  // JSON null is a valid native result (for example, a workspace without history).
  return undefined;
}

async function tryTauriExecution<T>(cmd: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<T | null> {
  if (typeof window === "undefined" || !(window as any).__TAURI_INTERNALS__) return null;
  const { invoke, Channel } = await import("@tauri-apps/api/core");
  if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
  const cancel = () => { void invoke("cancel_python_execution", { executionId: args.executionId }).catch(() => {}); };
  const onStarted = new Channel<{ kind: "started" }>();
  // Cancellation may arrive before Rust registers the execution. Reassert it
  // once the registration is acknowledged, including before the worker starts.
  onStarted.onmessage = () => { if (signal?.aborted) cancel(); };
  signal?.addEventListener("abort", cancel, { once: true });
  try {
    const result = await invoke<T>(cmd, { ...args, onStarted });
    if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
    return result;
  } catch (error) {
    if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
    throw error;
  } finally { signal?.removeEventListener("abort", cancel); }
}

export interface KbTechnique {
  entityId?: string;
  installationId?: string;
  packId?: string;
  packVersion?: string;
  digest?: string;
  methodIds?: string[];
  networkIds?: string[];
  aliases?: string[];
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
  /** Local package and MCP services share their cancellable JSON protocol in both hosts. */
  private async extensionService<T>(service: "extensions" | "mcp", request: Record<string, unknown>, options: ExecutionOptions = {}): Promise<T> {
    if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
    const executionId = options.executionId || crypto.randomUUID();
    const timeoutMs = executionTimeout(options.timeoutMs);
    let payload = await tryTauriExecution<unknown>(`${service}_operation`, { request, executionId, timeoutMs }, options.signal);
    if (payload === null) {
      const response = await fetch(`/api/${service}`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request, timeoutMs }), signal: options.signal,
      });
      try { payload = await response.json(); }
      catch { throw new Error(`${service} 服务响应无效（HTTP ${response.status}）`); }
      if (!response.ok && !(payload as { error?: unknown })?.error) throw new Error(`${service} 服务不可用（HTTP ${response.status}）`);
    }
    const error = (payload as { error?: string | { message?: string; code?: string; outcome?: string } })?.error;
    if (error) {
      if (typeof error === "string") throw new Error(error);
      throw Object.assign(new Error(error.message || "扩展操作失败"), { code: error.code, outcome: error.outcome });
    }
    return payload as T;
  }

  public extensions<T>(request: Record<string, unknown>, options: ExecutionOptions = {}): Promise<T> { return this.extensionService<T>("extensions", request, options); }
  public mcp<T>(request: Record<string, unknown>, options: ExecutionOptions = {}): Promise<T> { return this.extensionService<T>("mcp", request, options); }

  public async workspace<T>(request: Record<string, unknown>): Promise<T> {
    const native = await tryTauriInvoke<T>("workspace_operation", { request });
    if (native !== undefined) return native;
    const response = await fetch("/api/workspace", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request) });
    let payload;
    try { payload = await response.json(); }
    catch { throw new Error(`工作区服务响应无效（HTTP ${response.status}），请确认本地服务已启动`); }
    if (!response.ok || payload?.error) throw new Error(payload?.error || `Workspace HTTP ${response.status}`);
    return payload as T;
  }
  /**
   * Run deep static triage on target file or directory
   */
  public async triage(target: string, options: ExecutionOptions = {}): Promise<TriageResult> {
    if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
    const executionId = options.executionId || crypto.randomUUID();
    const timeoutMs = executionTimeout(options.timeoutMs);
    const tauriRes = await tryTauriExecution<TriageResult>("triage_target", { target, timeoutMs, executionId, route: toolRoute() }, options.signal);
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
      if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
      throw new Error(`Target triage unavailable: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Execute real Python script against target binary in host environment
   */
  public async execPython(script: string, options: ExecutionOptions = {}): Promise<PythonExecResult> {
    if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
    const executionId = options.executionId || crypto.randomUUID();
    const timeoutMs = executionTimeout(options.timeoutMs);
    const tauriRes = await tryTauriExecution<any>("run_python_code", { code: script, timeoutMs, executionId, route: toolRoute() }, options.signal);
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
      throw new HealthFault("TOOL_UNAVAILABLE", `Python execution service returned HTTP ${res.status}`);
    } catch (error) {
      if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
      if (error instanceof HealthFault) throw error;
      throw new HealthFault("TOOL_UNAVAILABLE", `Python execution service unavailable: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * List the repository's indexed techniques for the selected track.
   */
  public async listKb(track: SecurityTrack = "blue"): Promise<KbTechnique[]> {
    const tauriRes = await tryTauriInvoke<KbTechnique[]>("list_kb_techniques", { track });
    if (tauriRes !== undefined) return tauriRes;

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
    const tauriRes = await tryTauriInvoke<string | null>("read_kb_doc", { relativePath });
    if (tauriRes !== undefined) {
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
