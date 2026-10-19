/**
 * Unified Native Bridge
 * Seamlessly interfaces with Tauri IPC in native desktop app mode,
 * and with Vite system middleware in browser dev mode.
 */

async function tryTauriInvoke<T>(cmd: string, args?: Record<string, any>): Promise<T | null> {
  try {
    if (typeof window !== "undefined" && (window as any).__TAURI_INTERNALS__) {
      const { invoke } = await import("@tauri-apps/api/core");
      return await invoke<T>(cmd, args);
    }
    return null;
  } catch {
    return null;
  }
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
}

export interface PythonExecResult {
  success: boolean;
  stdout: string;
  stderr: string;
  executionTimeMs?: number;
  durationMs?: number;
}

export class NativeBridge {
  /**
   * Run deep static triage on target file or directory
   */
  public async triage(target: string): Promise<TriageResult> {
    const tauriRes = await tryTauriInvoke<TriageResult>("triage_target", { target });
    if (tauriRes && !tauriRes.error) {
      return tauriRes;
    }

    // Browser dev mode fallback to Vite reverseLabNativePlugin
    try {
      const res = await fetch("/api/system/triage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // offline fallback
    }

    // Pure client fallback heuristic
    const clean = target.replace(/^[ "']+|[ "']+$/g, "");
    const lower = clean.toLowerCase();
    const isPE = lower.endsWith(".exe") || lower.endsWith(".dll") || lower.includes("revo");
    const isAPK = lower.endsWith(".apk") || lower.endsWith(".dex");
    const isWeb = lower.startsWith("http://") || lower.startsWith("https://");

    return {
      board: isPE ? "pe-reverse" : isAPK ? "apk-reverse" : isWeb ? "ctf-website" : "general",
      fileType: isPE ? "Windows PE Binary" : isAPK ? "Android Package" : isWeb ? "Web Target" : "Binary File",
      target: clean,
      targetPath: clean,
    };
  }

  /**
   * Execute real Python script against target binary in host environment
   */
  public async execPython(script: string): Promise<PythonExecResult> {
    const tauriRes = await tryTauriInvoke<any>("run_python_code", { code: script });
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
        body: JSON.stringify({ script }),
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
   * Read markdown technique and attack network documentation
   */
  public async readKb(relativePath: string): Promise<string | null> {
    const tauriRes = await tryTauriInvoke<string>("read_kb_doc", { relativePath });
    if (tauriRes) {
      return tauriRes;
    }

    try {
      const res = await fetch(`/api/system/kb?path=${encodeURIComponent(relativePath)}`);
      if (res.ok) {
        const data = await res.json();
        return data.content || null;
      }
    } catch {
      return null;
    }
    return null;
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
  }): Promise<{ status: string; report_path?: string; script_path?: string }> {
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
