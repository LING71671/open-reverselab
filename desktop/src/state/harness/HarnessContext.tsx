import { createContext, useContext, useState, useEffect, useRef, ReactNode } from "react";
import {
  GraphStep,
  LogEntry,
  DiagnosticItem,
  SessionItem,
  Deliverables,
  HarnessView,
  HarnessMode,
  HarnessChatMessage,
  StageDiagnostic,
  DiscoveredSample,
} from "../../core";
import { logger, diagnosticService, llmService } from "../../services";
import { runOpenSourceAgent } from "../../engine/openSourceAgent";

interface HarnessContextType {
  sessions: SessionItem[];
  activeSessionId: string;
  currentSession?: SessionItem;
  viewMode: HarnessView;
  steps: GraphStep[];
  logs: LogEntry[];
  diagnostics: DiagnosticItem[];
  activeDiagnostics: Record<string, StageDiagnostic>;
  discoveredSamples: DiscoveredSample[];
  messages: HarnessChatMessage[];
  selectedStep: GraphStep | null;
  deliverables: Deliverables | null;
  isRunning: boolean;
  isToolMonitorOpen: boolean;
  executeHarness: (target: string, prompt: string, mode: HarnessMode) => Promise<void>;
  sendChatMessage: (content: string, target?: string) => Promise<void>;
  clearMessages: () => void;
  stopHarness: () => void;
  runDiagnostics: () => Promise<void>;
  clearLogs: () => void;
  newSession: () => void;
  selectSession: (id: string) => void;
  archiveSession: (id: string) => void;
  deleteSession: (id: string) => void;
  selectStep: (step: GraphStep | null) => void;
  setViewMode: (view: HarnessView) => void;
  setToolMonitorOpen: (open: boolean) => void;
  dismissLoot: () => void;
}

const SEED_SESSION_ID = "sess-revo-pro-verified";
const SEED_SAMPLES: DiscoveredSample[] = [
  { name: "RevoUninPro.exe", path: "B:\\Revo Uninstaller Pro\\RevoUninPro.exe", sizeBytes: 25692968, ext: ".exe", type: "PE Executable", isPrimary: true },
  { name: "ruplp.exe", path: "B:\\Revo Uninstaller Pro\\ruplp.exe", sizeBytes: 10103264, ext: ".exe", type: "PE Executable", isPrimary: false },
  { name: "RevoAppBar.exe", path: "B:\\Revo Uninstaller Pro\\RevoAppBar.exe", sizeBytes: 9829168, ext: ".exe", type: "PE Executable", isPrimary: false },
  { name: "unins000.exe", path: "B:\\Revo Uninstaller Pro\\unins000.exe", sizeBytes: 1281912, ext: ".exe", type: "PE Executable", isPrimary: false },
  { name: "RevoSrp.exe", path: "B:\\Revo Uninstaller Pro\\RevoSrp.exe", sizeBytes: 356144, ext: ".exe", type: "PE Executable", isPrimary: false },
  { name: "RUExt.dll", path: "B:\\Revo Uninstaller Pro\\RUExt.dll", sizeBytes: 191968, ext: ".dll", type: "Dynamic Library", isPrimary: false },
  { name: "RevoCmd.exe", path: "B:\\Revo Uninstaller Pro\\RevoCmd.exe", sizeBytes: 190768, ext: ".exe", type: "PE Executable", isPrimary: false },
  { name: "revoflt.sys", path: "B:\\Revo Uninstaller Pro\\revoflt.sys", sizeBytes: 38400, ext: ".sys", type: "Kernel Driver", isPrimary: false },
  { name: "WinAppsDll.dll", path: "B:\\Revo Uninstaller Pro\\WinAppsDll.dll", sizeBytes: 38184, ext: ".dll", type: "Dynamic Library", isPrimary: false },
];

const SEED_SCRIPT = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RevoUninPro.exe 静态取证验证脚本 (pefile + hashlib)"""
import pefile, hashlib, sys, re

TARGET = r"B:\\Revo Uninstaller Pro\\RevoUninPro.exe"
ANTI_DEBUG = [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
              b"NtQueryInformationProcess", b"OutputDebugStringA"]
REG_API = [b"RegCreateKeyExW", b"RegSetValueExW", b"RegDeleteKeyW",
           b"RegOpenKeyExW", b"RegNotifyChangeKeyValue"]

def main():
    data = open(TARGET, "rb").read()
    print(f"[HASH] MD5={hashlib.md5(data).hexdigest()} SHA256={hashlib.sha256(data).hexdigest()}")
    pe = pefile.PE(data=data, fast_load=False)
    print(f"[HEADER] Machine=0x{pe.FILE_HEADER.Machine:04X} EP=0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X} Subsystem={pe.OPTIONAL_HEADER.Subsystem}")
    print("[SECTIONS]")
    for s in pe.sections:
        name = s.Name.rstrip(b"\\x00").decode(errors="replace")
        print(f"  {name:10s} VA=0x{s.VirtualAddress:08X} RawSize=0x{s.SizeOfRawData:08X} Entropy={s.get_entropy():.2f}")
    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode(errors="replace")
        for imp in entry.imports:
            if imp.name:
                imports.setdefault(dll.upper(), set()).add(imp.name.decode(errors="replace"))
    def hit(patterns):
        return [f"{dll}!{a}" for dll, apis in imports.items() for a in apis if any(p.decode() in a for p in patterns)]
    print("[ANTI-DEBUG API]")
    for x in hit(ANTI_DEBUG): print(f"  * {x}")
    print("[REGISTRY API]")
    for x in hit(REG_API): print(f"  * {x}")
    print("[VERDICT] 反调试API=%d 注册表API=%d" % (len(hit(ANTI_DEBUG)), len(hit(REG_API))))

if __name__ == "__main__":
    main()
`;

const SEED_OUTPUT = `[HASH] MD5=1374fc66d7941336511ad0f71ac68420 SHA256=a0488e8b8fd8873802ee8fa9ff2930700435345528505b4ddc836fee9f63b69f
[HEADER] Machine=0x8664 EP=0x0051DD2C Subsystem=2 DllChars=0x8120
[ASLR/DEP] NX=True ASLR=False CFG=False
[SECTIONS]
  .text      VA=0x00001000 RawSize=0x0089AE00 Entropy=6.39
  .rdata     VA=0x0089C000 RawSize=0x0033D600 Entropy=4.59
  .data      VA=0x00BDA000 RawSize=0x0002D400 Entropy=4.38
  .pdata     VA=0x00C45000 RawSize=0x0005CA00 Entropy=6.48
  .gfids     VA=0x00CA2000 RawSize=0x0001C800 Entropy=4.22
  .giats     VA=0x00CBF000 RawSize=0x00000200 Entropy=0.16
  .tls       VA=0x00CC0000 RawSize=0x00000200 Entropy=0.02
  .rsrc      VA=0x00CC1000 RawSize=0x00BFCE00 Entropy=6.77
[ANTI-DEBUG API]
  * KERNEL32.DLL!OutputDebugStringA
  * KERNEL32.DLL!IsDebuggerPresent
[REGISTRY API]
  * ADVAPI32.DLL!RegNotifyChangeKeyValue
  * ADVAPI32.DLL!RegCreateKeyExW
  * ADVAPI32.DLL!RegOpenKeyExW
  * ADVAPI32.DLL!RegSetValueExW
  * ADVAPI32.DLL!RegDeleteKeyW
[REG PATHS (UTF-16)]
  * HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDlls
  * HKLM\\RunOnce
  * HKCU\\ExplorerRun
  * SOFTWARE\\VS Revo Group\\Revo Uninstaller Pro
[VERDICT] 反调试API=2 注册表API=5
`;

const SEED_DELIVERABLES: Deliverables = {
  summary: "【open-reverseLab 攻击网研判结论】目标为合法商业卸载程序 RevoUninPro.exe。反调试调用（IsDebuggerPresent、OutputDebugStringA）为合规商业防逆向壳保护；注册表 API 对应卸载项扫描功能；已自动化执行取证脚本并完成 8 节区及注册表路径验证。",
  flag: "LIKELY-BENIGN / 许可证反逆向防护",
  key: "SHA256: a0488e8b8fd8873802ee8fa9ff2930700435345528505b4ddc836fee9f63b69f",
  script: SEED_SCRIPT,
  executionOutput: {
    success: true,
    stdout: SEED_OUTPUT,
    stderr: "",
    executionTimeMs: 2958,
  },
  savedArtifacts: {
    report_path: "reports/RevoUninPro_analysis.md",
    script_path: "exports/RevoUninPro_forensics.py",
  },
};

const SEED_SESSIONS: SessionItem[] = [
  {
    id: SEED_SESSION_ID,
    target: "B:\\Revo Uninstaller Pro\\RevoUninPro.exe",
    title: "RevoUninPro 深度行为取证研判",
    time: "Verified",
    status: "completed",
  },
];

function loadSessionData(id: string) {
  if (!id) return null;
  try {
    const raw = localStorage.getItem(`reverselab_session_data_${id}`);
    if (raw) return JSON.parse(raw);
  } catch {}
  if (id === SEED_SESSION_ID) {
    return {
      messages: [
        {
          id: "seed-msg-u",
          role: "user",
          content: "深入分析反调试逻辑与注册表挂钩行为",
          target: "B:\\Revo Uninstaller Pro\\RevoUninPro.exe",
          timestamp: Date.now() - 3600000,
        },
        {
          id: "seed-msg-a",
          role: "assistant",
          content:
            "## 【open-reverseLab 攻击网路由诊断】\n" +
            "- **主目标**: `B:\\Revo Uninstaller Pro\\RevoUninPro.exe` (x86_64, GUI)\n" +
            "- **目录套件**: 发现 9 个关联模块（含内核驱动 `revoflt.sys`、代理 `ruplp.exe`、卸载器 `unins000.exe`）\n" +
            "- **攻击网命中**: `04-dynamic-analysis/05-anti-debug-bypass.md` (反调试API), `06-ioc-extraction/08-procmon-patterns.md` (注册表监控)\n\n" +
            "## 【关键证据与行为研判】\n" +
            "1. **反调试调用**: 命中 `KERNEL32.DLL!IsDebuggerPresent` 与 `OutputDebugStringA`，用于商业版本壳保护与异常监控。\n" +
            "2. **注册表挂钩**: 调用 `RegCreateKeyExW`、`RegSetValueExW`、`RegNotifyChangeKeyValue`，对应卸载项扫描与配置持久化。\n" +
            "3. **内核驱动**: `revoflt.sys` 作为微过滤驱动配合 `RUExt.dll` 拦截进程与文件变动。\n\n" +
            "## 【自动化取证执行成品】\n" +
            "底层 Python 脚本已通过测试，输出验证结果如下：",
          model: "TokenRhythm / mimo-v2.6-flash",
          timestamp: Date.now() - 3590000,
          discoveredSamples: SEED_SAMPLES,
          containerDirectory: "B:\\Revo Uninstaller Pro",
          resolvedBinary: "RevoUninPro.exe",
          deliverables: SEED_DELIVERABLES,
          isRunning: false,
        },
      ],
      steps: [
        { id: "step-1", title: "Target Discovery", status: "completed", detail: "Found container and 9 binaries" },
        { id: "step-2", title: "Static Triage", status: "completed", detail: "x86_64 PE, 8 sections, anti-debug APIs" },
        { id: "step-3", title: "KB Routing", status: "completed", detail: "Routed attack-network.md and 4 techniques" },
        { id: "step-4", title: "LLM Reasoning (mimo-v2.6-flash)", status: "completed", detail: "Generated verified forensics script" },
        { id: "step-5", title: "Forensics Execution", status: "completed", detail: "Executed script with exit code 0 (2958ms)" },
      ],
      deliverables: SEED_DELIVERABLES,
      discoveredSamples: SEED_SAMPLES,
      activeDiagnostics: {},
    };
  }
  return null;
}

function saveSessionData(id: string, data: any) {
  if (!id) return;
  try {
    localStorage.setItem(`reverselab_session_data_${id}`, JSON.stringify(data));
  } catch {}
}

const HarnessContext = createContext<HarnessContextType | null>(null);

export function HarnessProvider({ children }: { children: ReactNode }) {
  const [sessions, setSessions] = useState<SessionItem[]>(() => {
    try {
      const saved = localStorage.getItem("reverselab_sessions");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed.map((s) => (s.target === "target.bin" ? { ...s, target: "" } : s));
        }
      }
      return SEED_SESSIONS;
    } catch {
      return SEED_SESSIONS;
    }
  });

  const [activeSessionId, setActiveSessionId] = useState(() => {
    try {
      const saved = localStorage.getItem("reverselab_sessions");
      if (saved) {
        const list = JSON.parse(saved);
        if (Array.isArray(list) && list.length > 0) return list[0].id;
      }
    } catch {
      // ignore
    }
    return SEED_SESSION_ID;
  });

  const initialData = loadSessionData(activeSessionId);
  const [viewMode, setViewMode] = useState<HarnessView>("chat");
  const [steps, setSteps] = useState<GraphStep[]>(() => initialData?.steps || []);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [messages, setMessages] = useState<HarnessChatMessage[]>(() => initialData?.messages || []);
  const [diagnostics, setDiagnostics] = useState<DiagnosticItem[]>(diagnosticService.getCached());
  const [activeDiagnostics, setActiveDiagnostics] = useState<Record<string, StageDiagnostic>>(
    () => initialData?.activeDiagnostics || {}
  );
  const [discoveredSamples, setDiscoveredSamples] = useState<DiscoveredSample[]>(
    () => initialData?.discoveredSamples || []
  );
  const [selectedStep, setSelectedStep] = useState<GraphStep | null>(null);
  const [deliverables, setDeliverables] = useState<Deliverables | null>(
    () => initialData?.deliverables || null
  );
  const [isRunning, setIsRunning] = useState(false);
  const [isToolMonitorOpen, setIsToolMonitorOpen] = useState(false);

  const abortControllerRef = useRef<AbortController | null>(null);

  // Sync active session state to localStorage
  useEffect(() => {
    if (!activeSessionId) return;
    saveSessionData(activeSessionId, {
      messages,
      steps,
      deliverables,
      discoveredSamples,
      activeDiagnostics,
    });
  }, [activeSessionId, messages, steps, deliverables, discoveredSamples, activeDiagnostics]);


  useEffect(() => {
    return logger.subscribe((entry) => {
      setLogs((prev) => [...prev, entry]);
    });
  }, []);

  const currentSession = sessions.find((s) => s.id === activeSessionId);

  const executeHarness = async (target: string, prompt: string, mode: HarnessMode) => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsRunning(true);
    setSteps([]);
    setSelectedStep(null);
    setDeliverables(null);
    setActiveDiagnostics({});
    setDiscoveredSamples([]);


    let currentId = activeSessionId;
    if (!currentId || !sessions.some((s) => s.id === currentId)) {
      currentId = `sess-${Date.now()}`;
      setActiveSessionId(currentId);
      setSessions((prev) => [
        {
          id: currentId,
          target: target || "",
          title: prompt.slice(0, 16) || "新分析",
          time: "Just now",
          status: "running",
        },
        ...prev,
      ]);
    } else {
      setSessions((prev) =>
        prev.map((s) =>
          s.id === currentId
            ? { ...s, target: target || s.target, title: prompt.slice(0, 16), status: "running" }
            : s
        )
      );
    }

    // Initialize conversation stream with User and Assistant messages
    const userMsg: HarnessChatMessage = {
      id: `msg-${Date.now()}-u`,
      role: "user",
      content: prompt,
      target: target || undefined,
      timestamp: Date.now(),
    };
    const activeProvider = llmService.getActiveProvider();
    const modelName = `${activeProvider?.name || "TokenRhythm"} / ${llmService.getModel() || "mimo-v2.6-flash"}`;
    const assistantMsg: HarnessChatMessage = {
      id: `msg-${Date.now()}-a`,
      role: "assistant",
      content: "正在启动逆向分析流程并调用底层探针...",
      model: modelName,
      timestamp: Date.now(),
      toolCalls: [],
      isRunning: true,
    };
    setMessages((prev) => [...prev, userMsg, assistantMsg]);

    logger.info("main", `Starting ${mode.toUpperCase()} session on ${target}: ${prompt}`);

    try {
      const history = messages
        .filter((m) => m.role === "user" || (m.role === "assistant" && !m.isRunning))
        .map((m) => ({
          role: m.role as "user" | "assistant",
          content: m.content,
        }));

      await runOpenSourceAgent(
        target,
        prompt,
        history,
        {
          onToken: (fullText) => {
            setMessages((prev) => {
              if (prev.length === 0) return prev;
              const last = prev[prev.length - 1];
              if (!last || last.role !== "assistant") return prev;
              return [...prev.slice(0, -1), { ...last, content: fullText }];
            });
          },
          onToolCall: (toolRecord) => {
            setMessages((prev) => {
              if (prev.length === 0) return prev;
              const last = prev[prev.length - 1];
              if (!last || last.role !== "assistant") return prev;
              const toolCalls = [...(last.toolCalls || [])];
              const idx = toolCalls.findIndex((t) => t.id === toolRecord.id);
              if (idx >= 0) {
                toolCalls[idx] = toolRecord;
              } else {
                toolCalls.push(toolRecord);
              }
              return [...prev.slice(0, -1), { ...last, toolCalls }];
            });
          },
          onStepNode: (stepNode) => {
            setSteps((prev) => {
              const idx = prev.findIndex((s) => s.id === stepNode.id);
              if (idx >= 0) {
                const next = [...prev];
                next[idx] = stepNode;
                return next;
              }
              return [...prev, stepNode];
            });
          },
          onDeliverables: (deliv) => {
            setDeliverables(deliv);
            setMessages((prev) => {
              if (prev.length === 0) return prev;
              const last = prev[prev.length - 1];
              if (!last || last.role !== "assistant") return prev;
              return [...prev.slice(0, -1), { ...last, deliverables: deliv }];
            });
          },
          onDiagnosticUpdate: (diag) => {
            setActiveDiagnostics((prev) => ({ ...prev, [diag.stageId]: diag }));
            setMessages((prev) => {
              if (prev.length === 0) return prev;
              const last = prev[prev.length - 1];
              if (!last || last.role !== "assistant") return prev;
              const diags = { ...(last.diagnostics || {}), [diag.stageId]: diag };
              return [...prev.slice(0, -1), { ...last, diagnostics: diags }];
            });
          },
          onDiscoveredSamples: (samples, containerDir, primary) => {
            setDiscoveredSamples(samples);
            setMessages((prev) => {
              if (prev.length === 0) return prev;
              const last = prev[prev.length - 1];
              if (!last || last.role !== "assistant") return prev;
              return [
                ...prev.slice(0, -1),
                {
                  ...last,
                  discoveredSamples: samples,
                  containerDirectory: containerDir,
                  resolvedBinary: primary,
                },
              ];
            });
            if (primary || containerDir) {
              setSessions((prev) =>
                prev.map((s) =>
                  s.id === currentId
                    ? {
                        ...s,
                        target: primary ? `${containerDir || ""}\\${primary}` : s.target,
                      }
                    : s
                )
              );
            }
          },
        },
        controller.signal
      );
    } catch (err: any) {
      if (controller.signal.aborted || err?.message === "AbortError") {
        logger.warn("main", "Session execution cancelled by user");
      } else {
        logger.error("main", "Harness execution failed", err);
        setMessages((prev) => {
          if (prev.length === 0) return prev;
          const last = prev[prev.length - 1];
          if (!last || last.role !== "assistant") return prev;
          return [
            ...prev.slice(0, -1),
            {
              ...last,
              content: last.content.includes("异常")
                ? last.content
                : `${last.content}\n\n[执行异常: ${err.message || String(err)}]`,
              isRunning: false,
            },
          ];
        });
      }
    } finally {
      setIsRunning(false);
      abortControllerRef.current = null;
      setSessions((prev) =>
        prev.map((s) => (s.id === currentId ? { ...s, status: "completed" } : s))
      );
      setMessages((prev) => {
        if (prev.length === 0) return prev;
        const last = prev[prev.length - 1];
        if (!last || last.role !== "assistant") return prev;
        return [...prev.slice(0, -1), { ...last, isRunning: false }];
      });
    }
  };

  const sendChatMessage = async (content: string, target?: string) => {
    const tgt = target || currentSession?.target || "";
    await executeHarness(tgt, content, "wish");
  };

  const clearMessages = () => {
    setMessages([]);
  };

  const stopHarness = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setIsRunning(false);
    setSteps((prev) =>
      prev.map((s) =>
        s.status === "running" ? { ...s, status: "failed", detail: "Aborted by user" } : s
      )
    );
    setMessages((prev) => {
      if (prev.length === 0) return prev;
      const last = prev[prev.length - 1];
      if (!last || last.role !== "assistant") return prev;
      return [
        ...prev.slice(0, -1),
        { ...last, isRunning: false, content: last.content + " (已手动中止)" },
      ];
    });
    logger.warn("main", "Analysis halted by user");
    setSessions((prev) =>
      prev.map((s) => (s.id === activeSessionId ? { ...s, status: "idle" } : s))
    );
  };

  const runDiagnostics = async () => {
    const results = await diagnosticService.runFullDiagnostics(currentSession?.target);
    setDiagnostics(results);
  };

  const clearLogs = () => {
    logger.clear();
    setLogs([]);
  };

  useEffect(() => {
    localStorage.setItem("reverselab_sessions", JSON.stringify(sessions));
  }, [sessions]);

  const newSession = () => {
    const id = `sess-${Date.now()}`;
    const item: SessionItem = {
      id,
      target: "",
      title: "新分析",
      time: "Just now",
      status: "idle",
    };
    setSessions((prev) => [item, ...prev]);
    setActiveSessionId(id);
    setSteps([]);
    setSelectedStep(null);
    setDeliverables(null);
    setMessages([]);
    setDiscoveredSamples([]);
    setActiveDiagnostics({});
    logger.info("main", "Created new session");
  };

  const selectSession = (id: string) => {
    setActiveSessionId(id);
    const data = loadSessionData(id);
    setSteps(data?.steps || []);
    setSelectedStep(null);
    setDeliverables(data?.deliverables || null);
    setMessages(data?.messages || []);
    setDiscoveredSamples(data?.discoveredSamples || []);
    setActiveDiagnostics(data?.activeDiagnostics || {});
    logger.info("main", `Selected session ${id}`);
  };

  const archiveSession = (id: string) => {
    setSessions((prev) =>
      prev.map((s) => (s.id === id ? { ...s, isArchived: !s.isArchived } : s))
    );
  };

  const deleteSession = (id: string) => {
    localStorage.removeItem(`reverselab_session_data_${id}`);
    setSessions((prev) => {
      const remaining = prev.filter((s) => s.id !== id);
      if (activeSessionId === id) {
        if (remaining.length > 0) {
          const nextId = remaining[0].id;
          setActiveSessionId(nextId);
          const data = loadSessionData(nextId);
          setSteps(data?.steps || []);
          setSelectedStep(null);
          setDeliverables(data?.deliverables || null);
          setMessages(data?.messages || []);
          setDiscoveredSamples(data?.discoveredSamples || []);
          setActiveDiagnostics(data?.activeDiagnostics || {});
        } else {
          setActiveSessionId("");
          setSteps([]);
          setSelectedStep(null);
          setDeliverables(null);
          setMessages([]);
          setDiscoveredSamples([]);
          setActiveDiagnostics({});
        }
      }
      return remaining;
    });
  };

  return (
    <HarnessContext.Provider
      value={{
        sessions,
        activeSessionId,
        currentSession,
        viewMode,
        steps,
        logs,
        messages,
        diagnostics,
        activeDiagnostics,
        discoveredSamples,
        selectedStep,
        deliverables,
        isRunning,
        isToolMonitorOpen,
        executeHarness,
        sendChatMessage,
        clearMessages,
        stopHarness,
        runDiagnostics,
        clearLogs,
        newSession,
        selectSession,
        archiveSession,
        deleteSession,
        selectStep: setSelectedStep,
        setViewMode,
        setToolMonitorOpen: setIsToolMonitorOpen,
        dismissLoot: () => setDeliverables(null),
      }}
    >
      {children}
    </HarnessContext.Provider>
  );
}

export function useHarness() {
  const ctx = useContext(HarnessContext);
  if (!ctx) throw new Error("useHarness must be used within HarnessProvider");
  return ctx;
}
