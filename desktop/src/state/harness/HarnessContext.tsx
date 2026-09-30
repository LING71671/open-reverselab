import { createContext, useContext, useState, useEffect, useCallback, useRef, ReactNode } from "react";
import { GraphStep, LogEntry, DiagnosticItem, SessionItem, Deliverables, HarnessView, HarnessMode } from "../../core";
import { logger, diagnosticService } from "../../services";
import { createHarnessEngine } from "../../engine/harnessGraph";

interface HarnessContextType {
  sessions: SessionItem[];
  activeSessionId: string;
  currentSession?: SessionItem;
  viewMode: HarnessView;
  steps: GraphStep[];
  logs: LogEntry[];
  diagnostics: DiagnosticItem[];
  selectedStep: GraphStep | null;
  deliverables: Deliverables | null;
  isRunning: boolean;
  isToolMonitorOpen: boolean;
  executeHarness: (target: string, prompt: string, mode: HarnessMode) => Promise<void>;
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

const INITIAL_SESSIONS: SessionItem[] = [];

const HarnessContext = createContext<HarnessContextType | null>(null);

export function HarnessProvider({ children }: { children: ReactNode }) {
  const [sessions, setSessions] = useState<SessionItem[]>(() => {
    try {
      const saved = localStorage.getItem("reverselab_sessions");
      return saved ? JSON.parse(saved) : INITIAL_SESSIONS;
    } catch {
      return INITIAL_SESSIONS;
    }
  });
  const [activeSessionId, setActiveSessionId] = useState(() => {
    try {
      const saved = localStorage.getItem("reverselab_sessions");
      if (saved) {
        const list = JSON.parse(saved);
        if (list.length > 0) return list[0].id;
      }
    } catch {
      // ignore
    }
    return "";
  });
  const [viewMode, setViewMode] = useState<HarnessView>("canvas");
  const [steps, setSteps] = useState<GraphStep[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [diagnostics, setDiagnostics] = useState<DiagnosticItem[]>(diagnosticService.getCached());
  const [selectedStep, setSelectedStep] = useState<GraphStep | null>(null);
  const [deliverables, setDeliverables] = useState<Deliverables | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [isToolMonitorOpen, setIsToolMonitorOpen] = useState(false);

  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    return logger.subscribe((entry) => {
      setLogs((prev) => [...prev, entry]);
    });
  }, []);

  const currentSession = sessions.find((s) => s.id === activeSessionId);

  const handleGraphEvent = useCallback(
    (event: { type: "NODE_EVENT" | "LOOT_REVEAL"; step?: GraphStep; deliverables?: any }) => {
      if (event.type === "NODE_EVENT" && event.step) {
        const step = event.step;
        setSteps((prev) => {
          const idx = prev.findIndex((s) => s.id === step.id);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = step;
            return next;
          }
          return [...prev, step];
        });

        if (step.status === "running") {
          logger.tool(step.agentId, `${step.title}: ${step.detail}`, undefined, { kbRef: step.kbRef });
        } else if (step.status === "done" && step.evidence) {
          logger.evidence(step.agentId, step.title, step.evidence);
        }
      } else if (event.type === "LOOT_REVEAL" && event.deliverables) {
        setDeliverables(event.deliverables);
        logger.info("main", "Mission complete. Deliverables card generated.", event.deliverables);
      }
    },
    []
  );

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

    let currentId = activeSessionId;
    if (!currentId || !sessions.some((s) => s.id === currentId)) {
      currentId = `sess-${Date.now()}`;
      setActiveSessionId(currentId);
      setSessions((prev) => [
        {
          id: currentId,
          target: target || "target.bin",
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

    logger.info("main", `Starting ${mode.toUpperCase()} session on ${target}: ${prompt}`);

    try {
      const app = createHarnessEngine(handleGraphEvent, controller.signal);
      await app.invoke(
        {
          target,
          wish: prompt,
          board: "",
          triageInfo: {},
          steps: [],
          deliverables: {},
          isCompleted: false,
        },
        {
          recursionLimit: 50,
          configurable: { thread_id: `harness-${Date.now()}` },
        }
      );
    } catch (err: any) {
      if (controller.signal.aborted || err?.message === "AbortError") {
        logger.warn("main", "Session execution cancelled by user");
      } else {
        logger.error("main", "Harness execution failed", err);
      }
    } finally {
      setIsRunning(false);
      abortControllerRef.current = null;
      setSessions((prev) =>
        prev.map((s) => (s.id === currentId ? { ...s, status: "completed" } : s))
      );
    }
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
    try {
      localStorage.setItem("reverselab_sessions", JSON.stringify(sessions));
    } catch {
      // ignore
    }
  }, [sessions]);

  const newSession = () => {
    const newId = `sess-${Date.now()}`;
    const item: SessionItem = {
      id: newId,
      title: "新分析",
      target: "",
      time: "Just now",
      status: "idle",
    };
    setSessions((prev) => [item, ...prev]);
    setActiveSessionId(newId);
    setSteps([]);
    setSelectedStep(null);
    setDeliverables(null);
    setIsRunning(false);
    logger.info("main", `Created new session ${newId}`);
  };

  const selectSession = (id: string) => {
    setActiveSessionId(id);
    setSteps([]);
    setSelectedStep(null);
    setDeliverables(null);
  };

  const archiveSession = (id: string) => {
    setSessions((prev) =>
      prev.map((s) => (s.id === id ? { ...s, isArchived: !s.isArchived } : s))
    );
  };

  const deleteSession = (id: string) => {
    setSessions((prev) => {
      const remaining = prev.filter((s) => s.id !== id);
      if (activeSessionId === id) {
        if (remaining.length > 0) {
          setActiveSessionId(remaining[0].id);
        } else {
          setActiveSessionId("");
        }
        setSteps([]);
        setSelectedStep(null);
        setDeliverables(null);
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
        diagnostics,
        selectedStep,
        deliverables,
        isRunning,
        isToolMonitorOpen,
        executeHarness,
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
