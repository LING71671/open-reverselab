import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import type { DiagnosticItem, GraphStep, HarnessView, HarnessMode, SecurityTrack, RunBudget } from "../../core";
import { isSecurityTrack } from "../../core/contracts/track";
import { diagnosticService } from "../../services/diagnostics/diagnosticService";
import { flushWorkspaces, loadWorkspaceRuntime, type WorkspaceRuntime } from "../../services/goals/workspaceRuntime";
import type { Workspace } from "../../core/contracts/workspace";
import { nativeBridge } from "../../services/native/nativeBridge";

let storage: Storage | undefined;
try { storage = window.localStorage; } catch { /* Allow a session without browser persistence. */ }
function useHarnessState(runtime: WorkspaceRuntime, openWorkspace: (workspace: Workspace) => Promise<void>) {
  const goalManager = runtime.manager;
  const { sessions, records, persistenceError } = useSyncExternalStore(goalManager.subscribe, goalManager.getSnapshot);
  const [track, setActiveTrack] = useState<SecurityTrack>(() => {
    const saved = storage?.getItem("reverselab_track");
    return isSecurityTrack(saved) ? saved : "blue";
  });
  const [activeSessionId, setActiveSessionId] = useState("");
  const trackSelections = useRef<Partial<Record<SecurityTrack, string>>>({});
  const [viewMode, setViewMode] = useState<HarnessView>("canvas");
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);
  const [isToolMonitorOpen, setToolMonitorOpen] = useState(false);
  const [diagnostics, setDiagnostics] = useState<DiagnosticItem[]>(diagnosticService.getCached());
  const currentSession = sessions.find(session => session.id === activeSessionId);
  const record = records[activeSessionId];
  const isRunning = currentSession?.status === "running" || currentSession?.status === "queued";
  const activeRunCount = sessions.filter(s => s.status === "running").length;
  const queuedCount = sessions.filter(s => s.status === "queued").length;
  useEffect(() => {
    try { storage?.setItem("reverselab_track", track); } catch { /* Keep in memory. */ }
  }, [track]);
  useEffect(() => {
    window.addEventListener("pagehide", flushWorkspaces);
    return () => window.removeEventListener("pagehide", flushWorkspaces);
  }, []);
  const selectSession = (id: string) => {
    const session = sessions.find(s => s.id === id);
    if (!session) return;
    trackSelections.current[track] = activeSessionId;
    setActiveSessionId(id);
    setActiveTrack(session.track);
    setSelectedStepId(null);
    setViewMode("canvas");
  };
  const newSession = () => {
    const id = goalManager.create(track);
    setActiveSessionId(id);
    setSelectedStepId(null);
    setViewMode("canvas");
    return id;
  };
  const executeHarness = async (target: string, prompt: string, _mode: HarnessMode, budget?: RunBudget) => {
    const id = goalManager.submit(target, prompt, track, budget, activeSessionId);
    setActiveSessionId(id);
    setSelectedStepId(null);
    setViewMode("canvas");
    return id;
  };
  const selectStep = useCallback((step: GraphStep | null) => setSelectedStepId(step?.id || null), []);
  const selectedStep = useMemo(() => record?.steps.find(step => step.id === selectedStepId) || null, [record?.steps, selectedStepId]);
  return {
    workspace: runtime.workspace, openWorkspace,
    sessions, records, track, activeSessionId, currentSession, viewMode,
    steps: record?.steps || [], logs: record?.logs || [], messages: record?.messages || [],
    activeDiagnostics: record?.diagnostics || {}, discoveredSamples: record?.samples || [],
    deliverables: record?.deliverables || null, progress: record?.progress, healthEvents: record?.healthEvents || [], persistenceError,
    diagnostics, selectedStep, isRunning, activeRunCount, queuedCount, isToolMonitorOpen,
    executeHarness,
    sendChatMessage: (content: string, target?: string) => executeHarness(target || currentSession?.target || "", content, "wish"),
    clearMessages: () => goalManager.clearMessages(activeSessionId),
    clearLogs: () => goalManager.clearLogs(activeSessionId),
    stopHarness: () => goalManager.cancel(activeSessionId),
    cancelGoal: (id: string) => goalManager.cancel(id),
    runDiagnostics: async () => setDiagnostics(await diagnosticService.runFullDiagnostics(currentSession?.target)),
    newSession, selectSession,
    archiveSession: (id: string) => goalManager.archive(id),
    deleteSession: (id: string) => { goalManager.remove(id); if (id === activeSessionId) setActiveSessionId(""); },
    selectStep,
    setViewMode, setToolMonitorOpen,
    setTrack: (next: SecurityTrack) => {
      if (next === track) return;
      trackSelections.current[track] = activeSessionId;
      setActiveTrack(next);
      const previous = trackSelections.current[next];
      setActiveSessionId(previous && sessions.some(session => session.id === previous) ? previous : "");
      setSelectedStepId(null);
    },
    dismissLoot: () => undefined,
  };
}
const HarnessContext = createContext<ReturnType<typeof useHarnessState> | null>(null);
function ActiveWorkspace({ runtime, openWorkspace, children }: { runtime: WorkspaceRuntime; openWorkspace: (workspace: Workspace) => Promise<void>; children: ReactNode }) {
  const value = useHarnessState(runtime, openWorkspace);
  return <HarnessContext.Provider value={value}>{children}</HarnessContext.Provider>;
}
export function HarnessProvider({ children }: { children: ReactNode }) {
  const [runtime, setRuntime] = useState<WorkspaceRuntime>();
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  const openWorkspace = async (workspace: Workspace) => {
    const next = await loadWorkspaceRuntime(workspace);
    flushWorkspaces(); setRuntime(next);
    try { storage?.setItem("reverselab_workspace", workspace.root); } catch { /* Registry also records recent workspaces. */ }
  };
  useEffect(() => {
    let cancelled = false;
    setError("");
    void (async () => {
      const list = await nativeBridge.workspace<Workspace[]>({ action: "list" });
      const selected = list.find(w => w.root === storage?.getItem("reverselab_workspace")) || list[0];
      const workspace = selected ? await nativeBridge.workspace<Workspace>({ action: "open", root: selected.root }) : await nativeBridge.workspace<Workspace>({ action: "default" });
      const result = await loadWorkspaceRuntime(workspace);
      if (!cancelled) setRuntime(result);
    })().catch(err => { if (!cancelled) setError(String(err)); });
    return () => { cancelled = true; };
  }, [revision]);
  if (!runtime) return <div className="workspace-loading" role="status">{error ? <><p>{error}</p><button className="secondary-button" onClick={() => setRevision(n => n + 1)}>重新打开工作区</button><button className="text-button" onClick={async () => { try { await openWorkspace(await nativeBridge.workspace<Workspace>({ action: "default" })); } catch (err) { setError(String(err)); } }}>打开默认工作区</button></> : <><span className="loading-ring" />正在打开工作区</>}</div>;
  return <ActiveWorkspace key={runtime.workspace.root} runtime={runtime} openWorkspace={openWorkspace}>{children}</ActiveWorkspace>;
}
export function useHarness() {
  const value = useContext(HarnessContext);
  if (!value) throw new Error("useHarness must be used within HarnessProvider");
  return value;
}
