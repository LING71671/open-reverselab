import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type CSSProperties } from "react";
import { FileText, Workflow } from "lucide-react";
import { HarnessProvider, useHarness } from "./state";
import { I18nProvider } from "./core";
import { TitleBar, Sidebar, CanvasGraph, AgentChatView, LogConsole, DiagnosticsPanel, PromptConsole, DetailDrawer, SettingsView, KbNavigator, type SettingsTab } from "./views";
import "./App.css";
import "./workspace.css";
import { ResizeHandle, usePaneSize } from "./views/controls/ResizeHandle";
import { SamplesView } from "./views/samples/SamplesView";
import { RetainedView } from "./views/shell/RetainedView";
import type { ComposerDraft } from "./views/prompt/PromptConsole";
import { updateService } from "./services/updates/updateService";
import { PerformanceMonitor } from "./views/shell/PerformanceMonitor";

const emptyDraft: ComposerDraft = { target: "", prompt: "", instruction: "", minutes: "", tokens: "", limitsOpen: false };

function AppContent() {
  const state = useHarness();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("model");
  const [sidebarWidth, setSidebarWidth] = usePaneSize("sidebar", 224);
  const [composerHeight, setComposerHeight] = usePaneSize("composer", 210);
  const [canvasFullscreen, setCanvasFullscreen] = useState(false);
  const fullscreenTrigger = useRef<HTMLElement | null>(null);
  const toggleCanvasFullscreen = useCallback(() => {
    setCanvasFullscreen(previous => {
      if (!previous) fullscreenTrigger.current = document.activeElement as HTMLElement;
      else requestAnimationFrame(() => fullscreenTrigger.current?.focus());
      return !previous;
    });
  }, []);
  useEffect(() => {
    if (!canvasFullscreen) return;
    const exit = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); setCanvasFullscreen(false); requestAnimationFrame(() => fullscreenTrigger.current?.focus()); }
    };
    window.addEventListener("keydown", exit);
    return () => window.removeEventListener("keydown", exit);
  }, [canvasFullscreen]);
  useEffect(() => { if (state.viewMode !== "canvas" || settingsOpen) setCanvasFullscreen(false); }, [state.viewMode, settingsOpen]);
  const updates = useSyncExternalStore(updateService.subscribe, updateService.getSnapshot);
  const openSettings = (tab: SettingsTab = "model") => { setSettingsTab(tab); setSettingsOpen(true); };
  useEffect(() => {
    void updateService.initialize();
    const timer = setTimeout(() => void updateService.check(false), 20_000);
    const repeat = setInterval(() => void updateService.check(false), 60 * 60 * 1000);
    return () => { clearTimeout(timer); clearInterval(repeat); };
  }, []);
  const [drafts, setDrafts] = useState<Record<string, ComposerDraft>>({});
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    try { return localStorage.getItem("reverselab_theme") === "dark" ? "dark" : "light"; } catch { return "light"; }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("reverselab_theme", theme); } catch { /* Theme remains usable without storage. */ }
  }, [theme]);
  const names = { canvas: "Goal", chat: "Goal", kb: "知识库", console: "日志", diagnostics: "健康监控", samples: "样本" };
  const statuses = { idle: "待开始", queued: "等待执行", running: "运行中", completed: "已完成", failed: "执行失败", blocked: "已阻塞", exhausted: "已达运行上限", cancelled: "已停止" };
  const running = state.sessions.filter(s => s.status === "running" || s.status === "queued");
  const composerVisible = state.viewMode === "canvas" || state.viewMode === "chat";
  const workspaceDraftKey = (id: string) => `${state.workspace.root}:${id}`;
  const draftKey = workspaceDraftKey(state.activeSessionId || `new:${state.track}`);
  const baseTarget = state.currentSession?.target || "";
  const basePrompt = state.messages.find(message => message.role === "user")?.content || "";
  const draft = drafts[draftKey] || { ...emptyDraft, target: baseTarget, prompt: basePrompt };
  const updateDraft = useCallback((changes: Partial<ComposerDraft>) => {
    setDrafts(previous => ({ ...previous, [draftKey]: { ...(previous[draftKey] || { ...emptyDraft, target: baseTarget, prompt: basePrompt }), ...changes } }));
  }, [draftKey, baseTarget, basePrompt]);
  const createDraft = (changes: Partial<ComposerDraft> = {}) => {
    const id = state.newSession();
    setDrafts(previous => ({ ...previous, [workspaceDraftKey(id)]: { ...emptyDraft, ...changes } }));
  };
  return (
    <div className="desktop-app" data-track={state.track} data-canvas-fullscreen={canvasFullscreen}>
      <TitleBar />
      <div className="desktop-body">
      <div className="workspace-layout" hidden={settingsOpen} style={{ "--sidebar-width": `${sidebarWidth}px`, "--composer-height": `${composerHeight}px` } as CSSProperties}>
        <div className="sidebar-region">
        <Sidebar workspaceName={state.workspace.name} workspaceRoot={state.workspace.root} onOpenWorkspace={() => openSettings("workspace")} sessions={state.sessions} activeSessionId={state.activeSessionId} track={state.track} onTrackChange={state.setTrack} isRunning={state.isRunning} theme={theme} onThemeChange={() => setTheme(theme === "light" ? "dark" : "light")} onSelectSession={state.selectSession} onNewSession={() => createDraft()} onRenameSession={state.renameSession} onArchiveSession={state.archiveSession} onDeleteSession={id => { state.deleteSession(id); setDrafts(previous => { const next = { ...previous }; delete next[workspaceDraftKey(id)]; return next; }); }} onOpenTools={() => openSettings("tools")} onOpenSettings={() => openSettings()} activeView={state.viewMode} onToggleView={state.setViewMode} />
        <ResizeHandle label="调整侧栏宽度" axis="x" size={sidebarWidth} min={180} max={360} initial={224} onChange={setSidebarWidth} />
        </div>
        <main className="workspace-main">
          <header className="workspace-heading">
            {composerVisible ? state.currentSession && (state.currentSession.customTitle || state.currentSession.status !== "idle") && <h1 className="goal-page-title">{state.currentSession.title}</h1> : <h1>{names[state.viewMode]}</h1>}
            {composerVisible && <div className="goal-view-tabs" role="tablist" aria-label="Goal 视图" onKeyDown={event => {
              if (event.key === "ArrowLeft" || event.key === "ArrowRight" || event.key === "Home" || event.key === "End") {
                event.preventDefault();
                const next = event.key === "Home" ? "chat" : event.key === "End" ? "canvas" : state.viewMode === "chat" ? "canvas" : "chat";
                state.setViewMode(next);
                event.currentTarget.querySelector<HTMLButtonElement>(`[data-view="${next}"]`)?.focus();
              }
            }}>
              <button role="tab" data-view="chat" aria-selected={state.viewMode === "chat"} tabIndex={state.viewMode === "chat" ? 0 : -1} onClick={() => state.setViewMode("chat")}><FileText size={16} />正文</button>
              <button role="tab" data-view="canvas" aria-selected={state.viewMode === "canvas"} tabIndex={state.viewMode === "canvas" ? 0 : -1} onClick={() => state.setViewMode("canvas")}><Workflow size={16} />画板</button>
            </div>}
            <div className="grow" />
            {updates.release && updates.preferences.skippedVersion !== updates.release.version && <button className="text-button update-available" onClick={() => { setSettingsTab("updates"); setSettingsOpen(true); }}>{updates.phase === "ready" ? "更新已就绪" : "有可用更新"}</button>}
            {running.length > 0 && <details className="running-tasks"><summary><span className="activity-dot" />{state.activeRunCount} 项运行中{state.queuedCount ? ` · ${state.queuedCount} 项排队中` : ""}</summary><div className="running-tasks-menu">{running.map(s => <button key={s.id} onClick={(event) => { state.selectSession(s.id); event.currentTarget.closest("details")?.removeAttribute("open"); }}><span>{s.title}</span><small>{s.track} · {statuses[s.status]}</small></button>)}</div></details>}
            {composerVisible && state.currentSession && <span className="goal-status" role="status">{statuses[state.currentSession.status]}</span>}
          </header>
          <div className="workspace-stage">
            <RetainedView active={state.viewMode === "samples"}><SamplesView onSelect={target => createDraft({ target })} /></RetainedView>
            <RetainedView active={state.viewMode === "canvas"}><CanvasGraph key={state.activeSessionId} active={!settingsOpen && state.viewMode === "canvas"} fullscreen={canvasFullscreen} onToggleFullscreen={toggleCanvasFullscreen} steps={state.steps} selectedStep={state.selectedStep} onSelectStep={step => { setCanvasFullscreen(false); state.selectStep(step); }} /></RetainedView>
            <RetainedView active={state.viewMode === "chat"}><AgentChatView key={state.activeSessionId} /></RetainedView>
            <RetainedView active={state.viewMode === "console"}><LogConsole active={state.viewMode === "console"} logs={state.logs} onClear={state.clearLogs} /></RetainedView>
            <RetainedView active={state.viewMode === "diagnostics"}><DiagnosticsPanel currentTarget={state.currentSession?.target} /></RetainedView>
            <RetainedView active={state.viewMode === "kb"}><KbNavigator track={state.track} onTrackChange={state.setTrack} onSelectTechnique={(path, title) => createDraft({ prompt: `参考《${title}》（${path}），完成目标的${state.track === "blue" ? "防御分析与验证" : state.track === "red" ? "安全评估" : "攻防对照验证"}。` })} /></RetainedView>
          </div>
          <div className="workspace-composer" hidden={!composerVisible}>
            <ResizeHandle label="调整输入区高度" axis="y" reverse size={composerHeight} min={170} max={480} initial={210} onChange={setComposerHeight} />
            {state.progress && <div className="run-progress" role="status"><span>{state.progress.reason || `第 ${state.progress.attempts} 条路径`}</span><span>{Math.round(state.progress.elapsedMs / 1000)}s · {state.progress.usageEstimated ? "约 " : ""}{state.progress.tokensUsed.toLocaleString()} tokens</span></div>}
            <PromptConsole key={draftKey} active={!settingsOpen && composerVisible} isRunning={state.isRunning} draft={draft} onDraftChange={updateDraft} onSteer={state.steerGoal} onExecute={async (target, prompt, mode, budget) => { const id = await state.executeHarness(target, prompt, mode, budget); setDrafts(previous => { const next = { ...previous, [workspaceDraftKey(id)]: draft }; if (!state.activeSessionId) delete next[draftKey]; return next; }); }} onStop={state.stopHarness} onSettings={() => openSettings()} />
          </div>
          <PerformanceMonitor />
        </main>
        <DetailDrawer step={state.viewMode === "canvas" ? state.selectedStep : null} onClose={() => state.selectStep(null)} />
      </div>
        <SettingsView isOpen={settingsOpen} initialTab={settingsTab} onClose={() => setSettingsOpen(false)} theme={theme} onThemeChange={() => setTheme(theme === "light" ? "dark" : "light")} />
      </div>
    </div>
  );
}
export default function App() {
  return <I18nProvider><HarnessProvider><AppContent /></HarnessProvider></I18nProvider>;
}
