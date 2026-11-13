import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { HarnessProvider, useHarness } from "./state";
import { I18nProvider } from "./core";
import { TitleBar, Sidebar, CanvasGraph, AgentChatView, LogConsole, DiagnosticsPanel, PromptConsole, DetailDrawer, ToolMonitorDrawer, SettingsModal, KbNavigator } from "./views";
import "./App.css";
import { WorkspaceDialog } from "./views/shell/WorkspaceDialog";
import { SamplesView } from "./views/samples/SamplesView";
import { RetainedView } from "./views/shell/RetainedView";
import type { ComposerDraft } from "./views/prompt/PromptConsole";
import { updateService } from "./services/updates/updateService";

const emptyDraft: ComposerDraft = { target: "", prompt: "", minutes: "", tokens: "", limitsOpen: false };

function AppContent() {
  const state = useHarness();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<"model" | "updates">("model");
  const updates = useSyncExternalStore(updateService.subscribe, updateService.getSnapshot);
  const openSettings = () => { setSettingsTab("model"); setSettingsOpen(true); };
  useEffect(() => {
    void updateService.initialize();
    const timer = setTimeout(() => void updateService.check(false), 20_000);
    const repeat = setInterval(() => void updateService.check(false), 60 * 60 * 1000);
    return () => { clearTimeout(timer); clearInterval(repeat); };
  }, []);
  const [drafts, setDrafts] = useState<Record<string, ComposerDraft>>({});
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    try { return localStorage.getItem("reverselab_theme") === "dark" ? "dark" : "light"; } catch { return "light"; }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("reverselab_theme", theme); } catch { /* Theme remains usable without storage. */ }
  }, [theme]);
  const names = { canvas: "流程画板", chat: "执行记录", kb: "知识库", console: "日志", diagnostics: "健康监控", samples: "样本" };
  const statuses = { idle: "待开始", queued: "等待执行", running: "运行中", completed: "已完成", failed: "执行失败", blocked: "已阻塞", exhausted: "已达运行上限", cancelled: "已停止" };
  const running = state.sessions.filter(s => s.status === "running" || s.status === "queued");
  const composerVisible = state.viewMode === "canvas" || state.viewMode === "chat";
  const draftKey = state.activeSessionId || `new:${state.track}`;
  const baseTarget = state.currentSession?.target || "";
  const basePrompt = state.messages.find(message => message.role === "user")?.content || "";
  const draft = drafts[draftKey] || { ...emptyDraft, target: baseTarget, prompt: basePrompt };
  const updateDraft = useCallback((changes: Partial<ComposerDraft>) => {
    setDrafts(previous => ({ ...previous, [draftKey]: { ...(previous[draftKey] || { ...emptyDraft, target: baseTarget, prompt: basePrompt }), ...changes } }));
  }, [draftKey, baseTarget, basePrompt]);
  const createDraft = (changes: Partial<ComposerDraft> = {}) => {
    const id = state.newSession();
    setDrafts(previous => ({ ...previous, [id]: { ...emptyDraft, ...changes } }));
  };
  return (
    <div className="desktop-app" data-track={state.track}>
      <TitleBar />
      <div className="desktop-body">
        <Sidebar workspaceName={state.workspace.name} workspaceRoot={state.workspace.root} onOpenWorkspace={() => setWorkspaceOpen(true)} sessions={state.sessions} activeSessionId={state.activeSessionId} track={state.track} onTrackChange={state.setTrack} isRunning={state.isRunning} theme={theme} onThemeChange={() => setTheme(theme === "light" ? "dark" : "light")} onSelectSession={state.selectSession} onNewSession={() => createDraft()} onArchiveSession={state.archiveSession} onDeleteSession={id => { state.deleteSession(id); setDrafts(previous => { const next = { ...previous }; delete next[id]; return next; }); }} onOpenTools={() => state.setToolMonitorOpen(true)} onOpenSettings={openSettings} activeView={state.viewMode} onToggleView={state.setViewMode} />
        <main className="workspace-main">
          <header className="workspace-heading">
            <h1>{names[state.viewMode]}</h1>
            <div className="grow" />
            {updates.release && updates.preferences.skippedVersion !== updates.release.version && <button className="text-button update-available" onClick={() => { setSettingsTab("updates"); setSettingsOpen(true); }}>{updates.phase === "ready" ? "更新已就绪" : "有可用更新"}</button>}
            {running.length > 0 && <details className="running-tasks"><summary><span className="activity-dot" />{state.activeRunCount} 项运行中{state.queuedCount ? ` · ${state.queuedCount} 项排队中` : ""}</summary><div className="running-tasks-menu">{running.map(s => <button key={s.id} onClick={(event) => { state.selectSession(s.id); event.currentTarget.closest("details")?.removeAttribute("open"); }}><span>{s.title}</span><small>{s.track} · {statuses[s.status]}</small></button>)}</div></details>}
            {composerVisible && state.currentSession && <span className="goal-status" role="status">{statuses[state.currentSession.status]}</span>}
          </header>
          <div className="workspace-stage">
            <RetainedView active={state.viewMode === "samples"}><SamplesView onSelect={target => createDraft({ target })} /></RetainedView>
            <RetainedView active={state.viewMode === "canvas"}><CanvasGraph key={state.activeSessionId} active={state.viewMode === "canvas"} steps={state.steps} selectedStep={state.selectedStep} onSelectStep={state.selectStep} /></RetainedView>
            <RetainedView active={state.viewMode === "chat"}><AgentChatView key={state.activeSessionId} /></RetainedView>
            <RetainedView active={state.viewMode === "console"}><LogConsole active={state.viewMode === "console"} logs={state.logs} onClear={state.clearLogs} /></RetainedView>
            <RetainedView active={state.viewMode === "diagnostics"}><DiagnosticsPanel currentTarget={state.currentSession?.target} /></RetainedView>
            <RetainedView active={state.viewMode === "kb"}><KbNavigator track={state.track} onTrackChange={state.setTrack} onSelectTechnique={(path, title) => createDraft({ prompt: `参考《${title}》（${path}），完成目标的${state.track === "blue" ? "防御分析与验证" : state.track === "red" ? "安全评估" : "攻防对照验证"}。` })} /></RetainedView>
          </div>
          <div className="workspace-composer" hidden={!composerVisible}>
            {state.progress && <div className="run-progress" role="status"><span>{state.progress.reason || `第 ${state.progress.attempts} 条路径`}</span><span>{Math.round(state.progress.elapsedMs / 1000)}s · {state.progress.usageEstimated ? "约 " : ""}{state.progress.tokensUsed.toLocaleString()} tokens</span></div>}
            <PromptConsole key={draftKey} active={composerVisible} isRunning={state.isRunning} draft={draft} onDraftChange={updateDraft} onExecute={async (target, prompt, mode, budget) => { const id = await state.executeHarness(target, prompt, mode, budget); setDrafts(previous => { const next = { ...previous, [id]: draft }; if (draftKey.startsWith("new:")) delete next[draftKey]; return next; }); }} onStop={state.stopHarness} onSettings={openSettings} />
          </div>
        </main>
        <DetailDrawer step={state.viewMode === "canvas" ? state.selectedStep : null} onClose={() => state.selectStep(null)} />
        <ToolMonitorDrawer isOpen={state.isToolMonitorOpen} onClose={() => state.setToolMonitorOpen(false)} />
        {settingsOpen && <SettingsModal isOpen initialTab={settingsTab} onClose={() => setSettingsOpen(false)} />}
        {workspaceOpen && <WorkspaceDialog onClose={() => setWorkspaceOpen(false)} />}
      </div>
    </div>
  );
}
export default function App() {
  return <I18nProvider><HarnessProvider><AppContent /></HarnessProvider></I18nProvider>;
}
