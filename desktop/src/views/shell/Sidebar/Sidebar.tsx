import { useState } from "react";
import { Plus, Workflow, ScrollText, Gauge, BookOpen, Settings, Archive, ArchiveRestore, Trash2, MessageSquare, Sun, Moon, Loader2, FolderOpen, Files, ChevronsUpDown } from "lucide-react";
import { HarnessView, SessionItem, SecurityTrack, SECURITY_TRACKS, useI18n, matchesTrack } from "../../../core";

interface SidebarProps {
  sessions: SessionItem[];
  activeSessionId: string;
  track: SecurityTrack;
  onTrackChange: (track: SecurityTrack) => void;
  isRunning: boolean;
  theme: "light" | "dark";
  onThemeChange: () => void;
  onSelectSession: (id: string) => void;
  onNewSession: () => void;
  onArchiveSession: (id: string) => void;
  onDeleteSession: (id: string) => void;
  onOpenTools: () => void;
  onOpenSettings: () => void;
  activeView: HarnessView;
  onToggleView: (view: HarnessView) => void;
  workspaceName: string;
  workspaceRoot: string;
  onOpenWorkspace: () => void;
}

export function Sidebar(props: SidebarProps) {
  const { t, locale } = useI18n();
  const zh = locale === "zh";
  const [archived, setArchived] = useState(false);
  const items = [
    { id: "canvas" as const, label: zh ? "流程画板" : "Workflow", icon: Workflow },
    { id: "chat" as const, label: zh ? "执行记录" : "Activity", icon: MessageSquare },
    { id: "samples" as const, label: "样本", icon: Files },
    { id: "kb" as const, label: t.sidebar.kb, icon: BookOpen },
    { id: "console" as const, label: t.sidebar.logs, icon: ScrollText },
  ];
  const sessions = props.sessions.filter(s => matchesTrack(s.track, props.track) && !!s.isArchived === archived);
  return (
    <aside className="workspace-sidebar">
      <fieldset className="track-switch" aria-label="Track" data-active={props.track}>
        {SECURITY_TRACKS.map(track => (
          <label key={track} data-track={track} data-selected={props.track === track} title={track}>
            <input className="sr-only" type="radio" name="security-track" value={track} checked={props.track === track} onChange={() => props.onTrackChange(track)} />
            {track}
          </label>
        ))}
      </fieldset>
      <button className="workspace-select" onClick={props.onOpenWorkspace} title={props.workspaceRoot}><FolderOpen size={15} /><span>{props.workspaceName}</span><ChevronsUpDown size={13} /></button>
      <button className="new-goal" onClick={props.onNewSession}><Plus size={16} />{zh ? "新建 Goal" : "New goal"}</button>
      <nav className="workspace-nav" aria-label={zh ? "工作区" : "Workspace"}>
        {items.map(item => <button key={item.id} aria-current={props.activeView === item.id ? "page" : undefined} onClick={() => props.onToggleView(item.id)}><item.icon size={16} />{item.label}</button>)}
      </nav>
      <div className="history-heading"><span>{zh ? "任务" : "Goals"}</span><button className="icon-button" aria-label={archived ? (zh ? "查看当前任务" : "Current goals") : (zh ? "查看归档" : "Archived goals")} title={archived ? "当前任务" : "归档任务"} aria-pressed={archived} onClick={() => setArchived(!archived)}><Archive size={14} /></button></div>
      <div className="goal-history">
        {sessions.map(session => <div key={session.id} className="goal-history-row" data-active={props.activeSessionId === session.id}>
          <button className="goal-history-select" onClick={() => props.onSelectSession(session.id)} title={session.target}>
            <span>{session.status === "running" && <Loader2 size={13} className="loading-spinner" />}{session.status === "queued" && <span className="waiting-dot" />}{session.title}</span>
            <small><span className={`track-text track-${session.track}`}>{session.track}</span><span>{session.status === "running" ? (zh ? "运行中" : "Running") : session.status === "queued" ? (zh ? "排队中" : "Queued") : session.target ? session.target.replace(/[/\\]+$/, "").split(/[/\\]/).pop() : (zh ? "未设置目标" : "No target")}</span></small>
          </button>
          <div className="goal-history-actions">
            <button className="icon-button" title={archived ? "恢复任务" : "归档任务"} aria-label={archived ? "恢复任务" : "归档任务"} onClick={() => props.onArchiveSession(session.id)}>{archived ? <ArchiveRestore size={13} /> : <Archive size={13} />}</button>
            <button className="icon-button" title="删除任务" aria-label="删除任务" disabled={session.status === "running" || session.status === "queued"} onClick={() => { if (window.confirm(zh ? "删除这项任务及其本地记录？" : "Delete this goal and its local history?")) props.onDeleteSession(session.id); }}><Trash2 size={13} /></button>
          </div>
        </div>)}
      </div>
      <div className="sidebar-footer">
        <button className="sidebar-environment" aria-current={props.activeView === "diagnostics" ? "page" : undefined} onClick={() => props.onToggleView("diagnostics")}><Gauge size={16} />健康监控</button>
        <div className="sidebar-footer-actions">
          <button className="text-button" onClick={props.onOpenTools}>{zh ? "工具" : "Tools"}</button>
          <span className="grow" />
          <button className="icon-button" onClick={props.onThemeChange} title={props.theme === "light" ? "切换深色" : "切换浅色"} aria-label={props.theme === "light" ? "切换深色" : "切换浅色"}>{props.theme === "light" ? <Moon size={16} /> : <Sun size={16} />}</button>
          <button className="icon-button" onClick={props.onOpenSettings} aria-label={t.settings.title} title={t.settings.title}><Settings size={16} /></button>
        </div>
      </div>
    </aside>
  );
}
