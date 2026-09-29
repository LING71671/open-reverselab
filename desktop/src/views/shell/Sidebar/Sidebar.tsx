import { Plus, Terminal, Network, FolderGit2, Activity, BookOpen, Settings } from "lucide-react";
import { HarnessView, SessionItem, useI18n } from "../../../core";

interface SidebarProps {
  sessions: SessionItem[];
  activeSessionId: string;
  onSelectSession: (id: string) => void;
  onNewSession: () => void;
  onOpenTools: () => void;
  onOpenSettings?: () => void;
  activeView: HarnessView;
  onToggleView: (view: HarnessView) => void;
}

export function Sidebar({
  sessions,
  activeSessionId,
  onSelectSession,
  onNewSession,
  onOpenTools,
  onOpenSettings,
  activeView,
  onToggleView,
}: SidebarProps) {
  const { t, locale } = useI18n();

  const navItems: { id: HarnessView; label: string; icon: any }[] = [
    { id: "canvas", label: t.sidebar.graph, icon: Network },
    { id: "console", label: t.sidebar.logs, icon: Terminal },
    { id: "diagnostics", label: t.sidebar.diag, icon: Activity },
    { id: "kb", label: t.sidebar.kb, icon: BookOpen },
  ];

  const formatTime = (timeStr: string) => {
    if (locale === "zh") {
      if (timeStr === "Today") return "今天";
      if (timeStr === "Yesterday") return "昨天";
      if (timeStr === "Sep 27") return "9月27日";
    }
    return timeStr;
  };

  return (
    <aside className="w-56 h-full bg-[#0d0d10] border-r border-zinc-900 flex flex-col select-none shrink-0 z-10 font-sans">
      {/* New Analysis Button */}
      <div className="p-3 border-b border-zinc-900/80">
        <button
          onClick={onNewSession}
          className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-800/80 text-xs font-medium text-zinc-200 transition cursor-pointer active:scale-95"
        >
          <Plus className="w-3.5 h-3.5 text-zinc-400" />
          <span>{t.sidebar.newAnalysis}</span>
        </button>
      </div>

      {/* Vertical Navigation Items */}
      <div className="px-2 pt-3 pb-2 border-b border-zinc-900/60">
        <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1.5 px-2">
          {t.sidebar.views}
        </div>
        <nav className="space-y-0.5">
          {navItems.map((item) => {
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onToggleView(item.id)}
                className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer active:scale-95 ${
                  isActive
                    ? "bg-zinc-800 text-zinc-100 shadow-sm"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/50"
                }`}
              >
                <item.icon
                  className={`w-3.5 h-3.5 shrink-0 transition-colors ${
                    isActive ? "text-zinc-100" : "text-zinc-500"
                  }`}
                />
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* History Session List */}
      <div className="flex-1 overflow-y-auto px-2 py-3 space-y-1">
        <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1.5 px-2">
          {t.sidebar.history}
        </div>
        {sessions.map((s) => {
          const isActive = s.id === activeSessionId;
          return (
            <div
              key={s.id}
              onClick={() => onSelectSession(s.id)}
              className={`p-2.5 rounded-lg cursor-pointer transition flex flex-col gap-0.5 border ${
                isActive
                  ? "bg-zinc-900/90 border-zinc-800 text-zinc-100"
                  : "border-transparent text-zinc-400 hover:bg-zinc-900/50 hover:text-zinc-300"
              }`}
            >
              <div className="text-xs font-medium truncate">{s.title}</div>
              <div className="flex items-center justify-between text-[10px] font-mono text-zinc-500">
                <span className="truncate max-w-[110px]">{s.target}</span>
                <span>{formatTime(s.time)}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer: Environment & Settings */}
      <div className="p-2 border-t border-zinc-900 bg-[#0a0a0d] space-y-1">
        <div className="flex items-center gap-1">
          <button
            onClick={onOpenTools}
            title={`${t.sidebar.environment} (109)`}
            className="flex-1 flex items-center justify-between px-2.5 py-1.5 rounded-lg hover:bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 text-xs transition cursor-pointer group"
          >
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.5)] group-hover:scale-110 transition-transform" />
              <span className="text-zinc-300 font-medium">{t.sidebar.environment}</span>
            </div>
            <span className="text-[10px] font-mono text-zinc-500 group-hover:text-zinc-300 transition-colors">
              109
            </span>
          </button>

          <button
            onClick={onOpenSettings}
            title={t.settings.title}
            className="p-1.5 rounded-lg hover:bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 transition cursor-pointer active:scale-95"
          >
            <Settings className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="flex items-center justify-between px-2.5 text-[10px] font-mono text-zinc-600">
          <div className="flex items-center gap-1.5">
            <FolderGit2 className="w-3 h-3 text-zinc-600" />
            <span className="text-zinc-500">open-reverseLab</span>
          </div>
          <span>v0.1.0</span>
        </div>
      </div>
    </aside>
  );
}
