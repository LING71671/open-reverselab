import { useState, useMemo, useRef, useEffect } from "react";
import { LogEntry, LogLevel, useI18n } from "../../core";
import {
  Search,
  Trash2,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ArrowDown,
  ListFilter,
  Terminal,
  ShieldCheck,
  AlertCircle,
  AlertTriangle,
  Info,
} from "lucide-react";

interface LogConsoleProps {
  logs: LogEntry[];
  onClear: () => void;
}

export function LogConsole({ logs, onClear }: LogConsoleProps) {
  const { t, locale } = useI18n();
  const [filterLevel, setFilterLevel] = useState<"all" | LogLevel>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [copied, setCopied] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (filterLevel !== "all" && log.level !== filterLevel) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const msgMatch = log.message.toLowerCase().includes(q);
        const agentMatch = log.agentId.toLowerCase().includes(q);
        const cmdMatch = log.command?.toLowerCase().includes(q);
        return msgMatch || agentMatch || cmdMatch;
      }
      return true;
    });
  }, [logs, filterLevel, searchQuery]);

  const errorCount = useMemo(() => logs.filter((l) => l.level === "error").length, [logs]);

  useEffect(() => {
    if (autoScroll) {
      endRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs.length, autoScroll]);

  const handleCopyAll = () => {
    const text = filteredLogs
      .map(
        (l) =>
          `[${new Date(l.timestamp).toISOString()}] [${l.level.toUpperCase()}] [${l.agentId}] ${l.message}${
            l.command ? `\nCommand: ${l.command}` : ""
          }${l.payload ? `\nPayload: ${JSON.stringify(l.payload, null, 2)}` : ""}`
      )
      .join("\n\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getLevelBadge = (level: LogLevel) => {
    switch (level) {
      case "tool":
        return (
          <span
            title={locale === "zh" ? "工具调用" : "Tool Call"}
            className="flex items-center justify-center w-4 h-4 rounded bg-zinc-800/80 text-zinc-300 border border-zinc-700/60 shrink-0"
          >
            <Terminal className="w-2.5 h-2.5" />
          </span>
        );
      case "evidence":
        return (
          <span
            title={locale === "zh" ? "提取证据" : "Evidence"}
            className="flex items-center justify-center w-4 h-4 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 shrink-0"
          >
            <ShieldCheck className="w-2.5 h-2.5" />
          </span>
        );
      case "error":
        return (
          <span
            title={locale === "zh" ? "异常错误" : "Error"}
            className="flex items-center justify-center w-4 h-4 rounded bg-rose-950/80 text-rose-400 border border-rose-800/60 shrink-0"
          >
            <AlertCircle className="w-2.5 h-2.5" />
          </span>
        );
      case "warn":
        return (
          <span
            title={locale === "zh" ? "警告提示" : "Warning"}
            className="flex items-center justify-center w-4 h-4 rounded bg-amber-950/80 text-amber-400 border border-amber-800/60 shrink-0"
          >
            <AlertTriangle className="w-2.5 h-2.5" />
          </span>
        );
      default:
        return (
          <span
            title={locale === "zh" ? "系统信息" : "Info"}
            className="flex items-center justify-center w-4 h-4 rounded bg-zinc-900 text-zinc-500 border border-zinc-800/60 shrink-0"
          >
            <Info className="w-2.5 h-2.5" />
          </span>
        );
    }
  };

  const filterOptions = [
    { id: "all" as const, label: t.console.all, icon: ListFilter },
    { id: "tool" as const, label: t.console.tool, icon: Terminal },
    { id: "evidence" as const, label: t.console.evidence, icon: ShieldCheck },
    { id: "error" as const, label: t.console.error, icon: AlertCircle },
    { id: "info" as const, label: t.console.info, icon: Info },
  ];

  return (
    <div className="w-full h-full flex flex-col bg-[#09090b] text-zinc-200 select-none overflow-hidden font-mono text-xs">
      <div className="h-10 px-4 border-b border-zinc-900 bg-[#0d0d10] flex items-center justify-between gap-3 shrink-0">
        {/* Symbol/Icon-first Filter Control Bar */}
        <div className="flex items-center gap-1 bg-zinc-950/60 p-0.5 rounded-lg border border-zinc-900">
          {filterOptions.map((opt) => (
            <button
              key={opt.id}
              onClick={() => setFilterLevel(opt.id)}
              title={opt.label}
              className={`p-1.5 rounded-md transition-all duration-150 cursor-pointer flex items-center gap-1 active:scale-90 ${
                filterLevel === opt.id
                  ? opt.id === "error"
                    ? "bg-rose-950/80 text-rose-300 border border-rose-800/80 shadow-sm"
                    : opt.id === "evidence"
                    ? "bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 shadow-sm"
                    : "bg-zinc-800 text-zinc-100 border border-zinc-700/80 shadow-sm"
                  : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/60 border border-transparent"
              }`}
            >
              <opt.icon className="w-3.5 h-3.5" />
              {opt.id === "error" && errorCount > 0 && (
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
              )}
            </button>
          ))}
        </div>

        <div className="flex-1 max-w-xs relative">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t.console.searchPlaceholder}
            className="w-full pl-8 pr-2 py-1 rounded-md bg-zinc-950 border border-zinc-800 text-[11px] text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-700"
          />
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            title={t.console.autoScroll}
            className={`p-1 rounded text-xs transition cursor-pointer ${
              autoScroll ? "text-zinc-200 bg-zinc-800" : "text-zinc-600 hover:text-zinc-400"
            }`}
          >
            <ArrowDown className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={handleCopyAll}
            title={t.console.copy}
            className="p-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>

          <button
            onClick={onClear}
            title={t.console.clear}
            className="p-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-rose-400 transition cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-1 font-mono">
        {filteredLogs.length === 0 ? (
          <div className="h-full flex items-center justify-center text-zinc-600 text-xs">
            {t.console.empty}
          </div>
        ) : (
          filteredLogs.map((log) => {
            const isExpanded = expandedIds.has(log.id);
            const hasDetails = log.payload || log.command;

            return (
              <div
                key={log.id}
                className="py-1 px-2 rounded hover:bg-zinc-900/50 transition flex flex-col gap-1 border border-transparent hover:border-zinc-800/40"
              >
                <div className="flex items-start gap-2 leading-relaxed">
                  {hasDetails ? (
                    <button
                      onClick={() => toggleExpand(log.id)}
                      className="mt-0.5 text-zinc-500 hover:text-zinc-300 cursor-pointer"
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-3 h-3" />
                      ) : (
                        <ChevronRight className="w-3 h-3" />
                      )}
                    </button>
                  ) : (
                    <span className="w-3 shrink-0" />
                  )}

                  <span className="text-zinc-600 shrink-0 text-[10px]">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>

                  <span className="shrink-0">{getLevelBadge(log.level)}</span>

                  <span className="text-zinc-400 shrink-0 text-[11px]">
                    [{log.agentId}]
                  </span>

                  <span className="text-zinc-200 break-all">{log.message}</span>
                </div>

                {isExpanded && hasDetails && (
                  <div className="ml-8 mt-1 p-2.5 rounded bg-zinc-950 border border-zinc-800/80 text-[11px] text-zinc-400 space-y-1 overflow-x-auto">
                    {log.command && (
                      <div className="flex gap-2 text-zinc-300">
                        <span className="text-zinc-500">cmd:</span>
                        <code className="text-zinc-200">{log.command}</code>
                      </div>
                    )}
                    {log.payload && (
                      <pre className="text-zinc-400 text-[10px] leading-tight">
                        {JSON.stringify(log.payload, null, 2)}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
        <div ref={endRef} />
      </div>
    </div>
  );
}
