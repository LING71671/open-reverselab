import { useMemo, useRef, useState, useEffect } from "react";
import { Copy, Check, Search } from "lucide-react";
import type { LogEntry, LogLevel } from "../../core";
import { Select } from "../controls/Select";
const levelNames: Record<LogLevel, string> = { info: "信息", tool: "工具", evidence: "证据", warn: "警告", error: "错误" };
export function LogConsole({ active, logs, onClear }: { active: boolean; logs: LogEntry[]; onClear: () => void }) {
  const [level, setLevel] = useState<"all" | LogLevel>("all");
  const [query, setQuery] = useState("");
  const [follow, setFollow] = useState(true);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState("");
  const end = useRef<HTMLDivElement>(null);
  const filtered = useMemo(() => logs.filter(log => (level === "all" || log.level === level) && `${log.message} ${log.agentId} ${log.command || ""}`.toLowerCase().includes(query.toLowerCase())), [logs, level, query]);
  useEffect(() => { if (copied) { const timer = setTimeout(() => setCopied(false), 1800); return () => clearTimeout(timer); } }, [copied]);
  useEffect(() => { if (active && follow) end.current?.scrollIntoView({ behavior: "auto", block: "nearest" }); }, [active, logs.length, follow]);
  return <section className="logs-workspace"><header className="logs-controls"><label><Search size={15} /><input aria-label="搜索日志" placeholder="搜索日志" value={query} onChange={e => setQuery(e.target.value)} /></label><Select label="日志级别" value={level} onChange={value => setLevel(value as typeof level)} options={[{ value: "all", label: "所有级别" }, ...Object.entries(levelNames).map(([value, label]) => ({ value, label }))]} /><span className="grow" /><label className="logs-follow"><input type="checkbox" checked={follow} onChange={e => setFollow(e.target.checked)} />跟随日志</label><button className="icon-button" aria-label={copied ? "日志已复制" : "复制日志"} disabled={!filtered.length} onClick={async () => { try { await navigator.clipboard.writeText(filtered.map(log => `[${new Date(log.timestamp).toISOString()}] ${log.level} ${log.message}${log.payload ? `\n${JSON.stringify(log.payload)}` : ""}`).join("\n")); setCopied(true); setCopyError(""); } catch { setCopyError("复制失败"); } }}>{copied ? <Check size={14} /> : <Copy size={14} />}</button><button className="text-button" onClick={onClear} disabled={!logs.length}>清空</button></header>{copyError && <p role="alert" className="inline-error">{copyError}</p>}<div className="logs-list">{filtered.map(log => <details key={log.id}><summary><time>{new Date(log.timestamp).toLocaleTimeString("zh-CN", { hour12: false })}</time><span data-status={log.level === "error" ? "failed" : log.level === "warn" ? "degraded" : undefined}>{levelNames[log.level]}</span><p>{log.message}</p></summary><pre>{log.command}{log.payload ? JSON.stringify(log.payload, null, 2) : log.agentId}</pre></details>)}<div ref={end} /></div></section>;
}
