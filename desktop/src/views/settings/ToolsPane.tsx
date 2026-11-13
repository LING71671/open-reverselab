import { useEffect, useState } from "react";
import { Loader2, RefreshCw } from "lucide-react";
import { diagnosticService } from "../../services/diagnostics/diagnosticService";
import type { DiagnosticItem } from "../../core";

export function ToolsPane({ active }: { active: boolean }) {
  const [items, setItems] = useState<DiagnosticItem[]>(diagnosticService.getCached());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const probe = async () => {
    setLoading(true); setError("");
    try { setItems(await diagnosticService.runFullDiagnostics()); } catch (err) { setError(String(err)); }
    finally { setLoading(false); }
  };
  useEffect(() => { if (active) setItems(diagnosticService.getCached()); }, [active]);
  return <section id="settings-tools" role="tabpanel" aria-labelledby="settings-tab-tools" className="tools-pane">
    <div className="tools-toolbar"><span>{items.length ? `${items.filter(item => item.status === "pass").length} / ${items.length} 可用` : "尚未检测"}</span><button type="button" className="secondary-button" disabled={loading} onClick={() => void probe()}>{loading ? <Loader2 size={14} className="loading-spinner" /> : <RefreshCw size={14} />}{loading ? "正在检测" : "检测工具"}</button></div>
    {error && <p className="field-error" role="alert">{error}</p>}
    {loading && !items.length && <div className="skeleton-list" aria-label="正在检测工具">{[0, 1, 2].map(n => <div key={n} className="skeleton-row" />)}</div>}
    {items.map(item => <div className="tool-health-row" key={item.id}><span>{item.name}</span><small>{item.detail}</small><span data-status={item.status === "pass" ? "healthy" : "degraded"}>{item.status === "pass" ? "可用" : "未就绪"}</span></div>)}
  </section>;
}
