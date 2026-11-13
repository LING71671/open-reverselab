import { useEffect, useRef, useState } from "react";
import { Loader2, RefreshCw, X } from "lucide-react";
import { diagnosticService } from "../../services/diagnostics/diagnosticService";
import type { DiagnosticItem } from "../../core";
interface ToolMonitorDrawerProps { isOpen: boolean; onClose: () => void }
export function ToolMonitorDrawer({ isOpen, onClose }: ToolMonitorDrawerProps) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [items, setItems] = useState<DiagnosticItem[]>(diagnosticService.getCached());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const probe = async () => {
    setLoading(true); setError("");
    try { setItems(await diagnosticService.runFullDiagnostics()); } catch (err) { setError(String(err)); }
    finally { setLoading(false); }
  };
  useEffect(() => { if (isOpen) { dialog.current?.showModal(); void probe(); } else dialog.current?.close(); }, [isOpen]);
  return <dialog ref={dialog} className="settings-dialog tool-dialog" onCancel={onClose} onClose={onClose}><header><h2>本机工具</h2><button className="icon-button" aria-label="关闭工具" onClick={onClose}><X size={18} /></button></header><div className="tool-dialog-content">{loading && <p role="status"><Loader2 size={15} className="loading-spinner" />检测中</p>}{error && <p className="inline-error" role="alert">{error}</p>}{items.map(item => <div className="tool-health-row" key={item.id}><span>{item.name}</span><small>{item.detail}</small><span data-status={item.status === "pass" ? "healthy" : "degraded"}>{item.status === "pass" ? "可用" : "未就绪"}</span></div>)}</div><footer><button className="secondary-button" disabled={loading} onClick={probe}><RefreshCw size={14} />重新检测</button></footer></dialog>;
}
