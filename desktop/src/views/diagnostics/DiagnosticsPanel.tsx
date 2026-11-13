import { useMemo, useState, useSyncExternalStore } from "react";
import { RefreshCw, Loader2 } from "lucide-react";
import { HEALTH_LAYERS, type HealthLayer, type HealthStatus, type HealthRecovery } from "../../core";
import { HealthMonitor } from "../../services/health/healthMonitor";
import { useHarness } from "../../state";
import { updateService } from "../../services/updates/updateService";
const layerNames: Record<HealthLayer, string> = { goal: "Goal", agent: "Agent", model: "模型", kb: "知识库", tool: "工具", storage: "存储" };
const statusNames: Record<HealthStatus, string> = { unknown: "暂无记录", running: "运行中", healthy: "正常", degraded: "需关注", failed: "失败", cancelled: "已停止" };
const recoveries: Record<HealthRecovery, string> = { retry: "可重试", alternate: "切换路线", configure: "检查配置", revise: "调整输入", stop: "停止", inspect: "查看详情" };
export function DiagnosticsPanel({ currentTarget }: { currentTarget?: string }) {
  const { currentSession, healthEvents, persistenceError, diagnostics, activeDiagnostics, runDiagnostics } = useHarness();
  const updates = useSyncExternalStore(updateService.subscribe, updateService.getSnapshot);
  const [probing, setProbing] = useState(false);
  const [probeError, setProbeError] = useState("");
  const monitor = useMemo(() => {
    const result = new HealthMonitor({ goalId: currentSession?.id || "unselected" });
    for (const event of healthEvents) result.record(event);
    return result.snapshot();
  }, [currentSession?.id, healthEvents]);
  const localHashOnly = Object.values(activeDiagnostics).some(item => item.stageId.endsWith("kb-routing") && item.status === "skipped" && item.summary.includes("SHA256"));
  return <div className="health-workspace">
    <div className="health-context"><span>{currentSession?.title || "未选择 Goal"}</span>{currentTarget && <code>{currentTarget}</code>}</div>
    {persistenceError && <div className="inline-error" role="alert"><strong>STORAGE_FAILED</strong><p>任务记录尚未保存：{persistenceError}</p></div>}
    {updates.error && <div className="inline-error" role="alert"><strong>应用更新 · {updates.error.code}</strong><p>{updates.error.message}</p><p>在设置 → 应用更新查看详情或重试。</p></div>}
    <div className="health-layers">{HEALTH_LAYERS.map(layer => {
      const skipped = localHashOnly && monitor.layers[layer].observedEvents === 0 && (layer === "model" || layer === "kb");
      return <div key={layer} data-status={monitor.layers[layer].status}><span>{layerNames[layer]}</span><strong>{skipped ? layer === "model" ? "本次未调用" : "本次未检索" : statusNames[monitor.layers[layer].status]}</strong><small>{skipped ? "SHA256 已在本地核验" : monitor.layers[layer].lastEvent?.code || `${monitor.layers[layer].observedEvents} 条记录`}</small></div>;
    })}</div>
    <section className="health-events"><header><h2>运行记录</h2><span>{healthEvents.length} 条</span></header>{healthEvents.length > 0 ? <div className="health-event-list">{[...healthEvents].reverse().map(event => <details key={event.eventId}><summary><time>{new Date(event.timestamp).toLocaleTimeString("zh-CN", { hour12: false })}</time><span className="event-layer">{event.branchId && `${event.branchId} / `}{layerNames[event.layer]}</span><span data-status={event.status}>{event.code || statusNames[event.status]}</span><span className="event-reason">{event.reason}</span>{event.recovery && <small>{recoveries[event.recovery]}</small>}</summary><div><code>{event.nodeId || event.agentId || event.goalId}</code>{event.detail && <p>{event.detail}</p>}</div></details>)}</div> : <p className="compact-empty">暂无运行记录</p>}</section>
    <section className="health-tools"><header><h2>本机工具</h2><button className="secondary-button" disabled={probing} onClick={async () => { setProbing(true); setProbeError(""); try { await runDiagnostics(); } catch (err) { setProbeError(String(err)); } finally { setProbing(false); } }}>{probing ? <Loader2 size={14} className="loading-spinner" /> : <RefreshCw size={14} />}{probing ? "检测中" : "检测工具"}</button></header>{probeError && <p className="inline-error" role="alert">{probeError}</p>}{diagnostics.length ? diagnostics.map(item => <div className="tool-health-row" key={item.id}><span>{item.name}</span><small>{item.detail}</small><span data-status={item.status === "pass" ? "healthy" : "degraded"}>{item.status === "pass" ? "可用" : "未就绪"}</span></div>) : <p className="compact-empty">尚未检测</p>}</section>
  </div>;
}
