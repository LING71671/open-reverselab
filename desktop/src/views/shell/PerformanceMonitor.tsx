import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { TriangleAlert, X } from "lucide-react";
import { performancePreference } from "../../services/performance/performanceStore";
import type { PerformanceWarning } from "../../services/performance/diagnosticPolicy";
import { performanceMonitor } from "../../services/performance/performanceMonitor";
const labels: Record<PerformanceWarning, string> = { unresponsive: "应用持续响应缓慢，可暂缓新任务。", memory: "应用内存占用持续偏高，可减少并行任务。", cpu: "应用持续高负载，可暂缓新任务。" };

function ActiveMonitor() {
  const [warning, setWarning] = useState<PerformanceWarning | null>(null);
  const session = useRef<ReturnType<typeof performanceMonitor.start> | null>(null);
  useEffect(() => {
    const active = performanceMonitor.start(setWarning);
    session.current = active;
    return () => { session.current = null; void active.stop(); };
  }, []);
  return warning ? <div className="performance-warning" role="status"><TriangleAlert size={15} /><span>{labels[warning]}</span><button type="button" className="icon-button" aria-label="关闭此提醒" onClick={() => session.current?.dismiss(warning)}><X size={14} /></button></div> : null;
}
export function PerformanceMonitor() {
  const enabled = useSyncExternalStore(performancePreference.subscribe, performancePreference.getSnapshot);
  return enabled && isTauri() ? <ActiveMonitor /> : null;
}
