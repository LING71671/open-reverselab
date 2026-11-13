import { useSyncExternalStore } from "react";
import { performancePreference } from "../../services/performance/performanceStore";
import { telemetryPreference } from "../../services/telemetry/telemetryStore";
import { remoteDiagnosticsConfigured } from "../../services/telemetry/sentryService";

export function PerformancePane() {
  const enabled = useSyncExternalStore(performancePreference.subscribe, performancePreference.getSnapshot);
  const remote = useSyncExternalStore(telemetryPreference.subscribe, telemetryPreference.getSnapshot);
  return <section className="settings-fields performance-pane" id="settings-performance" role="tabpanel" aria-labelledby="settings-tab-performance">
    <label className="performance-toggle"><span><strong>性能异常提醒</strong><small>后台检测持续卡顿和资源占用异常。</small></span><input type="checkbox" role="switch" checked={enabled} onChange={event => performancePreference.setEnabled(event.target.checked)} /></label>
    <label className="performance-toggle"><span><strong>发送诊断数据</strong><small>向 Sentry 上报错误类型和操作耗时。</small></span><input type="checkbox" role="switch" checked={remote.enabled} disabled={!remoteDiagnosticsConfigured} onChange={event => telemetryPreference.set({ ...remote, enabled: event.target.checked })} /></label>
    {!remoteDiagnosticsConfigured && <p>此构建尚未配置远程诊断。</p>}
    <small>不发送样本、目标、提示词、文件路径或密钥。</small>
  </section>;
}
