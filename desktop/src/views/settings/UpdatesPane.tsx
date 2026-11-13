import { useSyncExternalStore } from "react";
import { ArrowDownToLine, Loader2, RefreshCw } from "lucide-react";
import { isTauri } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { updateService } from "../../services/updates/updateService";
import { getWorkloadCount, subscribeWorkload } from "../../services/goals/workspaceRuntime";
import "./updates.css";

const remedies: Record<string, string> = {
  UPDATE_NETWORK: "无法连接更新服务，请检查网络后重试。",
  UPDATE_MANIFEST: "发布信息不完整，请稍后重新检查。",
  UPDATE_SIGNATURE: "更新包未通过签名验证，请重新检查版本。",
  UPDATE_DOWNLOAD: "下载未完成，请重试。",
  UPDATE_INSTALL: "安装程序未能启动，请重新下载后重试。",
  UPDATE_STORAGE: "文件保存失败，请检查工作区权限和可用空间后重试。",
  UPDATE_TASKS_ACTIVE: "请等待所有工作区的 Goal 结束后再安装。",
  UPDATE_BUSY: "已有更新操作正在进行，请稍候重试。",
  UPDATE_UNSUPPORTED: "此运行方式不支持应用内安装。",
  UPDATE_NOT_READY: "请先下载更新。",
};
const size = (bytes: number) => `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
export function UpdatesPane() {
  const state = useSyncExternalStore(updateService.subscribe, updateService.getSnapshot);
  const workload = useSyncExternalStore(subscribeWorkload, getWorkloadCount);
  const { info, phase, release, progress, preferences, error } = state;
  const busy = ["checking", "downloading", "installing"].includes(phase);
  const percentage = progress.total ? Math.min(100, Math.round(progress.downloaded / progress.total * 100)) : undefined;
  const openRelease = () => {
    const url = `https://github.com/LING71671/open-reverselab/releases/${release ? `tag/v${encodeURIComponent(release.version)}` : "latest"}`;
    if (isTauri()) void openUrl(url); else window.open(url, "_blank", "noopener,noreferrer");
  };
  const status = phase === "checking" ? "正在检查更新" : phase === "current" ? "已是最新版本" : phase === "downloading" ? "正在下载更新" : phase === "ready" ? "更新已下载，签名验证通过" : phase === "installing" ? "正在保存工作区并启动安装" : release ? `新版本 ${release.version}` : "";
  return <section className="updates-pane" id="settings-updates" role="tabpanel" aria-labelledby="settings-tab-updates">
    <div className="update-version"><div><h3>ReverseLab <span>{info.version}</span></h3><p>{info.mode === "installed" ? "Windows 安装版" : info.mode === "portable" ? "Windows 便携版" : info.mode === "browser" ? "浏览器预览" : info.mode === "development" ? "开发构建" : "源码构建"}</p></div><button type="button" className="secondary-button" onClick={() => void updateService.check()} disabled={busy || phase === "ready" || info.mode === "browser"}>{phase === "checking" ? <Loader2 size={14} className="loading-spinner" /> : <RefreshCw size={14} />}检查更新</button></div>
    {info.mode === "browser" && <p className="update-hint">请在桌面应用中检查和安装更新。</p>}
    <label className="update-automatic"><input type="checkbox" checked={preferences.automatic} onChange={event => updateService.setAutomatic(event.target.checked)} disabled={phase === "installing"} /><span>自动检查更新<small>每天检查一次，下载和安装由你决定。</small></span></label>
    {status && <p className="update-status" role="status">{busy && <Loader2 size={15} className="loading-spinner" />}{status}</p>}
    {phase === "downloading" && <div className="update-progress"><progress aria-label="更新下载进度" value={percentage} max={100} /><span>{size(progress.downloaded)}{progress.total ? ` / ${size(progress.total)} · ${percentage}%` : ""}</span></div>}
    {release && <div className="update-release"><h4>版本说明</h4><div className="update-notes">{release.notes || "本次发布未附带版本说明。"}</div><button type="button" className="text-button" onClick={openRelease}>查看完整发布说明</button></div>}
    {release && info.mode !== "installed" && <p className="update-hint">当前版本需手动升级。打开发布页下载 Windows 安装包，工作区继续保留。</p>}
    {phase === "available" && info.mode === "installed" && <div className="update-actions"><button type="button" className="primary-button" onClick={() => void updateService.download()}><ArrowDownToLine size={14} />下载更新</button><button type="button" className="text-button" onClick={preferences.skippedVersion === release?.version ? updateService.unskip : updateService.skip}>{preferences.skippedVersion === release?.version ? "恢复版本提醒" : "跳过此版本"}</button></div>}
    {phase === "ready" && <div className="update-install"><p>{workload ? `还有 ${workload} 项 Goal 正在运行或排队，结束后可安装。` : "安装将关闭应用，完成后重新打开。"}</p><button type="button" className="primary-button" disabled={workload > 0} onClick={() => void updateService.install()}>安装并重新打开</button></div>}
    {error && <div className="update-error" role="alert"><p>{remedies[error.code] || "更新失败，请重新检查。"}</p><details><summary>错误详情 · {error.code}</summary><pre>{error.message}</pre></details></div>}
    {preferences.lastChecked > 0 && <p className="update-last-check">上次检查 {new Date(preferences.lastChecked).toLocaleString()}</p>}
  </section>;
}
