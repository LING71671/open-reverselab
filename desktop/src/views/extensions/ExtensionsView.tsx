import { useCallback, useEffect, useRef, useState } from "react";
import { Download, Loader2, Plus, RefreshCw, Upload, X } from "lucide-react";
import { isTauri } from "@tauri-apps/api/core";
import type { ExtensionEntry, ExtensionInspection, ExtensionSource, InstalledExtension, KnowledgeUpdate, McpConnection } from "../../core/contracts/extensions";
import { nativeBridge } from "../../services/native/nativeBridge";
import { McpConfiguration } from "./McpConfiguration";
import "./extensions.css";

const tabs = [["kb", "知识库"], ["mcp", "MCP"], ["sources", "市场源"]] as const;
type Tab = typeof tabs[number][0];
type Operation = (signal: AbortSignal) => Promise<void>;
interface ExportNetwork { id: string; title: string; track: string; installationId: string }
const statusText = { ready: "已验证", unconfigured: "待配置", disconnected: "已断开", error: "连接失败", unavailable: "扩展不可用" };
const errorText = (error: unknown) => error instanceof Error ? error.message : String(error);
const sourceLabel = (source: InstalledExtension["source"]) => source?.url || source?.label || source?.path || "本地文件";
const changed = () => window.dispatchEvent(new Event("reverselab-extensions-changed"));

export function ExtensionsView({ active }: { active: boolean }) {
  const [tab, setTab] = useState<Tab>("kb");
  const [installed, setInstalled] = useState<InstalledExtension[]>([]);
  const [connections, setConnections] = useState<McpConnection[]>([]);
  const [sources, setSources] = useState<ExtensionSource[]>([]);
  const [inspection, setInspection] = useState<ExtensionInspection | null>(null);
  const [updates, setUpdates] = useState<Record<string, KnowledgeUpdate>>({});
  const [source, setSource] = useState("");
  const [sourceUrl, setSourceUrl] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [configuration, setConfiguration] = useState<InstalledExtension | "new" | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [networkSelection, setNetworkSelection] = useState<{ installationId: string; networks: ExportNetwork[]; selected: string[] } | null>(null);
  const controller = useRef<AbortController | null>(null);
  const upload = useRef<HTMLInputElement>(null);
  const root = useRef<HTMLDivElement>(null);

  const reload = useCallback(async (signal: AbortSignal) => {
    const results = await Promise.allSettled([
      nativeBridge.extensions<{ entries: InstalledExtension[] }>({ operation: "list" }, { signal }),
      nativeBridge.extensions<{ sources: ExtensionSource[] }>({ operation: "sources/list" }, { signal }),
      nativeBridge.mcp<{ connections: McpConnection[] }>({ operation: "list" }, { signal }),
    ]);
    if (signal.aborted) return;
    if (results[0].status === "fulfilled") setInstalled(results[0].value.entries);
    if (results[1].status === "fulfilled") setSources(results[1].value.sources);
    if (results[2].status === "fulfilled") setConnections(results[2].value.connections);
    setLoaded(true);
    const failures = results.filter(result => result.status === "rejected");
    if (failures.length) throw new Error(failures.map(result => errorText((result as PromiseRejectedResult).reason)).join("；"));
  }, []);

  const run = useCallback(async (label: string, operation: Operation) => {
    if (controller.current && !controller.current.signal.aborted) return;
    const current = new AbortController(); controller.current = current;
    setBusy(label); setError(""); setNotice("");
    try { await operation(current.signal); }
    catch (err) { if (controller.current === current) setError(current.signal.aborted ? "操作已取消；可刷新查看当前状态" : errorText(err)); }
    finally { if (controller.current === current) { controller.current = null; setBusy(""); } }
  }, []);

  useEffect(() => { if (active && !loaded) void run("正在读取扩展", reload); }, [active, loaded, reload, run]);
  useEffect(() => () => controller.current?.abort(), []);

  const inspect = (request: Record<string, unknown>) => run("正在读取安装包", async signal => {
    setInspection(null);
    const result = await nativeBridge.extensions<ExtensionInspection>({ operation: "inspect", ...request }, { signal });
    setInspection(result);
  });
  const chooseZip = async () => {
    if (!isTauri()) { upload.current?.click(); return; }
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({ multiple: false, filters: [{ name: "扩展包", extensions: ["zip"] }], title: "选择扩展 ZIP" });
      if (typeof selected === "string") await inspect({ source: selected });
    } catch (err) { setError(errorText(err)); }
  };
  const uploadZip = (file: File) => run("正在读取 ZIP", async signal => {
    if (file.size > 128 * 1024 * 1024) throw new Error("ZIP 文件不能超过 128 MB");
    const archiveBase64 = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      const abort = () => reader.abort(); signal.addEventListener("abort", abort, { once: true });
      reader.onload = () => resolve(String(reader.result).split(",", 2)[1]);
      reader.onerror = () => reject(new Error("ZIP 文件读取失败"));
      reader.onabort = () => reject(new DOMException("Aborted", "AbortError"));
      reader.onloadend = () => signal.removeEventListener("abort", abort);
      reader.readAsDataURL(file);
    });
    const result = await nativeBridge.extensions<ExtensionInspection>({ operation: "inspect", filename: file.name, archiveBase64 }, { signal });
    setInspection(result);
  });
  const install = (entry: ExtensionEntry) => run(`正在安装 ${entry.title}`, async signal => {
    if (!inspection) return;
    await nativeBridge.extensions({ operation: "install", inspectionId: inspection.inspectionId, entryId: entry.id }, { signal });
    changed(); await reload(signal); setNotice(`已安装 ${entry.title}`);
  });
  const isInstalled = (entry: ExtensionEntry) => installed.some(item => item.id === entry.id && item.version === entry.version && item.kind === entry.kind && item.source.identity === entry.source?.identity);
  const checkUpdate = (entry: InstalledExtension) => run(`正在检查 ${entry.title} 更新`, async signal => {
    setUpdates(previous => { const next = { ...previous }; delete next[entry.installationId]; return next; });
    const result = await nativeBridge.extensions<KnowledgeUpdate>({ operation: "updates/check", installationId: entry.installationId }, { signal });
    setUpdates(previous => ({ ...previous, [entry.installationId]: result }));
  });
  const applyUpdate = (entry: InstalledExtension) => run(`正在更新 ${entry.title}`, async signal => {
    const update = updates[entry.installationId];
    if (!update?.inspectionId || !update.available) return;
    const result = await nativeBridge.extensions<{ entry: InstalledExtension }>({ operation: "updates/install", installationId: entry.installationId, inspectionId: update.inspectionId }, { signal });
    setUpdates(previous => { const next = { ...previous }; delete next[entry.installationId]; return next; });
    changed(); await reload(signal); setNotice(`已更新到 ${result.entry.version}，已有 Goal 继续使用原版本`);
  });
  const renderUpdate = (entry: InstalledExtension) => entry.kind === "knowledge" && entry.source.identity?.startsWith("https://github.com/") ? <>
    <button className="text-button" disabled={Boolean(busy)} onClick={() => void checkUpdate(entry)}>检查更新</button>
    {updates[entry.installationId]?.available ? <button className="text-button" disabled={Boolean(busy)} onClick={() => void applyUpdate(entry)}>更新到 {updates[entry.installationId].latestVersion}</button> : updates[entry.installationId]?.message && <span role="status">{updates[entry.installationId].message}</span>}
  </> : null;
  const mutate = (entry: InstalledExtension, operation: "enable" | "remove") => run(operation === "remove" ? "正在移除扩展" : "正在更新扩展", async signal => {
    const result = await nativeBridge.extensions<{ disabledDependents?: string[] }>({ operation, installationId: entry.installationId, ...(operation === "enable" ? { enabled: !entry.enabled } : {}) }, { signal });
    if (operation === "remove") { setRemoving(null); if (configuration !== "new" && configuration?.installationId === entry.installationId) setConfiguration(null); }
    changed(); await reload(signal);
    if (result.disabledDependents?.length) setNotice(`扩展已移除，同时停用了 ${result.disabledDependents.length} 个依赖扩展`);
  });
  const selectNetworks = (entry: InstalledExtension) => run("正在读取知识网络", async signal => {
    const graph = await nativeBridge.extensions<{ networks: ExportNetwork[] }>({ operation: "graph", track: "both", pinned: [{ installationId: entry.installationId, digest: entry.digest }] }, { signal });
    const networks = graph.networks.filter(network => network.installationId === entry.installationId);
    setNetworkSelection(networks.length ? { installationId: entry.installationId, networks, selected: [] } : null);
    if (!networks.length) setNotice("此知识包没有可单独导出的网络");
  });
  const exportEntry = async (entry: InstalledExtension, networkIds?: string[]) => {
    let outputPath: string | undefined;
    if (isTauri()) {
      try { const { save } = await import("@tauri-apps/plugin-dialog"); const path = await save({ defaultPath: `${entry.id}${networkIds ? "-networks" : ""}-${entry.version}.zip`, filters: [{ name: "扩展包", extensions: ["zip"] }] }); if (!path) return; outputPath = path; }
      catch (err) { setError(errorText(err)); return; }
    }
    await run("正在导出扩展", async signal => {
      const result = await nativeBridge.extensions<{ filename?: string; archiveBase64?: string; path?: string }>({ operation: "export", installationId: entry.installationId, ...(networkIds ? { networkIds } : {}), ...(outputPath ? { outputPath } : {}) }, { signal });
      if (result.archiveBase64 && result.filename) {
        const bytes = Uint8Array.from(atob(result.archiveBase64), char => char.charCodeAt(0));
        const url = URL.createObjectURL(new Blob([bytes], { type: "application/zip" }));
        const anchor = document.createElement("a"); anchor.href = url; anchor.download = result.filename; anchor.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } else if (!result.path) throw new Error("导出服务未返回文件");
      setNotice(networkIds ? "所选网络已导出为派生知识包" : "扩展已导出");
    });
  };
  const mcpAction = (connection: McpConnection, operation: "connect" | "disconnect" | "remove") => run(operation === "connect" ? "正在验证 MCP 连接" : "正在更新 MCP 连接", async signal => {
    try { await nativeBridge.mcp({ operation, connectionId: connection.id }, { signal }); setRemoving(null); changed(); }
    finally { if (!signal.aborted) await reload(signal); }
  });
  const entryConnection = (entry: InstalledExtension) => connections.find(connection => connection.installationId === entry.installationId);
  const renderConnection = (connection: McpConnection) => <>
    <span className="extension-status">{statusText[connection.status] || connection.status} · {connection.tools?.length || 0} 个工具 · {connection.resources?.length || 0} 个资源</span>
    {connection.error && <p className="field-error">{typeof connection.error === "string" ? connection.error : connection.error.message}</p>}
    {connection.tools?.length > 0 && <details className="extension-tools"><summary>工具目录</summary><ul>{connection.tools.map(tool => <li key={tool.id || tool.name}><code>{tool.name}</code>{tool.description && <span>{tool.description}</span>}</li>)}</ul></details>}
  </>;

  return <div ref={root} className="extensions-page">
    <div className="extensions-content">
      <div className="extensions-toolbar">
        <div className="extension-tabs" role="tablist" aria-label="扩展类别" onKeyDown={event => {
          if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
          event.preventDefault(); const index = tabs.findIndex(([key]) => key === tab);
          const next = tabs[event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length][0];
          setTab(next); root.current?.querySelector<HTMLButtonElement>(`#extension-tab-${next}`)?.focus();
        }}>{tabs.map(([key, label]) => <button key={key} id={`extension-tab-${key}`} role="tab" aria-selected={tab === key} aria-controls={`extension-panel-${key}`} tabIndex={tab === key ? 0 : -1} onClick={() => setTab(key)}>{label}</button>)}</div>
        <button className="icon-button" aria-label="刷新扩展" title="刷新扩展" disabled={Boolean(busy)} onClick={() => void run("正在刷新扩展", reload)}><RefreshCw size={16} /></button>
      </div>
      <div className="extension-feedback" aria-live="polite">{busy ? <><Loader2 size={15} className="loading-spinner" /><span>{busy}</span><button className="text-button" onClick={() => controller.current?.abort()}>取消</button></> : error ? <p role="alert" className="field-error">{error}</p> : notice ? <p role="status">{notice}</p> : null}</div>
      <section className="extension-import" aria-label="安装扩展" hidden={tab === "sources"}>
        <form onSubmit={event => { event.preventDefault(); void inspect({ source: source.trim() }); }}>
          <label className="sr-only" htmlFor="extension-source">GitHub 链接或本地路径</label><input id="extension-source" value={source} onChange={event => setSource(event.target.value)} placeholder="GitHub 链接或本地路径" spellCheck={false} disabled={Boolean(busy)} />
          <button className="primary-button" disabled={Boolean(busy) || !source.trim()} type="submit">读取</button>
          <button type="button" className="secondary-button" disabled={Boolean(busy)} onClick={() => void chooseZip()}><Upload size={15} />导入 ZIP</button>
          <input type="file" ref={upload} accept=".zip,application/zip" hidden onChange={event => { const file = event.target.files?.[0]; event.target.value = ""; if (file) void uploadZip(file); }} />
        </form>
      </section>
      {inspection && <section className="extension-inspection" aria-label="安装包内容"><div className="extension-section-heading"><h2>可安装内容</h2><button className="icon-button" aria-label="关闭安装包" disabled={Boolean(busy)} onClick={() => setInspection(null)}><X size={16} /></button></div>{inspection.warnings?.map((warning, index) => <p className="extension-warning" key={index}>{warning}</p>)}{inspection.entries.map(entry => <div className="extension-row" key={entry.id}><div className="extension-row-content"><h3>{entry.title}<small>{entry.version}</small></h3><p>{entry.description}</p>{entry.requires?.length ? <p className="extension-meta">依赖：{entry.requires.map(dependency => `${dependency.id}@${dependency.version}${dependency.optional ? "（可选）" : ""}`).join("、")}</p> : null}<span className="extension-meta">{entry.kind === "mcp" ? "MCP" : "知识库"} · {entry.id}</span></div><button className="secondary-button" disabled={Boolean(busy) || isInstalled(entry)} onClick={() => void install(entry)}><Download size={15} />{isInstalled(entry) ? "已安装" : "安装"}</button></div>)}</section>}
      {(["kb", "mcp"] as const).map(kind => <section key={kind} id={`extension-panel-${kind}`} role="tabpanel" aria-labelledby={`extension-tab-${kind}`} hidden={tab !== kind}>
        <div className="extension-section-heading"><h2>已安装</h2>{kind === "mcp" && <button className="text-button" disabled={Boolean(busy)} onClick={() => setConfiguration("new")}><Plus size={15} />添加连接</button>}</div>
        {loaded && !installed.some(entry => entry.kind === (kind === "kb" ? "knowledge" : "mcp")) && (kind !== "mcp" || !connections.some(item => !item.installationId)) && <p className="extension-empty">{kind === "mcp" ? "暂无 MCP 扩展" : "暂无知识库扩展"}</p>}
        {installed.filter(entry => entry.kind === (kind === "kb" ? "knowledge" : "mcp")).map(entry => {
          const connection = entryConnection(entry);
          return <article className="extension-installed" key={entry.installationId}>
            <div className="extension-row"><div className="extension-row-content"><h3>{entry.title}<small>{entry.version}</small></h3>{entry.description && <p>{entry.description}</p>}<p className="extension-meta" title={sourceLabel(entry.source)}>{sourceLabel(entry.source)}</p>{kind === "mcp" && (connection ? renderConnection(connection) : <span className="extension-status">待配置</span>)}</div><label className="extension-switch"><input type="checkbox" role="switch" checked={entry.enabled} aria-label={`启用 ${entry.title}`} disabled={Boolean(busy)} onChange={() => void mutate(entry, "enable")} /><span>{entry.enabled ? "已启用" : "已停用"}</span></label></div>
            <div className="extension-row-actions">{renderUpdate(entry)}{kind === "mcp" && <><button className="text-button" disabled={Boolean(busy)} onClick={() => setConfiguration(entry)}>配置</button>{connection && <><button className="text-button" disabled={Boolean(busy) || !entry.enabled} onClick={() => void mcpAction(connection, "connect")}>验证连接</button>{connection.status === "ready" && <button className="text-button" disabled={Boolean(busy)} onClick={() => void mcpAction(connection, "disconnect")}>断开</button>}</>}</>}<button className="text-button" disabled={Boolean(busy)} onClick={() => void exportEntry(entry)}>导出 ZIP</button>{kind === "kb" && <button className="text-button" disabled={Boolean(busy)} onClick={() => void selectNetworks(entry)}>选择网络导出</button>}{removing === entry.installationId ? <><span>移除扩展？</span><button className="text-button" disabled={Boolean(busy)} onClick={() => setRemoving(null)}>取消</button><button className="text-button danger-text" disabled={Boolean(busy)} onClick={() => void mutate(entry, "remove")}>确认移除</button></> : <button className="text-button" disabled={Boolean(busy)} onClick={() => setRemoving(entry.installationId)}>移除</button>}</div>
            {networkSelection?.installationId === entry.installationId && <fieldset className="extension-networks"><legend>选择网络</legend>{networkSelection.networks.map(network => <label key={network.id}><input type="checkbox" checked={networkSelection.selected.includes(network.id)} disabled={Boolean(busy)} onChange={event => setNetworkSelection(previous => previous && ({ ...previous, selected: event.target.checked ? [...previous.selected, network.id] : previous.selected.filter(id => id !== network.id) }))} /><span>{network.title.endsWith(` · ${network.track}`) ? network.title.slice(0, -(` · ${network.track}`).length) : network.title}<small>{network.track}</small></span></label>)}<div className="extension-form-actions"><button className="text-button" disabled={Boolean(busy)} onClick={() => setNetworkSelection(null)}>取消</button><button className="secondary-button" disabled={Boolean(busy) || !networkSelection.selected.length} onClick={() => void exportEntry(entry, networkSelection.selected)}>导出所选网络</button></div></fieldset>}
            {configuration !== "new" && configuration?.installationId === entry.installationId && <McpConfiguration key={entry.installationId} entry={entry} connection={connection} busy={Boolean(busy)} onClose={() => setConfiguration(null)} onSave={request => void run("正在保存配置", async signal => { await nativeBridge.mcp(request, { signal }); setConfiguration(null); changed(); await reload(signal); setNotice("配置已保存，可验证连接"); })} />}
          </article>;
        })}
        {kind === "mcp" && connections.filter(connection => !connection.installationId).map(connection => <article className="extension-installed" key={connection.id}><div className="extension-row"><div className="extension-row-content"><h3>{connection.name}</h3><p className="extension-meta">{connection.transport}</p>{renderConnection(connection)}</div></div><div className="extension-row-actions"><button className="text-button" disabled={Boolean(busy)} onClick={() => void mcpAction(connection, "connect")}>验证连接</button>{connection.status === "ready" && <button className="text-button" disabled={Boolean(busy)} onClick={() => void mcpAction(connection, "disconnect")}>断开</button>}{removing === connection.id ? <><span>移除连接？</span><button className="text-button" disabled={Boolean(busy)} onClick={() => setRemoving(null)}>取消</button><button className="text-button danger-text" disabled={Boolean(busy)} onClick={() => void mcpAction(connection, "remove")}>确认移除</button></> : <button className="text-button" disabled={Boolean(busy)} onClick={() => setRemoving(connection.id)}>移除</button>}</div></article>)}
        {kind === "mcp" && configuration === "new" && <McpConfiguration busy={Boolean(busy)} onClose={() => setConfiguration(null)} onSave={request => void run("正在保存配置", async signal => { await nativeBridge.mcp(request, { signal }); setConfiguration(null); changed(); await reload(signal); setNotice("配置已保存，可验证连接"); })} />}
      </section>)}
      <section id="extension-panel-sources" role="tabpanel" aria-labelledby="extension-tab-sources" hidden={tab !== "sources"}>
        <form className="extension-source-form" onSubmit={event => { event.preventDefault(); void run("正在添加市场源", async signal => { await nativeBridge.extensions({ operation: "sources/add", source: sourceUrl.trim() }, { signal }); setSourceUrl(""); await reload(signal); }); }}><label htmlFor="market-source">市场源地址</label><div><input id="market-source" value={sourceUrl} onChange={event => setSourceUrl(event.target.value)} spellCheck={false} disabled={Boolean(busy)} /><button className="primary-button" disabled={Boolean(busy) || !sourceUrl.trim()}><Plus size={15} />添加</button></div></form>
        {loaded && sources.length === 0 && <p className="extension-empty">暂无市场源</p>}
        {sources.map(item => <article className="extension-row" key={item.sourceId}><div className="extension-row-content"><h3>{item.title || item.url || item.source}</h3>{item.title && <p className="extension-meta">{item.url || item.source}</p>}{item.error && <p className="field-error">{item.error}</p>}</div><div className="extension-source-actions"><button className="text-button" disabled={Boolean(busy)} onClick={() => void run("正在读取市场源", async signal => { const result = await nativeBridge.extensions<ExtensionInspection>({ operation: "sources/refresh", sourceId: item.sourceId }, { signal }); setInspection(result); await reload(signal); })}>浏览</button><button className="text-button" disabled={Boolean(busy)} onClick={() => void run("正在移除市场源", async signal => { await nativeBridge.extensions({ operation: "sources/remove", sourceId: item.sourceId }, { signal }); await reload(signal); })}>移除</button></div></article>)}
      </section>
    </div>
  </div>;
}
