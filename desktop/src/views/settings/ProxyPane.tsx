import { useRef, useState, useSyncExternalStore } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { Check, Loader2, Pencil, Plus, Trash2, X } from "lucide-react";
import { proxyPool, testProxy } from "../../services/network/networkService";
import type { NetworkScope, ProxyConfig, ProxyMode, ProxyNode } from "../../services/network/proxyPool";
import "./network.css";
import { Select } from "../controls/Select";

const policies: [ProxyMode, string][] = [["system", "跟随系统"], ["direct", "直连"], ["fixed", "固定节点"], ["failover", "失败切换"], ["round-robin", "轮询"]];
export function ProxyPane() {
  const snapshot = useSyncExternalStore(proxyPool.subscribe, proxyPool.getSnapshot);
  const [draft, setDraft] = useState<ProxyConfig>(() => structuredClone(snapshot.config));
  const [editor, setEditor] = useState<ProxyNode | null>(null);
  const [testUrl, setTestUrl] = useState("https://example.com/");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [testingAll, setTestingAll] = useState(false);
  const addButton = useRef<HTMLButtonElement>(null);
  const editorTrigger = useRef<HTMLButtonElement | null>(null);
  const closeEditor = () => {
    setEditor(null);
    requestAnimationFrame(() => (editorTrigger.current?.isConnected ? editorTrigger.current : addButton.current)?.focus());
  };
  const dirty = JSON.stringify(draft) !== JSON.stringify(snapshot.config);
  const update = (config: ProxyConfig) => { setDraft(config); setMessage(""); setError(""); };
  const save = () => {
    try { proxyPool.save(draft); setDraft(structuredClone(proxyPool.getSnapshot().config)); setError(""); setMessage("已保存，用于后续请求"); return true; }
    catch (err) { setError(err instanceof Error ? err.message : "保存失败"); return false; }
  };
  const saveNode = () => {
    if (!editor) return;
    // Validate the node independently while a policy is still being edited.
    try {
      const config = { ...draft, nodes: draft.nodes.some(node => node.id === editor.id) ? draft.nodes.map(node => node.id === editor.id ? editor : node) : [...draft.nodes, editor] };
      // Full configuration validation is performed by Save below.
      let url: URL;
      try { url = new URL(editor.url); } catch { throw new Error("请填写有效代理地址，例如 http://127.0.0.1:8080"); }
      if (!editor.name.trim() || !["http:", "https:", "socks5:", "socks5h:"].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash || !["", "/"].includes(url.pathname)) throw new Error("请填写节点名称和有效代理地址，账号密码单独填写");
      update(config); closeEditor();
    } catch (err) { setError(err instanceof Error ? err.message : "节点配置无效"); }
  };
  const test = async (id?: string) => {
    if (dirty && !save()) return;
    setError("");
    try {
      if (id) { await testProxy(id, testUrl); return; }
      setTestingAll(true);
      const pending = [...proxyPool.getSnapshot().config.nodes.filter(node => node.enabled)];
      // Two workers keep testing bounded even for a large imported pool.
      await Promise.all([0, 1].map(async () => { while (pending.length) { const node = pending.shift(); if (node) await testProxy(node.id, testUrl); } }));
    } catch (err) { setError(err instanceof Error ? err.message : "连接测试失败"); }
    finally { setTestingAll(false); }
  };
  return <section className="network-pane settings-fields" id="settings-network" role="tabpanel" aria-labelledby="settings-tab-network">
    <div className="proxy-routes">
      {(["model", "tools"] as NetworkScope[]).map(scope => <div className="proxy-route" key={scope}>
        <label>{scope === "model" ? "模型请求" : "Python 目标访问"}<Select label={`${scope === "model" ? "模型请求" : "Python 目标访问"}代理策略`} value={draft[scope].mode} onChange={value => update({ ...draft, [scope]: { ...draft[scope], mode: value as ProxyMode } })} options={policies.filter(([mode]) => scope !== "tools" || mode !== "failover").map(([value, label]) => ({ value, label }))} /></label>
        {draft[scope].mode === "fixed" && <label>代理节点<Select label={`${scope === "model" ? "模型请求" : "Python 目标访问"}代理节点`} value={draft[scope].nodeId || ""} onChange={nodeId => update({ ...draft, [scope]: { ...draft[scope], nodeId } })} placeholder="选择节点" options={draft.nodes.filter(node => node.enabled && (scope === "model" || /^https?:/.test(node.url))).map(node => ({ value: node.id, label: node.name }))} /></label>}
      </div>)}
    </div>
    <div className="proxy-section-heading"><h3>代理池</h3><button ref={addButton} className="text-button" type="button" disabled={Boolean(editor)} onClick={event => { editorTrigger.current = event.currentTarget; setEditor({ id: crypto.randomUUID(), name: "", url: "", username: "", password: "", enabled: true }); setError(""); }}><Plus size={14} />添加节点</button></div>
    {draft.nodes.length > 0 && <ul className="proxy-list">{draft.nodes.map(node => {
      const health = snapshot.health[node.id];
      return <li key={node.id}>
        <input type="checkbox" aria-label={`启用 ${node.name}`} checked={node.enabled} onChange={event => update({ ...draft, nodes: draft.nodes.map(item => item.id === node.id ? { ...item, enabled: event.target.checked } : item) })} />
        <div className="proxy-node-detail"><strong>{node.name}</strong><span>{node.url}</span><small className={health?.state === "failed" ? "proxy-error" : ""}>{health?.state === "checking" ? "正在测试…" : health?.state === "healthy" ? `${health.latencyMs} ms` : health?.state === "failed" ? health.error : "未测试"}</small></div>
        <button type="button" className="text-button" disabled={!isTauri() || testingAll || health?.state === "checking" || Boolean(editor)} onClick={() => void test(node.id)}>测试</button>
        <button type="button" className="icon-button" aria-label={`编辑 ${node.name}`} disabled={Boolean(editor)} onClick={event => { editorTrigger.current = event.currentTarget; setEditor({ ...node }); setError(""); }}><Pencil size={14} /></button>
        <button type="button" className="icon-button" aria-label={`移除 ${node.name}`} disabled={Boolean(editor)} onClick={() => update({ ...draft, nodes: draft.nodes.filter(item => item.id !== node.id) })}><Trash2 size={14} /></button>
      </li>;
    })}</ul>}
    {!draft.nodes.length && !editor && <p className="proxy-empty">尚未添加代理节点</p>}
    {editor && <div className="proxy-editor" onKeyDown={event => { if (event.key === "Escape") { event.preventDefault(); closeEditor(); setError(""); } }}>
      <div className="proxy-editor-grid"><label>名称<input autoFocus value={editor.name} maxLength={80} onChange={event => setEditor({ ...editor, name: event.target.value })} /></label><label>代理地址<input type="url" spellCheck={false} placeholder="http://127.0.0.1:8080" value={editor.url} onChange={event => setEditor({ ...editor, url: event.target.value })} /></label><label>用户名<input autoComplete="off" value={editor.username} maxLength={512} onChange={event => setEditor({ ...editor, username: event.target.value })} /></label><label>密码<input type="password" autoComplete="new-password" value={editor.password} maxLength={512} onChange={event => setEditor({ ...editor, password: event.target.value })} /></label></div>
      <div className="proxy-editor-actions"><button type="button" className="text-button" onClick={() => { closeEditor(); setError(""); }}><X size={14} />取消编辑</button><button type="button" className="secondary-button" onClick={saveNode}><Check size={14} />完成</button></div>
    </div>}
    <div className="proxy-test"><label>测试地址<input type="url" value={testUrl} spellCheck={false} onChange={event => setTestUrl(event.target.value)} /></label><button type="button" className="secondary-button" disabled={!isTauri() || !draft.nodes.some(node => node.enabled) || testingAll || Boolean(editor)} onClick={() => void test()}>{testingAll && <Loader2 size={14} className="loading-spinner" />}{testingAll ? "正在测试" : "测试启用节点"}</button></div>
    <small>SOCKS5 用于模型请求；Python 使用 HTTP(S) 代理。账号密码保存在本机应用存储中，未加密。</small>
    {!isTauri() && <small>浏览器可编辑配置；连接测试和代理路由需在桌面应用中使用。</small>}
    {error && <p className="proxy-error" role="alert">{error}</p>}
    {message && <p role="status" className="proxy-saved">{message}</p>}
    <div className="proxy-save"><span>{dirty ? "有未保存的更改" : ""}</span><button type="button" className="primary-button" disabled={Boolean(editor) || testingAll} onClick={save}>保存代理配置</button></div>
  </section>;
}
