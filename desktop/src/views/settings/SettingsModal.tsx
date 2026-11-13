import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Loader2, Plus, X } from "lucide-react";
import { llmService, deriveProviderName } from "../../services/llm/llmService";
import { UpdatesPane } from "./UpdatesPane";
import { updateService } from "../../services/updates/updateService";

interface SettingsModalProps { isOpen: boolean; onClose: () => void; onSaved?: () => void; initialTab?: "model" | "updates" }
export function SettingsModal({ isOpen, onClose, onSaved, initialTab = "model" }: SettingsModalProps) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [tab, setTab] = useState(initialTab);
  const updates = useSyncExternalStore(updateService.subscribe, updateService.getSnapshot);
  const installing = updates.phase === "installing";
  const [providers, setProviders] = useState(llmService.getProviders());
  const [providerId, setProviderId] = useState(llmService.getActiveProviderId());
  const [url, setUrl] = useState(llmService.getBaseUrl());
  const [name, setName] = useState(llmService.getActiveProvider()?.name || "");
  const [apiKey, setApiKey] = useState(llmService.getApiKey());
  const [model, setModel] = useState(llmService.getModel());
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState("");
  const [models, setModels] = useState<string[]>([]);
  useEffect(() => { if (isOpen) dialog.current?.showModal(); else dialog.current?.close(); }, [isOpen]);
  const select = (id: string) => {
    const provider = providers.find(p => p.id === id);
    setProviderId(id); setUrl(provider?.baseUrl || ""); setName(provider?.name || ""); setApiKey(provider?.apiKey || ""); setModels([]); setResult("");
  };
  const save = () => {
    try {
      const parsed = new URL(url);
      if (!["https:", "http:"].includes(parsed.protocol)) throw new Error("请使用 HTTP 或 HTTPS 地址");
      if (!model.trim()) throw new Error("请填写模型 ID");
      const id = providerId || `provider-${Date.now()}`;
      llmService.addProvider({ id, name: name.trim() || deriveProviderName(url), baseUrl: url.trim().replace(/\/+$/, ""), apiKey: apiKey.trim() });
      llmService.setModel(model.trim()); setProviderId(id); setProviders(llmService.getProviders()); onSaved?.(); return true;
    } catch (err) { setResult(err instanceof Error ? err.message : String(err)); return false; }
  };
  const test = async () => {
    if (!save()) return;
    setTesting(true); setResult("");
    try { const response = await llmService.checkHealth(); setResult(response.ok ? `连接成功 · ${response.latencyMs} ms` : response.error || "连接失败"); }
    catch (err) { setResult(String(err)); }
    finally { setTesting(false); }
  };
  return <dialog ref={dialog} className="settings-dialog" onCancel={event => { if (installing) event.preventDefault(); else onClose(); }} onClose={onClose}>
    <form onSubmit={event => { event.preventDefault(); if (save()) onClose(); }}>
      <header><h2>设置</h2><button type="button" className="icon-button" aria-label="关闭设置" onClick={onClose} disabled={installing}><X size={18} /></button></header>
      <div className="settings-tabs" role="tablist" aria-label="设置类别" onKeyDown={event => { if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) { event.preventDefault(); if (installing) return; const next = event.key === "Home" ? "model" : event.key === "End" ? "updates" : tab === "model" ? "updates" : "model"; setTab(next); dialog.current?.querySelector<HTMLButtonElement>(`#settings-tab-${next}`)?.focus(); } }}>
        <button type="button" role="tab" id="settings-tab-model" aria-controls="settings-model" aria-selected={tab === "model"} tabIndex={tab === "model" ? 0 : -1} onClick={() => setTab("model")} disabled={installing}>模型</button>
        <button type="button" role="tab" id="settings-tab-updates" aria-controls="settings-updates" aria-selected={tab === "updates"} tabIndex={tab === "updates" ? 0 : -1} onClick={() => setTab("updates")}>应用更新</button>
      </div>
      <div className="settings-fields" id="settings-model" role="tabpanel" aria-labelledby="settings-tab-model" hidden={tab !== "model"}>
        <div className="provider-row"><label>提供商<select value={providerId} onChange={e => select(e.target.value)}><option value="">新增提供商</option>{providers.map(p => <option value={p.id} key={p.id}>{p.name}</option>)}</select></label><button type="button" className="icon-button" aria-label="新增提供商" onClick={() => select("")}><Plus size={18} /></button></div>
        <label>名称<input value={name} onChange={e => setName(e.target.value)} placeholder="可选" /></label>
        <label>API 地址<input type="url" required value={url} onChange={e => setUrl(e.target.value)} placeholder="https://api.example.com/v1" spellCheck={false} /></label>
        <label>API Key<input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} autoComplete="off" /></label>
        <label>模型 ID<input list="provider-models" required value={model} onChange={e => setModel(e.target.value)} spellCheck={false} /><datalist id="provider-models">{models.map(id => <option key={id} value={id} />)}</datalist></label>
        <button type="button" className="text-button" disabled={testing} onClick={async () => { if (!save()) return; setTesting(true); const list = await llmService.fetchModels(); setModels(list); setResult(list.length ? `已读取 ${list.length} 个模型` : "未获取到模型列表，可直接填写模型 ID"); setTesting(false); }}>读取模型列表</button>
        <small>保存后用于新 Goal。API Key 仅保存在本机；测试连接会发送一条短请求。</small>
        {result && <p className="settings-result" role="status">{result}</p>}
      </div>
      <div hidden={tab !== "updates"}><UpdatesPane /></div>
      <footer hidden={tab !== "model"}><button type="button" className="secondary-button" onClick={test} disabled={testing}>{testing && <Loader2 size={14} className="loading-spinner" />}{testing ? "连接中" : "保存并测试"}</button><span className="grow" /><button type="button" className="text-button" onClick={onClose}>取消</button><button className="primary-button" type="submit" disabled={testing}>保存</button></footer>
    </form>
  </dialog>;
}
