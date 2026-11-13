import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { ArrowLeft, Loader2, Plus, Moon, Sun } from "lucide-react";
import { llmService, deriveProviderName } from "../../services/llm/llmService";
import { UpdatesPane } from "./UpdatesPane";
import { updateService } from "../../services/updates/updateService";
import { ProxyPane } from "./ProxyPane";
import { PerformancePane } from "./PerformancePane";
import { WorkspacePane } from "./WorkspacePane";
import { ToolsPane } from "./ToolsPane";
import { Select } from "../controls/Select";

export type SettingsTab = "workspace" | "model" | "network" | "performance" | "tools" | "updates";
const tabs: [SettingsTab, string][] = [["workspace", "工作区"], ["model", "模型"], ["network", "代理池"], ["performance", "诊断"], ["tools", "本机工具"], ["updates", "应用更新"]];
interface SettingsViewProps {
  isOpen: boolean;
  onClose: () => void;
  initialTab?: SettingsTab;
  theme: "light" | "dark";
  onThemeChange: () => void;
}

export function SettingsView({ isOpen, onClose, initialTab = "model", theme, onThemeChange }: SettingsViewProps) {
  const root = useRef<HTMLDivElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const [tab, setTab] = useState(initialTab);
  const updates = useSyncExternalStore(updateService.subscribe, updateService.getSnapshot);
  const installing = updates.phase === "installing";
  useEffect(() => {
    if (!isOpen) return;
    returnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setTab(initialTab);
    root.current?.querySelector<HTMLButtonElement>(`#settings-tab-${initialTab}`)?.focus();
    return () => { requestAnimationFrame(() => returnFocus.current?.focus()); };
  }, [isOpen, initialTab]);
  return <div ref={root} className="settings-page" hidden={!isOpen}>
    <aside className="settings-navigation">
      <button className="settings-back" onClick={onClose} disabled={installing}><ArrowLeft size={17} />返回工作区</button>
      <h1>设置</h1>
      <div className="settings-nav" role="tablist" aria-label="设置类别" aria-orientation="vertical" onKeyDown={event => {
        if (!["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        if (installing) return;
        const index = tabs.findIndex(([key]) => key === tab);
        const next = tabs[event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowDown" ? 1 : -1) + tabs.length) % tabs.length][0];
        setTab(next); root.current?.querySelector<HTMLButtonElement>(`#settings-tab-${next}`)?.focus();
      }}>
        {tabs.map(([key, label]) => <button key={key} type="button" role="tab" id={`settings-tab-${key}`} aria-controls={`settings-${key}`} aria-selected={tab === key} tabIndex={tab === key ? 0 : -1} onClick={() => setTab(key)} disabled={installing && key !== "updates"}>{label}</button>)}
      </div>
      <button className="text-button settings-theme" onClick={onThemeChange}>{theme === "light" ? <Moon size={16} /> : <Sun size={16} />}{theme === "light" ? "切换深色" : "切换浅色"}</button>
    </aside>
    <main className="settings-content">
      <div className="settings-content-inner">
        <header className="settings-heading"><h2>{tabs.find(([key]) => key === tab)?.[1]}</h2></header>
        <div hidden={tab !== "workspace"}><WorkspacePane active={isOpen && tab === "workspace"} onOpened={onClose} /></div>
        <div hidden={tab !== "model"}><ModelPane /></div>
        <div hidden={tab !== "network"}><ProxyPane /></div>
        <div hidden={tab !== "performance"}><PerformancePane /></div>
        <div hidden={tab !== "tools"}><ToolsPane active={isOpen && tab === "tools"} /></div>
        <div hidden={tab !== "updates"}><UpdatesPane /></div>
      </div>
    </main>
  </div>;
}

function ModelPane() {
  const [providers, setProviders] = useState(llmService.getProviders());
  const [providerId, setProviderId] = useState(llmService.getActiveProviderId());
  const [url, setUrl] = useState(llmService.getBaseUrl());
  const [name, setName] = useState(llmService.getActiveProvider()?.name || "");
  const [apiKey, setApiKey] = useState(llmService.getApiKey());
  const [model, setModel] = useState(llmService.getModel());
  const [pending, setPending] = useState<"test" | "models" | null>(null);
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const selectProvider = (id: string) => {
    const provider = providers.find(item => item.id === id);
    setProviderId(provider?.id || ""); setUrl(provider?.baseUrl || ""); setName(provider?.name || ""); setApiKey(provider?.apiKey || ""); setModels([]); setResult(""); setError("");
  };
  const save = (requireModel = true) => {
    setError(""); setResult("");
    try {
      if (!url.trim()) throw new Error("请填写 API 地址");
      let parsed: URL;
      try { parsed = new URL(url); } catch { throw new Error("API 地址格式不正确"); }
      if (!["https:", "http:"].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error("请使用 HTTP 或 HTTPS 地址，密钥单独填写");
      if (requireModel && !model.trim()) throw new Error("请填写模型 ID，或读取模型列表后选择");
      const id = providerId || crypto.randomUUID();
      llmService.addProvider({ id, name: name.trim() || deriveProviderName(url), baseUrl: url.trim().replace(/\/+$/, ""), apiKey: apiKey.trim() });
      if (model.trim()) llmService.setModel(model.trim());
      setProviderId(id); setProviders(llmService.getProviders()); setResult("已保存"); return true;
    } catch (err) { setError(err instanceof Error ? err.message : "保存失败"); return false; }
  };
  const request = async (action: "test" | "models") => {
    if (!save(action === "test")) return;
    setPending(action); setResult("");
    try {
      if (action === "test") {
        const response = await llmService.checkHealth();
        if (!response.ok) throw new Error(response.error || "连接失败，请检查地址和密钥");
        setResult("连接成功");
      } else {
        const list = await llmService.fetchModels(); setModels(list);
        setResult(list.length ? `已读取 ${list.length} 个模型` : "未获取到模型列表，可直接填写模型 ID");
      }
    } catch (err) { setError(err instanceof Error ? err.message : "请求失败，请重试"); }
    finally { setPending(null); }
  };
  return <form noValidate id="settings-model" role="tabpanel" aria-labelledby="settings-tab-model" className="settings-fields model-pane" onSubmit={event => { event.preventDefault(); save(); }}>
    {providers.length > 0 && <div className="provider-row"><label>提供商<Select label="提供商" value={providerId || "new"} onChange={selectProvider} disabled={Boolean(pending)} options={[...providers.map(item => ({ value: item.id, label: item.name })), { value: "new", label: "新增提供商" }]} /></label><button type="button" className="icon-button" aria-label="新增提供商" disabled={Boolean(pending)} onClick={() => selectProvider("")}><Plus size={18} /></button></div>}
    <label>名称<input value={name} onChange={event => setName(event.target.value)} placeholder="可选，默认使用服务名称" disabled={Boolean(pending)} /></label>
    <label>API 地址<input type="url" required value={url} onChange={event => setUrl(event.target.value)} placeholder="https://api.example.com/v1" spellCheck={false} disabled={Boolean(pending)} /></label>
    <label>API Key<input type="password" value={apiKey} onChange={event => setApiKey(event.target.value)} autoComplete="off" disabled={Boolean(pending)} /></label>
    <div className="model-field"><label>模型 ID<input required value={model} onChange={event => setModel(event.target.value)} placeholder="填写模型 ID" spellCheck={false} disabled={Boolean(pending)} /></label><button type="button" className="secondary-button" disabled={Boolean(pending)} onClick={() => void request("models")}>{pending === "models" && <Loader2 size={14} className="loading-spinner" />}读取模型列表</button></div>
    {models.length > 0 && <Select label="选择可用模型" placeholder="选择可用模型" value={models.includes(model) ? model : ""} onChange={setModel} options={models.map(id => ({ value: id, label: id }))} />}
    <small>保存后用于新 Goal。密钥保存在本机；测试连接会发送一条短请求。</small>
    <div className="settings-feedback" aria-live="polite">{error ? <p className="field-error" role="alert">{error}</p> : <p role="status">{result}</p>}</div>
    <footer className="settings-actions"><button type="button" className="secondary-button" onClick={() => void request("test")} disabled={Boolean(pending)}>{pending === "test" && <Loader2 size={14} className="loading-spinner" />}{pending === "test" ? "正在连接" : "保存并测试"}</button><button className="primary-button" type="submit" disabled={Boolean(pending)}>保存</button></footer>
  </form>;
}
