import { useEffect, useRef, useState } from "react";
import { llmService } from "../../services/llm/llmService";
import { Select } from "../controls/Select";

export function ModelControl({ active, isRunning, onSettings }: { active: boolean; isRunning: boolean; onSettings: () => void }) {
  const provider = llmService.getActiveProvider();
  const currentModel = llmService.getModel();
  const [model, setModel] = useState(currentModel);
  const [models, setModels] = useState(() => llmService.getCachedModels());
  const [pending, setPending] = useState(false);
  const [empty, setEmpty] = useState(false);
  const requestId = useRef(0);
  useEffect(() => {
    setModel(currentModel); setModels(llmService.getCachedModels()); setPending(false); setEmpty(false);
    return () => { requestId.current++; };
  }, [active, provider?.id, provider?.baseUrl, provider?.apiKey, currentModel]);
  const load = async (open: boolean) => {
    if (!open || !provider || pending || models.length) return;
    const id = ++requestId.current;
    setPending(true); setEmpty(false);
    try {
      const list = await llmService.fetchModels(provider.id);
      if (id === requestId.current) { setModels(list); setEmpty(!list.length); }
    } finally { if (id === requestId.current) setPending(false); }
  };
  if (!provider) return <button type="button" className="text-button model-control" onClick={onSettings}>配置模型</button>;
  const options = [...new Set([model, ...models].filter(Boolean))].map(id => ({ value: id, label: id }));
  const status = pending ? "正在读取模型" : empty ? "未获取到模型列表" : "读取模型列表";
  return <div className="composer-model">
    <button type="button" className="text-button model-provider" onClick={onSettings} title="模型设置">{provider.name}</button>
    <span className="model-divider" aria-hidden="true">/</span>
    <Select className="model-control" label="切换模型" value={model} placeholder="选择模型" disabled={isRunning}
      onOpenChange={open => { void load(open); }}
      onChange={value => { llmService.setModel(value); setModel(value); }}
      options={models.length ? options : [...options, { value: "__model_list_status__", label: status, disabled: true }]} />
  </div>;
}
