import { useEffect, useState, type FormEvent } from "react";
import { ArrowUp, SlidersHorizontal, Square } from "lucide-react";
import { isTauri } from "@tauri-apps/api/core";
import type { HarnessMode, RunBudget } from "../../core";
import { llmService } from "../../services/llm/llmService";

interface PromptConsoleProps {
  active: boolean;
  isRunning: boolean;
  onExecute: (target: string, prompt: string, mode: HarnessMode, budget?: RunBudget) => void | Promise<void>;
  onStop?: () => void;
  onSettings: () => void;
  draft: ComposerDraft;
  onDraftChange: (changes: Partial<ComposerDraft>) => void;
}
export interface ComposerDraft {
  target: string;
  prompt: string;
  limitsOpen: boolean;
  minutes: string;
  tokens: string;
}
export function PromptConsole({ active, isRunning, onExecute, onStop, onSettings, draft, onDraftChange }: PromptConsoleProps) {
  const { target, prompt, limitsOpen, minutes, tokens } = draft;
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  useEffect(() => {
    if (!active || !isTauri() || isRunning) return;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void import("@tauri-apps/api/webview").then(async ({ getCurrentWebview }) => {
      const remove = await getCurrentWebview().onDragDropEvent(({ payload }) => {
        if (disposed) return;
        setDragging(payload.type === "over");
        if (payload.type === "drop" && payload.paths[0]) onDraftChange({ target: payload.paths[0] });
      });
      if (disposed) remove(); else unlisten = remove;
    }).catch(() => { /* Manual target input remains available. */ });
    return () => { disposed = true; unlisten?.(); setDragging(false); };
  }, [active, isRunning, onDraftChange]);
  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (isRunning) return;
    if (!target.trim() || !prompt.trim()) { setError("请填写目标和任务内容"); return; }
    const budget = minutes || tokens ? { maxDurationMs: minutes ? Number(minutes) * 60000 : 600000, maxTokens: tokens ? Number(tokens) : 32000 } : undefined;
    if (budget && (!Number.isFinite(budget.maxDurationMs) || budget.maxDurationMs <= 0 || !Number.isSafeInteger(budget.maxTokens) || budget.maxTokens < 1)) { setError("运行上限需要为正数，Token 需要为整数"); return; }
    setError("");
    try { await onExecute(target, prompt, "wish", budget); } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };
  return <form className="goal-composer" data-dragging={dragging} onSubmit={submit}>
    <label className="target-field"><span>目标</span><input aria-label="目标" value={target} onChange={e => onDraftChange({ target: e.target.value })} placeholder="文件、目录或 URL" readOnly={isRunning} required spellCheck={false} /></label>
    <label className="objective-field"><span className="sr-only">Goal</span><textarea aria-label="Goal" value={prompt} onChange={e => onDraftChange({ prompt: e.target.value })} placeholder="描述要完成的任务" readOnly={isRunning} required rows={2} onKeyDown={e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); void submit(); } }} /></label>
    {limitsOpen && <div className="budget-fields"><label>时间上限 · 分钟<input type="number" aria-label="时间上限（分钟）" min="0.01" step="any" placeholder="10" value={minutes} onChange={e => onDraftChange({ minutes: e.target.value })} disabled={isRunning} /></label><label>Token 上限<input type="number" aria-label="Token 上限" min="1" step="1" placeholder="32000" value={tokens} onChange={e => onDraftChange({ tokens: e.target.value })} disabled={isRunning} /></label><small>留空使用默认上限：10 分钟 / 32,000 tokens</small></div>}
    {error && <p className="composer-error" role="alert">{error}</p>}
    <div className="composer-actions"><button type="button" className="text-button model-control" onClick={onSettings} title="模型设置">{llmService.getActiveProvider()?.name || "配置模型"}{llmService.getActiveProvider() && <span> / {llmService.getModel() || "选择模型"}</span>}</button><span className="grow" /><button type="button" className="text-button" aria-expanded={limitsOpen} onClick={() => onDraftChange({ limitsOpen: !limitsOpen })} title="可选的时间和 Token 上限"><SlidersHorizontal size={15} />运行限制{minutes || tokens ? " · 已设置" : ""}</button>{isRunning ? <button type="button" className="primary-button" onClick={onStop}><Square size={13} />停止</button> : <button type="submit" className="primary-button" disabled={!target.trim() || !prompt.trim()} title="开始 Goal · Ctrl+Enter">开始<ArrowUp size={15} /></button>}</div>
  </form>;
}
