import { useEffect, useRef } from "react";
import { X } from "lucide-react";
import type { GraphStep } from "../../core";
import { ResizeHandle, usePaneSize } from "../controls/ResizeHandle";
export function DetailDrawer({ step, onClose }: { step: GraphStep | null; onClose: () => void }) {
  const [width, setWidth] = usePaneSize("details", 360);
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!step) return;
    const previous = document.activeElement as HTMLElement | null;
    close.current?.focus();
    return () => previous?.focus();
  }, [step?.id]);
  if (!step) return null;
  return <aside className="step-drawer" style={{ width }} aria-label="流程节点详情" onKeyDown={e => { if (e.key === "Escape") onClose(); }}><ResizeHandle label="调整详情宽度" axis="x" reverse size={width} min={280} max={600} initial={360} onChange={setWidth} /><header><span>{step.agentId}</span><button ref={close} className="icon-button" aria-label="关闭节点详情" onClick={onClose}><X size={17} /></button></header><div className="step-drawer-content"><h2>{step.title}</h2><small>{step.status} · {new Date(step.timestamp).toLocaleTimeString()}</small><p>{step.detail}</p>{step.kbRef && <section><h3>知识库引用</h3><code>{step.kbRef}</code></section>}{step.evidence && <section><h3>证据</h3><pre>{JSON.stringify(step.evidence, null, 2)}</pre></section>}<footer>{step.id}</footer></div></aside>;
}
