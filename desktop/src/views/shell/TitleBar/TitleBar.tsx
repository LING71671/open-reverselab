import { Minus, Square, X } from "lucide-react";
import { isTauri } from "@tauri-apps/api/core";
import { Logo } from "../Logo";
export function TitleBar() {
  const native = isTauri();
  const windowAction = async (action: "minimize" | "toggleMaximize" | "close" | "startDragging") => {
    if (!native) return;
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    await getCurrentWindow()[action]();
  };
  return <div className="app-titlebar" data-tauri-drag-region onMouseDown={e => { if (e.button === 0 && !(e.target as HTMLElement).closest("button")) void windowAction("startDragging"); }} onDoubleClick={e => { if (!(e.target as HTMLElement).closest("button")) void windowAction("toggleMaximize"); }}>
    <span className="app-brand"><Logo size={22} /><span>ReverseLab</span></span><span className="grow" />
    {native && <div className="window-actions"><button aria-label="最小化" onClick={() => void windowAction("minimize")}><Minus size={14} /></button><button aria-label="最大化" onClick={() => void windowAction("toggleMaximize")}><Square size={12} /></button><button aria-label="关闭窗口" onClick={() => void windowAction("close")}><X size={16} /></button></div>}
  </div>;
}
