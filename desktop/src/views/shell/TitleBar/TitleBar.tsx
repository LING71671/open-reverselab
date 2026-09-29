import { Minus, Square, X } from "lucide-react";
import { Logo } from "../Logo";

export function TitleBar({ title }: { title?: string }) {
  const handleMinimize = async () => {
    try {
      const { getCurrentWindow } = await import("@tauri-apps/api/window");
      await getCurrentWindow().minimize();
    } catch (e) {
      console.warn("Window minimize error:", e);
    }
  };

  const handleMaximize = async () => {
    try {
      const { getCurrentWindow } = await import("@tauri-apps/api/window");
      await getCurrentWindow().toggleMaximize();
    } catch (e) {
      console.warn("Window maximize error:", e);
    }
  };

  const handleClose = async () => {
    try {
      const { getCurrentWindow } = await import("@tauri-apps/api/window");
      await getCurrentWindow().close();
    } catch (e) {
      console.warn("Window close error:", e);
    }
  };

  return (
    <div
      data-tauri-drag-region
      className="h-10 w-full bg-[#09090b] border-b border-zinc-900 flex items-center justify-between px-3 select-none shrink-0 z-50 text-zinc-400 font-sans"
    >
      <div className="flex items-center gap-3 pointer-events-none">
        <div className="flex items-center gap-2.5">
          <Logo size={14} className="text-zinc-100" />
          <span className="text-xs font-semibold tracking-wider text-zinc-200">
            REVERSE-LAB
          </span>
        </div>
        {title && (
          <div className="flex items-center gap-1.5 pl-3 border-l border-zinc-800 text-[11px] font-mono text-zinc-500">
            <span>/</span>
            <span className="text-zinc-300 truncate max-w-xs">{title}</span>
          </div>
        )}
      </div>

      <div data-tauri-drag-region className="flex-1 h-full"></div>

      <div className="flex items-center">
        <button
          onClick={handleMinimize}
          className="h-7 w-9 flex items-center justify-center hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition-colors rounded-sm"
          title="Minimize"
        >
          <Minus className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={handleMaximize}
          className="h-7 w-9 flex items-center justify-center hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition-colors rounded-sm"
          title="Maximize"
        >
          <Square className="w-3 h-3" />
        </button>
        <button
          onClick={handleClose}
          className="h-7 w-9 flex items-center justify-center hover:bg-rose-950/80 hover:text-rose-200 text-zinc-400 transition-colors rounded-sm"
          title="Close"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
