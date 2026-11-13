import { useEffect, useRef, useState, type PointerEvent } from "react";

export function usePaneSize(key: string, initial: number) {
  const [size, setSize] = useState(() => {
    try { const saved = Number(localStorage.getItem(`reverselab_layout_${key}`)); return saved > 0 && Number.isFinite(saved) ? saved : initial; } catch { return initial; }
  });
  useEffect(() => { try { localStorage.setItem(`reverselab_layout_${key}`, String(size)); } catch { /* Session layout still works. */ } }, [key, size]);
  return [size, setSize] as const;
}

interface ResizeHandleProps {
  label: string;
  axis: "x" | "y";
  size: number;
  min: number;
  max: number;
  initial: number;
  reverse?: boolean;
  onChange: (size: number) => void;
}
export function ResizeHandle({ label, axis, size, min, max, initial, reverse = false, onChange }: ResizeHandleProps) {
  const drag = useRef<{ start: number; size: number } | null>(null);
  const [resizing, setResizing] = useState(false);
  const clamp = (value: number) => Math.round(Math.max(min, Math.min(max, value)));
  const stop = () => { drag.current = null; setResizing(false); };
  const move = (event: PointerEvent) => {
    if (!drag.current) return;
    const delta = (axis === "x" ? event.clientX : event.clientY) - drag.current.start;
    onChange(clamp(drag.current.size + delta * (reverse ? -1 : 1)));
  };
  return <div className={`resize-handle resize-${axis}`} data-resizing={resizing} role="separator" aria-label={label} aria-orientation={axis === "x" ? "vertical" : "horizontal"} aria-valuenow={clamp(size)} aria-valuemin={min} aria-valuemax={max} tabIndex={0}
    onPointerDown={event => { if (event.button !== 0) return; event.preventDefault(); event.currentTarget.setPointerCapture(event.pointerId); drag.current = { start: axis === "x" ? event.clientX : event.clientY, size: clamp(size) }; setResizing(true); }}
    onPointerMove={move} onPointerUp={stop} onPointerCancel={stop} onLostPointerCapture={stop}
    onDoubleClick={() => onChange(initial)}
    onKeyDown={event => {
      const backward = axis === "x" ? "ArrowLeft" : "ArrowUp";
      const forward = axis === "x" ? "ArrowRight" : "ArrowDown";
      if (![backward, forward, "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      onChange(event.key === "Home" ? min : event.key === "End" ? max : clamp(size + (event.key === forward ? 1 : -1) * (reverse ? -1 : 1) * (event.shiftKey ? 32 : 8)));
    }} />;
}
