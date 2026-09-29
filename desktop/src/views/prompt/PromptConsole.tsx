import React, { useState, useRef, useEffect } from "react";
import { ArrowUp, Square, Paperclip, UploadCloud } from "lucide-react";
import { HarnessMode, useI18n } from "../../core";
import { logger } from "../../services";

interface PromptConsoleProps {
  isRunning: boolean;
  onExecute: (target: string, prompt: string, mode: HarnessMode) => void;
  onStop?: () => void;
  defaultTarget?: string;
}

export function PromptConsole({
  isRunning,
  onExecute,
  onStop,
  defaultTarget = "",
}: PromptConsoleProps) {
  const { t } = useI18n();
  const [target, setTarget] = useState(defaultTarget);
  const [prompt, setPrompt] = useState("");
  const [isEditingTarget, setIsEditingTarget] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setTarget(defaultTarget || "");
  }, [defaultTarget]);

  const handleSubmit = (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!prompt.trim() || isRunning) return;
    onExecute(target.trim(), prompt.trim(), "wish");
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleFileChosen = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const buffer = await file.arrayBuffer();
      const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const sha256 = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");

      // Magic byte detection
      const uint8 = new Uint8Array(buffer.slice(0, 4));
      let fileType = "Unknown Binary";
      if (uint8[0] === 0x4d && uint8[1] === 0x5a) {
        fileType = "PE";
      } else if (uint8[0] === 0x50 && uint8[1] === 0x4b) {
        fileType = "APK/ZIP";
      } else if (uint8[0] === 0x7f && uint8[1] === 0x45 && uint8[2] === 0x4c && uint8[3] === 0x46) {
        fileType = "ELF";
      }

      setTarget(file.name);
      logger.info(
        "triage",
        `Sample: ${file.name} (${(file.size / 1024).toFixed(1)} KB) · ${fileType}`,
        { sha256, sizeBytes: file.size, fileType }
      );
    } catch (err: any) {
      logger.error("triage", `Read error: ${err.message}`);
    }
  };

  return (
    <div className="w-full">
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileChosen}
        className="hidden"
      />

      <div className="rounded-xl bg-[#121215]/70 border border-zinc-800/70 shadow-2xl backdrop-blur-md transition-all duration-200 focus-within:border-zinc-700/80 focus-within:ring-1 focus-within:ring-zinc-700/40">
        {/* 1. Main Text Input Area */}
        <div className="p-3 pb-1.5">
          <textarea
            ref={textareaRef}
            rows={2}
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={t.prompt.wishPlaceholder}
            className="w-full bg-transparent text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none resize-none font-sans leading-relaxed"
          />
        </div>

        {/* 2. Unified Bottom Actions Toolbar */}
        <div className="px-2.5 pb-2 pt-1 flex items-center justify-between gap-2 border-t border-zinc-900/60">
          {/* Left: Target File Attachment */}
          <div className="flex items-center gap-1.5 overflow-x-auto min-w-0">
            {isEditingTarget ? (
              <input
                type="text"
                autoFocus
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onBlur={() => setIsEditingTarget(false)}
                onKeyDown={(e) => e.key === "Enter" && setIsEditingTarget(false)}
                className="px-2 py-0.5 rounded bg-zinc-950 border border-zinc-700 text-[11px] font-mono text-zinc-200 focus:outline-none shrink-0"
              />
            ) : (
              <div className="flex items-center gap-1 shrink min-w-0">
                <button
                  type="button"
                  onClick={() => setIsEditingTarget(true)}
                  title={t.common.target}
                  className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-zinc-900/80 hover:bg-zinc-800 border border-zinc-800/80 text-[11px] font-medium text-zinc-300 transition-all active:scale-95 cursor-pointer truncate max-w-[200px]"
                >
                  <Paperclip className="w-3 h-3 text-zinc-400 shrink-0" />
                  <span className="truncate">{target || t.common.target}</span>
                </button>

                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  title={t.common.target}
                  className="p-1 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition-all active:scale-95 cursor-pointer shrink-0"
                >
                  <UploadCloud className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          {/* Right: Submit / Stop Button */}
          <div className="flex items-center shrink-0">
            {isRunning ? (
              <button
                type="button"
                onClick={onStop}
                title={t.common.stop}
                className="w-7 h-7 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 flex items-center justify-center transition-all duration-200 active:scale-90 animate-pulse cursor-pointer shadow-sm"
              >
                <Square className="w-3 h-3 fill-rose-300" />
              </button>
            ) : (
              <button
                type="button"
                onClick={handleSubmit}
                disabled={!prompt.trim()}
                title={t.common.run}
                className="w-7 h-7 rounded-lg bg-zinc-100 hover:bg-white text-zinc-950 flex items-center justify-center transition-all duration-200 active:scale-90 disabled:opacity-20 disabled:hover:bg-zinc-100 cursor-pointer shadow-sm"
              >
                <ArrowUp className="w-3.5 h-3.5 stroke-[2.5]" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
