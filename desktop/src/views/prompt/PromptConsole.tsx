import React, { useState, useRef, useEffect, useMemo, useCallback } from "react";
import {
  ArrowUp,
  Square,
  Paperclip,
  UploadCloud,
  ChevronDown,
  Check,
  Plus,
  Trash2,
  RotateCw,
  Loader2,
  X,
} from "lucide-react";
import { HarnessMode, useI18n } from "../../core";
import { logger, llmService } from "../../services";
import { ProviderConfig, deriveProviderName } from "../../services/llm/llmService";

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
  const [isDraggingOver, setIsDraggingOver] = useState(false);

  // Providers & Models hierarchy
  const [providers, setProviders] = useState<ProviderConfig[]>(() => llmService.getProviders());
  const [activeProviderId, setActiveProviderId] = useState<string>(() =>
    llmService.getActiveProviderId()
  );
  const [models, setModels] = useState<string[]>([]);
  const [isLoadingModels, setIsLoadingModels] = useState(false);
  const [selectedModel, setSelectedModel] = useState<string>(() => llmService.getModel() || "");
  const [isModelMenuOpen, setIsModelMenuOpen] = useState(false);
  const [modelFilter, setModelFilter] = useState("");

  // Provider creation form
  const [isAddingProvider, setIsAddingProvider] = useState(false);
  const [newProvName, setNewProvName] = useState("");
  const [newProvUrl, setNewProvUrl] = useState("");
  const [newProvKey, setNewProvKey] = useState("");

  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const modelMenuRef = useRef<HTMLDivElement>(null);
  const filterInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setTarget(defaultTarget || "");
  }, [defaultTarget]);

  const activeProvider = useMemo(() => {
    return providers.find((p) => p.id === activeProviderId) || providers[0];
  }, [providers, activeProviderId]);

  const loadModelsForProvider = useCallback(async (providerId?: string) => {
    setIsLoadingModels(true);
    try {
      const fetched = await llmService.fetchModels(providerId);
      setModels(fetched);
      if (!llmService.getModel() && fetched.length > 0) {
        setSelectedModel(fetched[0]);
        llmService.setModel(fetched[0]);
      }
    } catch {
      setModels([]);
    } finally {
      setIsLoadingModels(false);
    }
  }, []);

  useEffect(() => {
    if (activeProvider?.id) {
      loadModelsForProvider(activeProvider.id);
    }
  }, [activeProvider?.id, loadModelsForProvider]);

  // Dismiss menu on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (modelMenuRef.current && !modelMenuRef.current.contains(e.target as Node)) {
        setIsModelMenuOpen(false);
        setIsAddingProvider(false);
        setModelFilter("");
      }
    };
    if (isModelMenuOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      setTimeout(() => filterInputRef.current?.focus(), 50);
    }
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [isModelMenuOpen]);

  const handleSelectProvider = (id: string) => {
    setActiveProviderId(id);
    llmService.setActiveProviderId(id);
    setIsAddingProvider(false);
  };

  const handleSaveNewProvider = (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!newProvUrl.trim()) return;
    const newP: ProviderConfig = {
      id: `prov-${Date.now()}`,
      name: newProvName.trim() || deriveProviderName(newProvUrl.trim()),
      baseUrl: newProvUrl.trim(),
      apiKey: newProvKey.trim() || undefined,
    };
    llmService.addProvider(newP);
    setProviders(llmService.getProviders());
    setActiveProviderId(newP.id);
    setIsAddingProvider(false);
    setNewProvName("");
    setNewProvUrl("");
    setNewProvKey("");
  };

  const handleDeleteProvider = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    llmService.removeProvider(id);
    const updated = llmService.getProviders();
    setProviders(updated);
    setActiveProviderId(llmService.getActiveProviderId());
  };

  const handleSelectModel = (modelId: string) => {
    const trimmed = modelId.trim();
    if (!trimmed) return;
    setSelectedModel(trimmed);
    llmService.setModel(trimmed);
    setIsModelMenuOpen(false);
    setModelFilter("");
    logger.info("llm", `Model: ${trimmed}`);
  };

  const filteredModels = useMemo(() => {
    const q = modelFilter.trim().toLowerCase();
    if (!q) return models;
    return models.filter((m) => m.toLowerCase().includes(q));
  }, [models, modelFilter]);

  const hasExactMatch = useMemo(() => {
    const q = modelFilter.trim().toLowerCase();
    return models.some((m) => m.toLowerCase() === q);
  }, [models, modelFilter]);

  // Native Tauri drag-drop
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        const { getCurrentWebview } = await import("@tauri-apps/api/webview");
        unlisten = await getCurrentWebview().onDragDropEvent((event) => {
          if (event.payload.type === "over") {
            setIsDraggingOver(true);
          } else if (event.payload.type === "drop" && event.payload.paths.length > 0) {
            setIsDraggingOver(false);
            const droppedPath = event.payload.paths[0];
            setTarget(droppedPath);
            logger.info("triage", `Target: ${droppedPath}`);
          } else {
            setIsDraggingOver(false);
          }
        });
      } catch {
        // web fallback
      }
    })();
    return () => {
      unlisten?.();
    };
  }, []);

  const handleSubmit = (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!prompt.trim() || isRunning) return;
    const currentTarget = target.trim();
    const currentPrompt = prompt.trim();
    setPrompt(""); // Immediately clear input field upon submission
    onExecute(currentTarget, currentPrompt, "wish");
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const processFile = async (file: File) => {
    try {
      setTarget(file.name);
      logger.info("triage", `Target: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
    } catch (err: any) {
      logger.error("triage", `${err.message}`);
    }
  };

  const handleFileChosen = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      await processFile(files[0]);
    }
  };

  return (
    <div
      className={`relative w-full rounded-2xl border transition-all duration-200 bg-[#0e0e11]/90 backdrop-blur-xl shadow-2xl ${
        isDraggingOver
          ? "border-emerald-500/80 ring-2 ring-emerald-500/20 bg-emerald-950/10"
          : "border-zinc-800/80 hover:border-zinc-700/80 focus-within:border-zinc-600/80"
      }`}
      onDragOver={(e) => {
        e.preventDefault();
        setIsDraggingOver(true);
      }}
      onDragLeave={() => setIsDraggingOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setIsDraggingOver(false);
        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
          processFile(files[0]);
        }
      }}
    >
      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        onChange={handleFileChosen}
        title="Choose target file"
      />

      {isDraggingOver && (
        <div className="absolute inset-0 z-20 rounded-2xl flex flex-col items-center justify-center bg-zinc-950/85 backdrop-blur-sm border-2 border-dashed border-emerald-500/60 pointer-events-none">
          <UploadCloud className="w-8 h-8 text-emerald-400 mb-2 animate-bounce" />
          <div className="text-xs font-mono font-medium text-emerald-300">Drop target file</div>
        </div>
      )}

      <div className="p-3">
        {/* Target Header */}
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-zinc-800/50 text-[11px] font-mono">
          <div className="flex items-center gap-1.5 text-zinc-400 min-w-0">
            <span className="text-zinc-500 shrink-0 uppercase tracking-wider text-[10px]">
              TARGET:
            </span>
            {isEditingTarget ? (
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onBlur={() => setIsEditingTarget(false)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") setIsEditingTarget(false);
                }}
                autoFocus
                placeholder="sample.exe / https://..."
                className="bg-zinc-900 border border-zinc-700 rounded px-1.5 py-0.5 text-xs text-zinc-200 focus:outline-none focus:border-zinc-500 w-64"
              />
            ) : (
              <span
                onClick={() => setIsEditingTarget(true)}
                className="text-zinc-300 hover:text-white cursor-pointer truncate max-w-[280px] bg-zinc-900/60 px-2 py-0.5 rounded border border-zinc-800/60 hover:border-zinc-700 transition"
                title="Click to edit target"
              >
                {target || "No target (click to set)"}
              </span>
            )}
          </div>
        </div>

        {/* Input Textarea */}
        <textarea
          ref={textareaRef}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Instruction..."
          rows={3}
          className="w-full bg-transparent resize-none text-xs font-mono text-zinc-100 placeholder-zinc-600 focus:outline-none leading-relaxed"
        />

        {/* Bottom Toolbar */}
        <div className="flex items-center justify-between pt-2 mt-1 border-t border-zinc-800/40">
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              title="Attach file"
              className="p-1.5 rounded-lg text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/60 transition-all cursor-pointer"
            >
              <Paperclip className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="flex items-center gap-2">
            {/* 2-Tier Provider/Model Picker */}
            <div className="relative" ref={modelMenuRef}>
              <button
                type="button"
                onClick={() => setIsModelMenuOpen(!isModelMenuOpen)}
                className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-zinc-900/80 hover:bg-zinc-800 border border-zinc-800/80 text-xs font-mono text-zinc-400 hover:text-zinc-200 transition-all active:scale-95 cursor-pointer"
              >
                <span className="text-zinc-500 max-w-[70px] truncate">
                  {activeProvider?.name || "Provider"}
                </span>
                <span className="text-zinc-700">/</span>
                <span className="text-zinc-300 max-w-[130px] truncate font-medium">
                  {selectedModel || "Select Model"}
                </span>
                <ChevronDown className="w-3 h-3 text-zinc-500 shrink-0 ml-0.5" />
              </button>

              {isModelMenuOpen && (
                <div className="absolute right-0 bottom-full mb-1.5 w-[460px] rounded-xl bg-[#121215] border border-zinc-800 shadow-2xl p-0 z-50 animate-in fade-in zoom-in-95 duration-100 backdrop-blur-xl flex divide-x divide-zinc-800/80 overflow-hidden">
                  {/* Tier 1: Providers 一级栏 */}
                  <div className="w-44 flex flex-col p-1.5 bg-zinc-950/40">
                    <div className="flex items-center justify-between px-2 py-1 mb-1 border-b border-zinc-800/60">
                      <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider font-semibold">
                        Provider
                      </span>
                      <button
                        type="button"
                        onClick={() => setIsAddingProvider(!isAddingProvider)}
                        title="Add Provider"
                        className="p-0.5 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition cursor-pointer"
                      >
                        {isAddingProvider ? (
                          <X className="w-3 h-3" />
                        ) : (
                          <Plus className="w-3 h-3" />
                        )}
                      </button>
                    </div>

                    {isAddingProvider ? (
                      <form onSubmit={handleSaveNewProvider} className="p-1 space-y-1.5">
                        <input
                          type="text"
                          value={newProvName}
                          onChange={(e) => setNewProvName(e.target.value)}
                          placeholder="Name..."
                          className="w-full px-2 py-1 rounded bg-zinc-900 border border-zinc-800 text-[11px] font-mono text-zinc-200 focus:outline-none focus:border-zinc-700"
                        />
                        <input
                          type="text"
                          value={newProvUrl}
                          onChange={(e) => setNewProvUrl(e.target.value)}
                          placeholder="Base URL..."
                          className="w-full px-2 py-1 rounded bg-zinc-900 border border-zinc-800 text-[11px] font-mono text-zinc-200 focus:outline-none focus:border-zinc-700"
                        />
                        <input
                          type="password"
                          value={newProvKey}
                          onChange={(e) => setNewProvKey(e.target.value)}
                          placeholder="API Key..."
                          className="w-full px-2 py-1 rounded bg-zinc-900 border border-zinc-800 text-[11px] font-mono text-zinc-200 focus:outline-none focus:border-zinc-700"
                        />
                        <div className="flex gap-1 pt-0.5">
                          <button
                            type="submit"
                            disabled={!newProvUrl.trim()}
                            className="flex-1 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-[10px] font-mono text-zinc-200 disabled:opacity-40 cursor-pointer"
                          >
                            Save
                          </button>
                          <button
                            type="button"
                            onClick={() => setIsAddingProvider(false)}
                            className="px-2 py-1 rounded bg-zinc-900 text-[10px] font-mono text-zinc-500 hover:text-zinc-300 cursor-pointer"
                          >
                            Cancel
                          </button>
                        </div>
                      </form>
                    ) : (
                      <div className="flex-1 space-y-0.5 max-h-56 overflow-y-auto">
                        {providers.map((p) => {
                          const isActive = p.id === activeProvider?.id;
                          return (
                            <div
                              key={p.id}
                              onClick={() => handleSelectProvider(p.id)}
                              className={`group flex items-center justify-between px-2 py-1.5 rounded-lg text-left text-xs font-mono transition-colors cursor-pointer ${
                                isActive
                                  ? "bg-zinc-800 text-zinc-100 font-medium"
                                  : "text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200"
                              }`}
                            >
                              <span className="truncate flex-1">{p.name}</span>
                              {providers.length > 1 && (
                                <button
                                  type="button"
                                  onClick={(e) => handleDeleteProvider(e, p.id)}
                                  className="opacity-0 group-hover:opacity-100 text-zinc-600 hover:text-rose-400 transition p-0.5 cursor-pointer"
                                >
                                  <Trash2 className="w-3 h-3" />
                                </button>
                              )}
                            </div>
                          );
                        })}
                        {providers.length === 0 && (
                          <div className="p-2 text-center text-[11px] font-mono text-zinc-600">
                            No providers. Click + to add.
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Tier 2: Models 二级栏 */}
                  <div className="flex-1 flex flex-col p-1.5 min-w-0">
                    <div className="flex items-center justify-between px-2 py-1 mb-1 border-b border-zinc-800/60">
                      <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider font-semibold truncate">
                        Model
                      </span>
                      <button
                        type="button"
                        onClick={() => loadModelsForProvider(activeProvider?.id)}
                        disabled={isLoadingModels}
                        title="Refresh models"
                        className="p-0.5 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition cursor-pointer"
                      >
                        <RotateCw
                          className={`w-3 h-3 ${isLoadingModels ? "animate-spin text-zinc-400" : ""}`}
                        />
                      </button>
                    </div>

                    {/* Filter / Custom Model Input */}
                    <div className="p-1 mb-1">
                      <input
                        ref={filterInputRef}
                        type="text"
                        value={modelFilter}
                        onChange={(e) => setModelFilter(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && modelFilter.trim()) {
                            handleSelectModel(modelFilter.trim());
                          }
                        }}
                        placeholder="Model or custom..."
                        className="w-full px-2 py-1 rounded bg-zinc-950/80 border border-zinc-800 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-700"
                      />
                    </div>

                    {/* Model List */}
                    <div className="flex-1 space-y-0.5 max-h-52 overflow-y-auto">
                      {modelFilter.trim() && !hasExactMatch && (
                        <button
                          type="button"
                          onClick={() => handleSelectModel(modelFilter.trim())}
                          className="w-full flex items-center justify-between px-2 py-1.5 rounded-lg text-left text-xs font-mono text-zinc-200 hover:bg-zinc-800/60 cursor-pointer border border-dashed border-zinc-800"
                        >
                          <span className="truncate">{modelFilter.trim()}</span>
                          <span className="text-[10px] text-zinc-500 font-mono">Enter</span>
                        </button>
                      )}

                      {isLoadingModels && models.length === 0 ? (
                        <div className="py-6 flex flex-col items-center justify-center gap-1.5 text-xs font-mono text-zinc-500">
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          <span>Loading...</span>
                        </div>
                      ) : filteredModels.length === 0 ? (
                        <div className="py-6 text-center text-xs font-mono text-zinc-600">
                          No models returned.
                          <br />
                          Type ID above.
                        </div>
                      ) : (
                        filteredModels.map((m) => {
                          const isCurrent = m === selectedModel;
                          return (
                            <button
                              key={m}
                              type="button"
                              onClick={() => handleSelectModel(m)}
                              className={`w-full flex items-center justify-between px-2 py-1.5 rounded-lg text-left text-xs font-mono transition-colors cursor-pointer ${
                                isCurrent
                                  ? "bg-zinc-800 text-zinc-100 font-medium"
                                  : "text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200"
                              }`}
                            >
                              <span className="truncate">{m}</span>
                              {isCurrent && (
                                <Check className="w-3.5 h-3.5 text-zinc-200 shrink-0" />
                              )}
                            </button>
                          );
                        })
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Submit / Stop */}
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
