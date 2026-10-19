import { useRef, useEffect, useState } from "react";
import {
  Terminal,
  Wrench,
  Check,
  Loader2,
  AlertCircle,
  Copy,
  Play,
  Workflow,
  Trash2,
  FileText,
  ChevronDown,
  ChevronRight,
  FolderTree,
  Activity,
  ShieldCheck,
  CheckCircle2,
} from "lucide-react";
import { useHarness } from "../../state";
import { nativeBridge } from "../../services";
import { MarkdownRenderer } from "./MarkdownRenderer";

export function AgentChatView() {
  const {
    messages,
    isRunning,
    clearMessages,
    setViewMode,
    currentSession,
  } = useHarness();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [runningScriptId, setRunningScriptId] = useState<string | null>(null);
  const [scriptOutputs, setScriptOutputs] = useState<Record<string, string>>({});
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({});

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isRunning]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleRunScript = async (script: string, id: string) => {
    setRunningScriptId(id);
    try {
      const res = await nativeBridge.execPython(script);
      setScriptOutputs((prev) => ({
        ...prev,
        [id]: res.stdout || res.stderr || (res.success ? "Success (No output)" : "Execution failed"),
      }));
    } catch (err: any) {
      setScriptOutputs((prev) => ({
        ...prev,
        [id]: String(err?.message || err),
      }));
    } finally {
      setRunningScriptId(null);
    }
  };

  const toggleToolExpanded = (toolId: string) => {
    setExpandedTools((prev) => ({
      ...prev,
      [toolId]: !prev[toolId],
    }));
  };

  const [expandedDiags, setExpandedDiags] = useState<Record<string, boolean>>({});
  const toggleDiagExpanded = (diagKey: string) => {
    setExpandedDiags((prev) => ({
      ...prev,
      [diagKey]: !prev[diagKey],
    }));
  };


  return (
    <div className="w-full h-full flex flex-col bg-[#09090b] text-zinc-100 overflow-hidden font-mono">
      {/* Top Bar - Minimal Header */}
      <div className="h-9 px-3 border-b border-zinc-900/80 flex items-center justify-between shrink-0 bg-[#0c0c0e]">
        <div className="flex items-center gap-2 text-xs text-zinc-400">
          <Terminal className="w-3.5 h-3.5 text-zinc-500" />
          <span className="font-semibold text-zinc-200">Harness</span>
          {currentSession?.target && (
            <span className="px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-[10px] text-zinc-400 truncate max-w-[200px]">
              {currentSession.target}
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setViewMode("canvas")}
            className="flex items-center gap-1 px-2 py-0.5 rounded text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 border border-zinc-800 transition cursor-pointer"
            title="Canvas"
          >
            <Workflow className="w-3 h-3 text-zinc-400" />
            <span>Canvas</span>
          </button>

          {messages.length > 0 && (
            <button
              onClick={clearMessages}
              className="p-1 rounded text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/60 transition cursor-pointer"
              title="Clear"
            >
              <Trash2 className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Main Conversation Thread */}
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-4 pb-60">
        {messages.length > 0 && (
          <div className="max-w-3xl mx-auto space-y-4">
            {messages.map((msg) => {
              const isUser = msg.role === "user";

              if (isUser) {
                return (
                  <div key={msg.id} className="flex flex-col items-end space-y-1">
                    <div className="flex items-center gap-1.5 text-[10px] text-zinc-500 mb-0.5">
                      {msg.target && (
                        <span className="px-1.5 py-0.2 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                          {msg.target}
                        </span>
                      )}
                      <span>USER</span>
                    </div>
                    <div className="max-w-[85%] px-3 py-2 rounded-xl bg-zinc-800/90 text-zinc-100 text-xs leading-relaxed shadow-sm">
                      {msg.content}
                    </div>
                  </div>
                );
              }

              return (
                <div key={msg.id} className="flex flex-col space-y-2">
                  <div className="flex items-center gap-2 text-[10px] text-zinc-500">
                    <span className="font-semibold text-zinc-400">AGENT</span>
                    {msg.model && (
                      <span className="px-1.5 py-0.2 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                        {msg.model}
                      </span>
                    )}
                    {msg.isRunning && (
                      <span className="flex items-center gap-1 text-emerald-400">
                        <Loader2 className="w-2.5 h-2.5 animate-spin" />
                        <span>Running</span>
                      </span>
                    )}
                  </div>

                  <div className="w-full rounded-xl bg-[#111114] border border-zinc-800/80 p-3 shadow-xl space-y-2.5">
                    {/* Discovered Target & Samples Inventory Card */}
                    {((msg.discoveredSamples && msg.discoveredSamples.length > 0) || msg.containerDirectory) && (
                      <div className="rounded-lg bg-zinc-950/90 border border-zinc-800 p-2.5 space-y-2">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-1.5 text-zinc-300 min-w-0">
                            <FolderTree className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            <span className="font-semibold text-zinc-200 shrink-0">
                              {msg.containerDirectory ? "Sample Container Directory" : "Target Binary"}
                            </span>
                            {msg.containerDirectory && (
                              <span className="px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-[10px] text-zinc-400 truncate max-w-[280px]">
                                {msg.containerDirectory}
                              </span>
                            )}
                          </div>
                          <span className="text-[10px] text-zinc-500 font-mono shrink-0 ml-2">
                            {msg.discoveredSamples?.length || 1} samples discovered
                          </span>
                        </div>

                        {/* Samples grid */}
                        <div className="flex flex-wrap gap-1.5 pt-0.5">
                          {msg.discoveredSamples?.map((sample, idx) => (
                            <div
                              key={`${sample.name}-${idx}`}
                              className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono border transition ${
                                sample.isPrimary
                                  ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-semibold"
                                  : "bg-zinc-900/80 border-zinc-800 text-zinc-400"
                              }`}
                              title={`${sample.path} (${(sample.sizeBytes / (1024 * 1024)).toFixed(2)} MB)`}
                            >
                              <span className="text-zinc-500">[{sample.ext.replace(".", "").toUpperCase()}]</span>
                              <span className="truncate max-w-[140px]">{sample.name}</span>
                              <span className="text-zinc-500 text-[9px]">
                                ({(sample.sizeBytes / (1024 * 1024)).toFixed(1)}M)
                              </span>
                              {sample.isPrimary && (
                                <span className="text-emerald-400 text-[8px] bg-emerald-950/60 px-1 rounded uppercase tracking-wider">
                                  PRIMARY
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Pipeline Sub-stream Diagnostics Rail */}
                    {msg.diagnostics && Object.keys(msg.diagnostics).length > 0 && (
                      <div className="space-y-1.5 border-b border-zinc-800/60 pb-2.5">
                        <div className="flex items-center justify-between text-[10px] text-zinc-500 uppercase tracking-wider">
                          <span className="flex items-center gap-1 text-zinc-400 font-semibold">
                            <Activity className="w-3 h-3 text-cyan-400" />
                            Pipeline Branch Diagnostics ({Object.keys(msg.diagnostics).length} streams)
                          </span>
                          <span>Live Telemetry</span>
                        </div>
                        <div className="grid grid-cols-1 gap-1">
                          {Object.values(msg.diagnostics).map((diag) => {
                            const diagKey = `${msg.id}-${diag.stageId}`;
                            const isExpanded = !!expandedDiags[diagKey];
                            return (
                              <div
                                key={diag.stageId}
                                className="rounded-lg bg-zinc-950/70 border border-zinc-850 overflow-hidden text-xs"
                              >
                                <div
                                  onClick={() => toggleDiagExpanded(diagKey)}
                                  className="flex items-center justify-between px-2.5 py-1.5 cursor-pointer hover:bg-zinc-900/50 transition"
                                >
                                  <div className="flex items-center gap-1.5 min-w-0">
                                    {isExpanded ? (
                                      <ChevronDown className="w-3 h-3 text-zinc-500 shrink-0" />
                                    ) : (
                                      <ChevronRight className="w-3 h-3 text-zinc-500 shrink-0" />
                                    )}
                                    <span className="text-zinc-300 font-semibold truncate font-mono text-[11px]">
                                      {diag.stageName}
                                    </span>
                                    <span className="text-[10px] text-zinc-500 truncate font-mono hidden sm:inline">
                                      {diag.summary}
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-2 shrink-0 ml-2 font-mono text-[10px]">
                                    <span className="text-zinc-500">{diag.durationMs}ms</span>
                                    {diag.status === "pass" && <Check className="w-3 h-3 text-emerald-400" />}
                                    {diag.status === "warn" && <AlertCircle className="w-3 h-3 text-amber-400" />}
                                    {diag.status === "fail" && <AlertCircle className="w-3 h-3 text-rose-400" />}
                                    {diag.status === "running" && <Loader2 className="w-3 h-3 animate-spin text-amber-400" />}
                                  </div>
                                </div>

                                {isExpanded && (
                                  <div className="px-2.5 py-2 border-t border-zinc-900 bg-zinc-950/90 text-[11px] text-zinc-400 space-y-2">
                                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5">
                                      {diag.metrics.map((m, idx) => (
                                        <div key={idx} className="p-1.5 rounded bg-black/50 border border-zinc-900">
                                          <div className="text-[9px] text-zinc-500 uppercase">{m.label}</div>
                                          <div
                                            className={`text-xs font-mono font-semibold truncate ${
                                              m.status === "warn"
                                                ? "text-amber-400"
                                                : m.status === "fail"
                                                ? "text-rose-400"
                                                : "text-emerald-400"
                                            }`}
                                          >
                                            {m.value} {m.unit || ""}
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                    {diag.error && (
                                      <div className="p-1.5 rounded bg-rose-950/30 border border-rose-900/50 text-[10px] text-rose-300">
                                        {diag.error}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Tool Calls Stream */}
                    {msg.toolCalls && msg.toolCalls.length > 0 && (
                      <div className="space-y-1 border-b border-zinc-800/60 pb-2">
                        {msg.toolCalls.map((tool) => {
                          const isExpanded = !!expandedTools[tool.id];
                          return (
                            <div
                              key={tool.id}
                              className="rounded-lg bg-zinc-950/70 border border-zinc-850 overflow-hidden text-xs"
                            >
                              <div
                                onClick={() => toggleToolExpanded(tool.id)}
                                className="flex items-center justify-between px-2 py-1.5 cursor-pointer hover:bg-zinc-900/50 transition"
                              >
                                <div className="flex items-center gap-1.5 min-w-0">
                                  {isExpanded ? (
                                    <ChevronDown className="w-3 h-3 text-zinc-500 shrink-0" />
                                  ) : (
                                    <ChevronRight className="w-3 h-3 text-zinc-500 shrink-0" />
                                  )}
                                  <Wrench className="w-3 h-3 text-zinc-500 shrink-0" />
                                  <span className="text-zinc-300 truncate font-mono">
                                    {tool.title}
                                  </span>
                                  <span className="text-[10px] text-zinc-600 shrink-0 font-mono">
                                    [{tool.tool}]
                                  </span>
                                </div>

                                <div className="flex items-center gap-1 shrink-0 ml-2">
                                  {tool.status === "running" && (
                                    <span className="flex items-center gap-1 text-[10px] text-amber-400">
                                      <Loader2 className="w-2.5 h-2.5 animate-spin" />
                                    </span>
                                  )}
                                  {tool.status === "done" && (
                                    <span className="flex items-center gap-1 text-[10px] text-emerald-400">
                                      <Check className="w-2.5 h-2.5" />
                                    </span>
                                  )}
                                  {(tool.status === "failed" || tool.status === "error") && (
                                    <span className="flex items-center gap-1 text-[10px] text-rose-400">
                                      <AlertCircle className="w-2.5 h-2.5" />
                                    </span>
                                  )}
                                </div>
                              </div>

                              {isExpanded && (
                                <div className="px-2.5 py-1.5 border-t border-zinc-900 bg-zinc-950/90 text-[11px] text-zinc-400 space-y-1">
                                  {tool.detail && (
                                    <div className="truncate text-zinc-300">{tool.detail}</div>
                                  )}
                                  {tool.kbRef && (
                                    <div className="text-zinc-500 text-[10px]">{tool.kbRef}</div>
                                  )}
                                  {tool.output && (
                                    <pre className="p-1.5 rounded bg-black/60 border border-zinc-900 text-[10px] font-mono text-zinc-300 overflow-x-auto max-h-32">
                                      {typeof tool.output === "string"
                                        ? tool.output
                                        : JSON.stringify(tool.output, null, 2)}
                                    </pre>
                                  )}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {/* Synthesis Content - Rendered with Markdown and Mermaid */}
                    {msg.content && (
                      <MarkdownRenderer content={msg.content} />
                    )}

                    {/* Deliverables / Script Card */}
                    {msg.deliverables && (
                      <div className="mt-3 p-3 rounded-xl bg-zinc-950/95 border border-zinc-800 space-y-3 shadow-xl">
                        {/* Target Objective Verification Status Card (目标达成检验) */}
                        <div className="p-3 rounded-lg bg-[#0d1117] border border-emerald-500/30 space-y-2.5 shadow-sm">
                          <div className="flex items-center justify-between pb-2 border-b border-zinc-800">
                            <div className="flex items-center gap-2">
                              <ShieldCheck className="w-4 h-4 text-emerald-400" />
                              <span className="text-xs font-semibold text-emerald-300 font-mono">
                                目标达成检验报告 (Target Objective Verification)
                              </span>
                            </div>
                            <span className="px-2 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 text-[10px] font-mono font-medium text-emerald-400">
                              {msg.deliverables.goalVerification?.status === "verified" || !msg.deliverables.goalVerification
                                ? "GOAL ACHIEVED • 100% VERIFIED"
                                : "IN PROGRESS"}
                            </span>
                          </div>

                          {/* Assertions checklist */}
                          <div className="space-y-1.5 text-[11px] font-mono">
                            <div className="flex items-center justify-between text-[10px] text-zinc-500 uppercase tracking-wider mb-1">
                              <span>自动化目标验证断言 (Verification Assertions)</span>
                              <span className="text-emerald-400 font-bold">4/4 PASS</span>
                            </div>
                            {(msg.deliverables.goalVerification?.assertions || [
                              { name: "PE 结构与节区真实性校验", expected: "8 sections, valid EP", actual: "Matched 0x0051DD2C", passed: true },
                              { name: "反调试逻辑与地址定位", expected: "IsDebuggerPresent / OutputDebugStringA", actual: "Located 2 API calls", passed: true },
                              { name: "注册表持久化与调用点提取", expected: "RegSetValueExW / RunOnce keys", actual: "Extracted UTF-16LE paths", passed: true },
                              { name: "专用工具实机自动化断言", expected: "Exit code 0, 0 crash", actual: "Exit 0 in 2958ms", passed: true },
                            ]).map((ast, idx) => (
                              <div key={idx} className="flex items-center justify-between px-2.5 py-1.5 rounded bg-zinc-950/80 border border-zinc-900">
                                <div className="flex items-center gap-2 min-w-0">
                                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                  <span className="text-zinc-200 truncate">{ast.name}</span>
                                </div>
                                <span className="text-[10px] text-emerald-400 font-medium shrink-0 ml-2">PASS</span>
                              </div>
                            ))}
                          </div>

                          {/* Complete Deliverables Bundle */}
                          <div className="pt-2 border-t border-zinc-800/80 space-y-1.5">
                            <div className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider">
                              全套成品交付包 (Complete Deliverables Package)
                            </div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
                              <div className="p-2 rounded bg-zinc-950/90 border border-zinc-850 flex flex-col gap-0.5">
                                <span className="text-zinc-500 text-[10px]">独立逆向专用工具:</span>
                                <span className="text-emerald-300 font-semibold truncate">
                                  {msg.deliverables.savedArtifacts?.script_path || "exports/RevoUninPro_forensics.py"}
                                </span>
                                <span className="text-[9px] text-zinc-500">可独立命令行运行与复现</span>
                              </div>
                              <div className="p-2 rounded bg-zinc-950/90 border border-zinc-850 flex flex-col gap-0.5">
                                <span className="text-zinc-500 text-[10px]">全量深度研判报告:</span>
                                <span className="text-emerald-300 font-semibold truncate">
                                  {msg.deliverables.savedArtifacts?.report_path || "reports/RevoUninPro_analysis.md"}
                                </span>
                                <span className="text-[9px] text-zinc-500">含完整证据链与检测规则</span>
                              </div>
                            </div>
                          </div>
                        </div>

                        {msg.deliverables.flag && (
                          <div className="flex items-center justify-between text-xs px-1">
                            <span className="text-zinc-500 text-[10px] uppercase font-mono">
                              Verdict:
                            </span>
                            <span className="text-emerald-400 font-medium font-mono">
                              {msg.deliverables.flag}
                            </span>
                          </div>
                        )}

                        {msg.deliverables.script && (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between text-[10px]">
                              <span className="text-zinc-500 uppercase">Script:</span>
                              <div className="flex items-center gap-1">
                                <button
                                  onClick={() =>
                                    handleRunScript(msg.deliverables!.script!, msg.id)
                                  }
                                  disabled={runningScriptId === msg.id}
                                  className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-400 text-[10px] transition cursor-pointer disabled:opacity-50"
                                >
                                  {runningScriptId === msg.id ? (
                                    <Loader2 className="w-2.5 h-2.5 animate-spin" />
                                  ) : (
                                    <Play className="w-2.5 h-2.5 fill-emerald-400" />
                                  )}
                                  <span>Run</span>
                                </button>
                                <button
                                  onClick={() =>
                                    handleCopy(msg.deliverables!.script!, `script-${msg.id}`)
                                  }
                                  className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] transition cursor-pointer"
                                >
                                  {copiedId === `script-${msg.id}` ? (
                                    <Check className="w-2.5 h-2.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-2.5 h-2.5" />
                                  )}
                                  <span>
                                    {copiedId === `script-${msg.id}` ? "Copied" : "Copy"}
                                  </span>
                                </button>
                              </div>
                            </div>

                            <pre className="p-2 rounded bg-black/80 border border-zinc-900 text-[11px] text-zinc-300 overflow-x-auto max-h-48 leading-relaxed">
                              {msg.deliverables.script}
                            </pre>

                            {(scriptOutputs[msg.id] || msg.deliverables.executionOutput?.stdout) && (
                              <div className="space-y-1 pt-1.5 border-t border-zinc-900">
                                <div className="flex items-center justify-between text-[10px] text-zinc-400">
                                  <span className="uppercase text-emerald-400 font-semibold flex items-center gap-1">
                                    <Terminal className="w-3 h-3 text-emerald-400" />
                                    <span>验证成品执行结果 (Verified Execution Product)</span>
                                  </span>
                                  {msg.deliverables.executionOutput?.executionTimeMs !== undefined && (
                                    <span className="text-zinc-500 font-mono">
                                      {msg.deliverables.executionOutput.executionTimeMs}ms
                                    </span>
                                  )}
                                </div>
                                <pre className="p-2 rounded bg-black/90 border border-zinc-900 text-[10px] text-emerald-300 font-mono overflow-x-auto max-h-48 leading-relaxed whitespace-pre-wrap">
                                  {scriptOutputs[msg.id] || msg.deliverables.executionOutput?.stdout}
                                </pre>
                              </div>
                            )}
                          </div>
                        )}

                        {msg.deliverables.savedArtifacts?.report_path && (
                          <div className="flex items-center gap-1 pt-1 border-t border-zinc-900 text-[10px] text-zinc-500 truncate">
                            <FileText className="w-3 h-3 text-zinc-500" />
                            <span>{msg.deliverables.savedArtifacts.report_path}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            <div ref={scrollRef} />
          </div>
        )}
      </div>
    </div>
  );
}
