import { useState } from "react";
import { Copy, Check, X, Download, Play, Loader2, Terminal, FileText } from "lucide-react";
import { Deliverables, useI18n } from "../../core";

interface LootCardProps {
  deliverables: Deliverables;
  onClose: () => void;
}

export function LootCard({ deliverables, onClose }: LootCardProps) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const [isRunningScript, setIsRunningScript] = useState(false);
  const [execResult, setExecResult] = useState(deliverables.executionOutput);

  const handleCopy = () => {
    if (deliverables.script) {
      navigator.clipboard.writeText(deliverables.script);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    if (deliverables.script) {
      const blob = new Blob([deliverables.script], { type: "text/x-python" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "solve_decrypt.py";
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const handleRunScript = async () => {
    if (!deliverables.script || isRunningScript) return;
    setIsRunningScript(true);
    try {
      const res = await fetch("/api/system/exec-python", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ script: deliverables.script }),
      });
      const data = await res.json();
      setExecResult(data);
    } catch (err: any) {
      setExecResult({
        success: false,
        stderr: `Execution failed: ${err.message}`,
        executionTimeMs: 0,
      });
    } finally {
      setIsRunningScript(false);
    }
  };

  return (
    <div className="absolute inset-0 flex items-center justify-center bg-black/70 backdrop-blur-sm z-50 p-6 animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-[#121215] border border-zinc-800 rounded-2xl p-6 shadow-2xl flex flex-col space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3">
          <div>
            <h2 className="text-sm font-medium text-zinc-100">{t.loot.title}</h2>
            <p className="text-xs font-mono text-zinc-500 mt-0.5">
              {deliverables.summary || t.common.ready}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md hover:bg-zinc-800 text-zinc-500 hover:text-zinc-200 transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-2 gap-2.5">
          {deliverables.key && (
            <div className="p-3 rounded-xl bg-zinc-950/60 border border-zinc-800/80">
              <div className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider mb-1">
                {deliverables.key.startsWith("SHA256") || deliverables.key.startsWith("EP:")
                  ? "特征指纹 / 标识"
                  : t.loot.key}
              </div>
              <div className="text-xs font-mono text-zinc-200 font-bold break-all">
                {deliverables.key}
              </div>
            </div>
          )}

          {deliverables.flag && (
            <div className="p-3 rounded-xl bg-zinc-950/60 border border-zinc-800/80">
              <div className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider mb-1">
                {deliverables.flag.startsWith("Verdict:") || deliverables.flag.startsWith("Status:")
                  ? "研判结论"
                  : t.loot.flag}
              </div>
              <div className="text-xs font-mono text-emerald-400 font-bold break-all">
                {deliverables.flag}
              </div>
            </div>
          )}
        </div>

        {deliverables.savedArtifacts && (
          <div className="flex items-center gap-3 px-3 py-2 rounded-xl bg-zinc-900/60 border border-zinc-800/60 text-[11px] font-mono text-zinc-400">
            {deliverables.savedArtifacts.report_path && (
              <span className="flex items-center gap-1.5 truncate">
                <FileText className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
                <span className="text-zinc-500">Report:</span>
                <span className="text-zinc-200">{deliverables.savedArtifacts.report_path}</span>
              </span>
            )}
            {deliverables.savedArtifacts.script_path && (
              <span className="flex items-center gap-1.5 truncate">
                <Terminal className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
                <span className="text-zinc-500">Script:</span>
                <span className="text-zinc-200">{deliverables.savedArtifacts.script_path}</span>
              </span>
            )}
          </div>
        )}

        {deliverables.script && (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider">
                {t.loot.script}
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={handleRunScript}
                  disabled={isRunningScript}
                  className="flex items-center gap-1 px-2 py-1 rounded bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-400 text-[11px] font-mono transition cursor-pointer disabled:opacity-50"
                >
                  {isRunningScript ? (
                    <Loader2 className="w-3 h-3 animate-spin" />
                  ) : (
                    <Play className="w-3 h-3 fill-emerald-400" />
                  )}
                  <span>{t.loot.runScript}</span>
                </button>
                <button
                  onClick={handleDownload}
                  className="flex items-center gap-1 px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[11px] font-mono transition cursor-pointer"
                >
                  <Download className="w-3 h-3" />
                  <span>{t.loot.saveScript}</span>
                </button>
                <button
                  onClick={handleCopy}
                  className="flex items-center gap-1.5 px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[11px] font-mono transition cursor-pointer"
                >
                  {copied ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>{t.common.copied}</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>{t.common.copy}</span>
                    </>
                  )}
                </button>
              </div>
            </div>
            <pre className="p-3 rounded-xl bg-zinc-950/80 border border-zinc-800/80 text-[11px] font-mono text-zinc-300 overflow-x-auto max-h-40 leading-relaxed">
              {deliverables.script}
            </pre>

            {execResult && (
              <div className="mt-2 p-2.5 rounded-xl bg-zinc-950/90 border border-zinc-800/80 space-y-1.5">
                <div className="flex items-center justify-between text-[10px] font-mono">
                  <div className="flex items-center gap-1.5 text-zinc-400">
                    <Terminal className="w-3 h-3 text-zinc-500" />
                    <span>{t.loot.output}</span>
                    {execResult.executionTimeMs !== undefined && (
                      <span className="text-zinc-600">({execResult.executionTimeMs}ms)</span>
                    )}
                  </div>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
                      execResult.success
                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                        : "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                    }`}
                  >
                    {execResult.success ? "PASS" : "FAIL"}
                  </span>
                </div>
                <pre className="text-[11px] font-mono text-zinc-300 whitespace-pre-wrap break-all max-h-28 overflow-y-auto leading-relaxed">
                  {execResult.stdout || execResult.stderr || "No output generated"}
                </pre>
              </div>
            )}
          </div>
        )}

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-zinc-100 hover:bg-white text-zinc-950 text-xs font-medium transition cursor-pointer"
          >
            {t.common.dismiss}
          </button>
        </div>
      </div>
    </div>
  );
}
