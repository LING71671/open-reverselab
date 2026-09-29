import { CheckCircle2, Loader2, XCircle, Clock } from "lucide-react";
import { GraphStep, useI18n } from "../../core";

interface ConsoleViewProps {
  steps: GraphStep[];
  selectedStep: GraphStep | null;
  onSelectStep: (step: GraphStep) => void;
}

export function ConsoleView({ steps, selectedStep, onSelectStep }: ConsoleViewProps) {
  const { t } = useI18n();

  if (steps.length === 0) {
    return (
      <div className="w-full h-full flex flex-col items-center justify-center text-zinc-600 font-mono text-xs select-none">
        <p>{t.console.empty}</p>
        <p className="text-[11px] text-zinc-700 mt-1">{t.console.emptyHint}</p>
      </div>
    );
  }

  return (
    <div className="w-full h-full overflow-y-auto p-6 space-y-3 font-mono">
      {steps.map((step) => {
        const isSelected = selectedStep?.id === step.id;
        return (
          <div
            key={step.id}
            onClick={() => onSelectStep(step)}
            className={`p-3.5 rounded-xl border transition cursor-pointer ${
              isSelected
                ? "bg-zinc-900 border-zinc-700 shadow-md"
                : "bg-[#121215]/80 border-zinc-900 hover:border-zinc-800"
            }`}
          >
            <div className="flex items-center justify-between text-xs mb-1.5">
              <div className="flex items-center gap-2">
                {step.status === "running" ? (
                  <Loader2 className="w-3.5 h-3.5 text-zinc-300 animate-spin" />
                ) : step.status === "done" ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <XCircle className="w-3.5 h-3.5 text-rose-400" />
                )}
                <span className="font-semibold text-zinc-200">{step.title}</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-400">
                  {step.agentId}
                </span>
              </div>

              <div className="flex items-center gap-1.5 text-[10px] text-zinc-500">
                <Clock className="w-3 h-3" />
                <span>{new Date(step.timestamp).toLocaleTimeString()}</span>
              </div>
            </div>

            <div className="text-xs text-zinc-400 leading-relaxed pl-5 whitespace-pre-wrap">
              {step.detail}
            </div>

            {step.evidence && (
              <div className="mt-2 pl-5">
                <span className="text-[10px] uppercase tracking-wider text-zinc-500 font-mono">
                  {t.console.evidence}:
                </span>
                <pre className="mt-1 p-2 rounded bg-zinc-950/80 border border-zinc-900 text-[10px] text-zinc-400 overflow-x-auto">
                  {JSON.stringify(step.evidence, null, 2)}
                </pre>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
