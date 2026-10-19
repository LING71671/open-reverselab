import React, { useState, useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import mermaid from "mermaid";
import { Check, Copy } from "lucide-react";

mermaid.initialize({
  startOnLoad: false,
  theme: "dark",
  securityLevel: "loose",
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  themeVariables: {
    darkMode: true,
    background: "#0c0c0e",
    mainBkg: "#141418",
    nodeBorder: "#27272a",
    primaryColor: "#065f46",
    primaryTextColor: "#ecfdf5",
    primaryBorderColor: "#059669",
    lineColor: "#10b981",
    secondaryColor: "#18181b",
    tertiaryColor: "#18181b",
    textColor: "#e4e4e7",
  },
});

function MermaidBlock({ chart }: { chart: string }) {
  const [svg, setSvg] = useState<string>("");
  const [error, setError] = useState<string>("");
  const containerRef = useRef<HTMLDivElement>(null);
  const idRef = useRef(`mermaid-${Math.random().toString(36).slice(2, 9)}`);

  useEffect(() => {
    let cancelled = false;
    async function renderChart() {
      try {
        // Clean chart input
        const cleanChart = chart.trim();
        const { svg: renderedSvg } = await mermaid.render(idRef.current, cleanChart);
        if (!cancelled) {
          setSvg(renderedSvg);
          setError("");
        }
      } catch (err: any) {
        if (!cancelled) {
          setError(err.message || String(err));
        }
      }
    }
    renderChart();
    return () => {
      cancelled = true;
    };
  }, [chart]);

  if (error) {
    return (
      <div className="my-2 p-2.5 rounded-lg bg-zinc-950 border border-zinc-800 text-[11px] font-mono text-zinc-400">
        <div className="text-zinc-500 mb-1 text-[10px] uppercase font-semibold">Mermaid Source</div>
        <pre className="overflow-x-auto text-[10px] text-zinc-400 whitespace-pre-wrap">{chart}</pre>
      </div>
    );
  }

  if (!svg) {
    return (
      <div className="my-2 p-4 rounded-xl bg-zinc-950/60 border border-zinc-850 flex items-center justify-center text-xs text-zinc-500 font-mono animate-pulse">
        Rendering Attack Network...
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="my-3 p-3 rounded-xl bg-[#09090b]/90 border border-zinc-800/80 overflow-x-auto shadow-xl flex flex-col items-center group relative"
    >
      <div className="w-full flex items-center justify-between pb-1.5 mb-2 border-b border-zinc-800/40 text-[10px] font-mono text-zinc-500">
        <span className="uppercase tracking-wider text-emerald-400/90 font-medium">Attack Network Flow</span>
        <button
          onClick={() => navigator.clipboard.writeText(chart)}
          className="hover:text-zinc-300 transition cursor-pointer"
          title="Copy Mermaid source"
        >
          <Copy className="w-3 h-3" />
        </button>
      </div>
      <div
        className="w-full flex justify-center [&_svg]:max-w-full [&_svg]:h-auto"
        dangerouslySetInnerHTML={{ __html: svg }}
      />
    </div>
  );
}

interface MarkdownRendererProps {
  content: string;
}

export const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({ content }) => {
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  const handleCopy = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  return (
    <div className="text-xs text-zinc-200 leading-relaxed font-sans space-y-2 prose prose-invert max-w-none">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => (
            <h1 className="text-sm font-semibold text-zinc-100 font-mono mt-3 mb-1.5 pb-1 border-b border-zinc-800 flex items-center gap-1.5">
              <span className="w-1.5 h-3.5 bg-emerald-500 rounded-sm" />
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-xs font-semibold text-zinc-200 font-mono mt-2.5 mb-1 flex items-center gap-1.5">
              <span className="w-1 h-2.5 bg-emerald-500/80 rounded-sm" />
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="text-xs font-medium text-zinc-300 font-mono mt-2 mb-0.5">{children}</h3>
          ),
          p: ({ children }) => <p className="my-1 text-zinc-300 font-mono leading-relaxed">{children}</p>,
          ul: ({ children }) => (
            <ul className="list-disc list-inside space-y-0.5 my-1 text-zinc-300 font-mono pl-1">{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className="list-decimal list-inside space-y-0.5 my-1 text-zinc-300 font-mono pl-1">{children}</ol>
          ),
          li: ({ children }) => <li className="text-zinc-300 text-[11px] leading-relaxed">{children}</li>,
          strong: ({ children }) => <strong className="font-semibold text-zinc-100">{children}</strong>,
          table: ({ children }) => (
            <div className="my-2 overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950/60">
              <table className="w-full text-left text-[11px] font-mono border-collapse divide-y divide-zinc-800">
                {children}
              </table>
            </div>
          ),
          thead: ({ children }) => <thead className="bg-zinc-900/60 text-zinc-400">{children}</thead>,
          th: ({ children }) => (
            <th className="px-2.5 py-1.5 font-medium text-[10px] uppercase tracking-wider">{children}</th>
          ),
          td: ({ children }) => <td className="px-2.5 py-1.5 text-zinc-300 border-t border-zinc-800/40">{children}</td>,
          code: ({ node, className, children, ...props }: any) => {
            const match = /language-(\w+)/.exec(className || "");
            const lang = match ? match[1] : "";
            const isInline = !match && !String(children).includes("\n");
            const codeString = String(children).replace(/\n$/, "");

            if (lang === "mermaid") {
              return <MermaidBlock chart={codeString} />;
            }

            if (isInline) {
              return (
                <code
                  className="px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-emerald-300 font-mono text-[10px]"
                  {...props}
                >
                  {children}
                </code>
              );
            }

            const codeId = `code-${Math.random().toString(36).slice(2, 7)}`;
            return (
              <div className="my-2 rounded-lg bg-[#0c0c0e] border border-zinc-800 overflow-hidden font-mono text-xs">
                <div className="flex items-center justify-between px-2.5 py-1 bg-zinc-900/60 border-b border-zinc-800/60 text-[10px] text-zinc-500">
                  <span className="uppercase font-semibold text-zinc-400">{lang || "code"}</span>
                  <button
                    onClick={() => handleCopy(codeString, codeId)}
                    className="flex items-center gap-1 hover:text-zinc-200 transition cursor-pointer"
                  >
                    {copiedCode === codeId ? (
                      <>
                        <Check className="w-2.5 h-2.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-2.5 h-2.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-2.5 overflow-x-auto text-[11px] text-zinc-200 leading-relaxed font-mono">
                  <code>{children}</code>
                </pre>
              </div>
            );
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
};
