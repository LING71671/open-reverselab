import React, { useState, useMemo } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkFrontmatter from "remark-frontmatter";
import { Check, Copy, Tag, Compass } from "lucide-react";

interface MarkdownViewerProps {
  content: string;
}

function parseFrontmatter(raw: string) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(raw.trim());
  if (!match) {
    return { meta: null, body: raw };
  }

  const yaml = match[1];
  const body = match[2];

  let summary = "";
  let difficulty = "";
  const tags: string[] = [];

  const summaryMatch = /summary:\s*>?\s*\n?([^\n]+(?:\n\s+[^\n]+)*)/.exec(yaml);
  if (summaryMatch) {
    summary = summaryMatch[1].replace(/\n\s+/g, " ").trim();
  }

  const diffMatch = /difficulty:\s*["']?([^"'\n]+)/.exec(yaml);
  if (diffMatch) {
    difficulty = diffMatch[1].trim();
  }

  const tagsMatch = /tags:\s*\n((?:\s*-\s*[^\n]+\n?)+)/.exec(yaml);
  if (tagsMatch) {
    for (const line of tagsMatch[1].split("\n")) {
      const clean = line.replace(/^\s*-\s*["']?/, "").replace(/["']?\s*$/, "").trim();
      if (clean) tags.push(clean);
    }
  }

  return {
    meta: { summary, difficulty, tags },
    body,
  };
}

function CodeBlock({ children, className }: { children?: React.ReactNode; className?: string }) {
  const [copied, setCopied] = useState(false);
  const match = /language-(\w+)/.exec(className || "");
  const lang = match ? match[1] : "";
  const codeText = String(children).replace(/\n$/, "");

  const handleCopy = () => {
    navigator.clipboard.writeText(codeText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative my-3 rounded-xl border border-zinc-800 bg-[#0c0c0e] overflow-hidden group">
      <div className="flex items-center justify-between px-3.5 py-1.5 bg-zinc-900/80 border-b border-zinc-800/80 text-[11px] font-mono text-zinc-400">
        <span className="uppercase text-zinc-400 font-semibold tracking-wider">
          {lang || "code"}
        </span>
        <button
          type="button"
          onClick={handleCopy}
          className="flex items-center gap-1 px-2 py-0.5 rounded hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition cursor-pointer"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-emerald-400" />
              <span className="text-emerald-400">已复制</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3" />
              <span>复制代码</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-3.5 overflow-x-auto text-xs font-mono text-zinc-200 leading-relaxed">
        <code>{codeText}</code>
      </pre>
    </div>
  );
}

export function MarkdownViewer({ content }: MarkdownViewerProps) {
  const { meta, body } = useMemo(() => parseFrontmatter(content), [content]);

  return (
    <div className="markdown-body select-text font-sans text-xs text-zinc-300 leading-relaxed space-y-3 p-6">
      {/* Clean Structured Metadata Header parsed from Front-Matter */}
      {meta && (meta.summary || meta.tags.length > 0) && (
        <div className="mb-6 p-4 rounded-xl bg-zinc-900/50 border border-zinc-800/80 space-y-2.5">
          {meta.summary && (
            <div className="flex items-start gap-2 text-zinc-300 text-xs leading-relaxed font-sans">
              <Compass className="w-4 h-4 text-zinc-400 shrink-0 mt-0.5" />
              <span>{meta.summary}</span>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            {meta.difficulty && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-750 uppercase">
                {meta.difficulty}
              </span>
            )}
            {meta.tags.slice(0, 5).map((t, idx) => (
              <span
                key={idx}
                className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-950 text-zinc-400 border border-zinc-800 flex items-center gap-1"
              >
                <Tag className="w-2.5 h-2.5 text-zinc-500" />
                <span>{t}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      <ReactMarkdown
        remarkPlugins={[remarkGfm, remarkFrontmatter]}
        components={{
          h1: ({ children }) => (
            <h1 className="text-base font-bold text-zinc-100 pb-2 border-b border-zinc-800 mt-6 mb-3 first:mt-0 font-sans tracking-tight">
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-sm font-semibold text-zinc-100 mt-5 mb-2 pb-1 border-b border-zinc-800/60 font-sans flex items-center gap-1.5">
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="text-xs font-semibold text-zinc-200 mt-4 mb-1.5 font-sans">
              {children}
            </h3>
          ),
          p: ({ children }) => (
            <p className="text-xs text-zinc-300 leading-relaxed mb-2.5 font-sans">
              {children}
            </p>
          ),
          ul: ({ children }) => (
            <ul className="list-disc list-outside pl-4 space-y-1 mb-2.5 text-xs text-zinc-300 font-sans">
              {children}
            </ul>
          ),
          ol: ({ children }) => (
            <ol className="list-decimal list-outside pl-4 space-y-1 mb-2.5 text-xs text-zinc-300 font-sans">
              {children}
            </ol>
          ),
          li: ({ children }) => (
            <li className="text-xs text-zinc-300 leading-relaxed font-sans">{children}</li>
          ),
          blockquote: ({ children }) => (
            <blockquote className="border-l-2 border-zinc-600 pl-3.5 py-1.5 my-3 text-xs text-zinc-400 bg-zinc-900/40 rounded-r-lg font-sans">
              {children}
            </blockquote>
          ),
          table: ({ children }) => (
            <div className="my-3 overflow-x-auto rounded-xl border border-zinc-800">
              <table className="w-full text-left text-xs border-collapse">
                {children}
              </table>
            </div>
          ),
          thead: ({ children }) => (
            <thead className="bg-zinc-900/90 text-zinc-200 font-mono text-[11px] border-b border-zinc-800">
              {children}
            </thead>
          ),
          tbody: ({ children }) => (
            <tbody className="divide-y divide-zinc-800/60 bg-zinc-950/40 text-zinc-300 font-sans">
              {children}
            </tbody>
          ),
          th: ({ children }) => (
            <th className="px-3.5 py-2 font-medium text-zinc-200">{children}</th>
          ),
          td: ({ children }) => (
            <td className="px-3.5 py-2 text-xs text-zinc-300 border-t border-zinc-800/40 font-mono">
              {children}
            </td>
          ),
          code: ({ className, children, ...props }) => {
            const isBlock = Boolean(className);
            if (isBlock) {
              return <CodeBlock className={className}>{children}</CodeBlock>;
            }
            return (
              <code
                className="px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 font-mono text-[11px] text-zinc-200"
                {...props}
              >
                {children}
              </code>
            );
          },
          pre: ({ children }) => <>{children}</>,
          hr: () => <hr className="my-4 border-zinc-800" />,
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noreferrer"
              className="text-zinc-200 underline decoration-zinc-600 hover:text-white transition"
            >
              {children}
            </a>
          ),
        }}
      >
        {body}
      </ReactMarkdown>
    </div>
  );
}
