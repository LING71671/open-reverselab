import { Children, isValidElement, useState, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkFrontmatter from "remark-frontmatter";
import { Check, Copy } from "lucide-react";

interface MarkdownViewerProps { content: string; docPath?: string; onNavigate?: (path: string) => void }
function textContent(value: ReactNode): string {
  return Children.toArray(value).map(child => isValidElement<{ children?: ReactNode }>(child) ? textContent(child.props.children) : String(child)).join("");
}
function CodeBlock({ children }: { children?: ReactNode }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);
  return <div className="document-code"><button className="text-button" type="button" onClick={async () => {
    try { await navigator.clipboard.writeText(textContent(children).replace(/\n$/, "")); setCopied(true); setFailed(false); setTimeout(() => setCopied(false), 2000); }
    catch { setFailed(true); }
  }}>{copied ? <Check size={13} /> : <Copy size={13} />}{copied ? "已复制" : failed ? "复制失败" : "复制代码"}</button><pre>{children}</pre></div>;
}
export function MarkdownViewer({ content, docPath, onNavigate }: MarkdownViewerProps) {
  return <div className="markdown-body"><ReactMarkdown remarkPlugins={[remarkGfm, remarkFrontmatter]} components={{
    pre: ({ children }) => <CodeBlock>{children}</CodeBlock>,
    table: ({ children }) => <div className="document-table"><table>{children}</table></div>,
    a: ({ href, children }) => {
      const localDoc = href && !/^[a-z]+:/i.test(href) && !href.startsWith("//") && /\.md(?:#.*)?$/.test(href);
      if (localDoc && docPath && onNavigate) {
        const path = new URL(href!, `https://kb.invalid/${docPath}`).pathname.slice(1);
        return <a href={href} onClick={event => { event.preventDefault(); onNavigate(decodeURIComponent(path)); }}>{children}</a>;
      }
      return <a href={href} target={href?.startsWith("#") ? undefined : "_blank"} rel="noreferrer">{children}</a>;
    },
  }}>{content}</ReactMarkdown></div>;
}
