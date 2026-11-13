import { useRef, useState } from "react";
import { Copy, Check, Loader2, ArrowDown } from "lucide-react";
import { useHarness } from "../../state";
import { MarkdownViewer } from "../kb/MarkdownViewer";
import type { Deliverables } from "../../core";
import { presentAgentContent } from "./agentContent";
function AgentBody({ content }: { content: string }) {
  const { prose, details } = presentAgentContent(content);
  return <>{prose && <MarkdownViewer content={prose} />}{details.length > 0 && <details className="activity-details"><summary>计划与脚本</summary>{details.map((detail, index) => <section key={index}><h4>{detail.label}</h4><pre>{detail.content}</pre></section>)}</details>}</>;
}
function Output({ data }: { data: Deliverables }) {
  const [copied, setCopied] = useState(false);
  return <div className="goal-output">
    {data.goalVerification && <section className="verification-result"><header><h3>目标核验</h3><span data-status={data.goalVerification.status === "verified" ? "healthy" : "degraded"}>{data.goalVerification.status === "verified" ? "已通过" : "待补充证据"}</span></header><details className="activity-details"><summary>核验明细 · {data.goalVerification.passRate}</summary>{data.goalVerification.assertions.map((check, index) => <div key={index}><strong>{check.name}</strong><span data-status={check.passed ? "healthy" : "degraded"}>{check.passed ? "通过" : "未通过"}</span><p>{check.actual}</p></div>)}</details></section>}
    {data.executionOutput && <details className="activity-details"><summary>执行输出<span data-status={data.executionOutput.success ? "healthy" : "failed"}>{data.executionOutput.success ? "成功" : "失败"}</span></summary><pre>{data.executionOutput.stdout || data.executionOutput.stderr}</pre>{data.executionOutput.stdout && data.executionOutput.stderr && <pre>{data.executionOutput.stderr}</pre>}</details>}
    {data.savedArtifacts?.report_path && <div className="report-location"><span>报告</span><code>{data.savedArtifacts.report_path}</code><button className="icon-button" aria-label="复制报告路径" onClick={async () => { try { await navigator.clipboard.writeText(data.savedArtifacts!.report_path!); setCopied(true); } catch { setCopied(false); } }}>{copied ? <Check size={14} /> : <Copy size={14} />}</button></div>}
    {data.branches && Object.entries(data.branches).map(([track, branch]) => <details className="activity-details" key={track}><summary>{track} 结果</summary><Output data={branch} /></details>)}
  </div>;
}
export function AgentChatView() {
  const { messages, isRunning } = useHarness();
  const bottom = useRef<HTMLDivElement>(null);
  return <div className="activity-workspace"><div className="activity-transcript">{messages.map(message => <article className="activity-message" key={message.id}><header><span>{message.role === "user" ? message.adjustment ? "补充要求" : "Goal" : "Agent"}</span><time>{new Date(message.timestamp).toLocaleTimeString("zh-CN", { hour12: false })}</time>{message.adjustment && <span role="status">{message.adjustment.status === "pending" ? "当前步骤结束后生效" : message.adjustment.status === "applied" ? "已生效" : "未执行"}</span>}{message.isRunning && <Loader2 size={13} className="loading-spinner" />}</header>
    {message.role === "user" ? <p className="goal-objective">{message.content}</p> : <>
      {message.toolCalls?.length ? <details className="activity-details"><summary>{message.isRunning && <Loader2 size={12} className="loading-spinner" />}<span>{message.isRunning ? [...message.toolCalls].reverse().find(tool => tool.status === "running")?.title || "运行记录" : "运行记录"}</span><small>{message.toolCalls.length} 项</small></summary><div className="activity-tools">{message.toolCalls.map(tool => <details className="activity-details" key={tool.id}><summary>{tool.status === "running" && <Loader2 size={12} className="loading-spinner" />}<span>{tool.title}</span><small>{tool.durationMs === undefined ? ({ pending: "排队中", running: "运行中", done: "完成", failed: "失败", error: "失败" }[tool.status]) : `${tool.durationMs} ms`}</small></summary><p>{tool.detail}</p>{tool.output && <pre>{typeof tool.output === "string" ? tool.output : JSON.stringify(tool.output, null, 2)}</pre>}</details>)}</div></details> : null}
      {message.content && <AgentBody content={message.content} />}
      {message.deliverables && <Output data={message.deliverables} />}
    </>}</article>)}<div ref={bottom} /></div>{isRunning && <button className="secondary-button activity-latest" onClick={() => bottom.current?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" })}><ArrowDown size={14} />最新进展</button>}</div>;
}
