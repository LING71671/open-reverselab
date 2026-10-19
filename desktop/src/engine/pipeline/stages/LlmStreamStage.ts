import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic } from "../../../core";
import { llmService } from "../../../services";

export class LlmStreamStage implements PipelineStage {
  readonly id = "llm-stream";
  readonly name = "LLM Stream Reasoning Engine";
  readonly description = "Streams forensic synthesis and assembly-level reasoning from LLM provider";
  readonly category = "llm" as const;
  enabled = true;

  async execute(ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<void> {
    const startTime = Date.now();
    const activeProvider = llmService.getActiveProvider();
    let baseUrl =
      activeProvider?.baseUrl ||
      (import.meta.env.VITE_LLM_BASE_URL as string) ||
      "https://tokenrhythm.studio/v1";
    const apiKey = activeProvider?.apiKey || llmService.getApiKey();
    const model = llmService.getModel() || "mimo-v2.6-flash";

    // In dev mode, route through Vite proxy to avoid CORS preflight issues
    if (
      import.meta.env.DEV &&
      (baseUrl.includes("tokenrhythm.studio") || baseUrl.startsWith("/api/llm"))
    ) {
      baseUrl = `/api/llm/v1`;
    }

    const cleanBase = baseUrl.replace(/\/+$/, "");
    const triage = ctx.triage;
    const board = ctx.kbRouting?.board || triage?.board || "pe-reverse";

    // Build context payload infused with open-reverseLab attack network methodology
    const matchedKbs = ctx.kbRouting?.matchedTechniques?.join("\n  - ") || "kb/pe-reverse/techniques/01-triage";
    const attackNetSummary = ctx.kbRouting?.content ? ctx.kbRouting.content.slice(0, 1200) : "";

    const systemPrompt =
      "你是 open-reverseLab 原生自动化逆向工程 Harness 核心 Agent。\n" +
      "你的工作目标是自主驱动逆向研判，严格遵循 open-reverseLab 攻击网（kb/pe-reverse/techniques/attack-network.md）与标准工程规约：\n" +
      "1. 绝不泛泛空谈概念；直接落地具体入口点地址、节区熵值、反调试/进程内存/注册表 API 与驱动组件分析。\n" +
      "2. 深度研判：基于识别出的静态遥测与匹配的知识库技术路径，评估样本行为特征、注入原语与自保护机制。\n" +
      "3. 自动化取证：必须输出一段精炼完整（约 60 行，用 ```python 包裹）的独立可运行 Python 取证脚本，使用 pefile/hashlib 真实提取该目标的 PE 特征、反调试 API 引用与持久化项并 print 输出。\n" +
      "4. 输出结构：【一、项目攻击网路由诊断】、【二、关键证据与行为研判】、【三、自动化取证脚本】、【四、最终结论】。\n";

    const compactTriage = {
      board,
      targetPath: ctx.resolvedBinary ? `${ctx.containerDirectory || ""}\\${ctx.resolvedBinary}` : ctx.target,
      arch: triage?.arch,
      entryPoint: triage?.entryPoint,
      subsystem: triage?.subsystem,
      linkerVersion: (triage as any)?.linkerVersion,
      packer: triage?.packer,
      sections: triage?.sections?.map((s) => ({ name: s.name, entropy: s.entropy, isExec: s.isExecutable })),
      capabilities: triage?.capabilities,
      discoveredSamples: ctx.discoveredSamples?.map((s) => s.name).slice(0, 10),
    };

    const messagesPayload = [
      { role: "system", content: systemPrompt },
      ...ctx.history,
      {
        role: "user",
        content:
          `【目标上下文】\n` +
          `- 主目标: ${compactTriage.targetPath}\n` +
          `- 容器目录: ${ctx.containerDirectory || "单个目标文件"}\n` +
          `- 发现关联二进制数: ${ctx.discoveredSamples?.length || 1}\n` +
          `- 匹配 open-reverseLab 攻击网技术路径:\n  - ${matchedKbs}\n\n` +
          `【静态初筛遥测】\n\`\`\`json\n${JSON.stringify(compactTriage, null, 2)}\n\`\`\`\n\n` +
          (attackNetSummary ? `【项目攻击网技术指引】\n${attackNetSummary}\n\n` : "") +
          `【任务需求】\n${ctx.prompt}`,
      },
    ];

    let fullContent = "";
    let firstTokenTime = 0;
    let tokenCount = 0;

    try {
      const url = `${cleanBase}/chat/completions`;
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: messagesPayload,
          stream: true,
          temperature: 0.2,
        }),
        signal: ctx.signal,
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`LLM HTTP ${res.status}: ${errText}`);
      }

      const reader = res.body?.getReader();
      if (!reader) throw new Error("Response body is not readable");

      const decoder = new TextDecoder();
      let buffer = "";

      let isStreamDone = false;
      while (!isStreamDone) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith(":")) continue;
          if (trimmed === "data: [DONE]") {
            isStreamDone = true;
            break;
          }
          if (trimmed.startsWith("data: ")) {
            try {
              const json = JSON.parse(trimmed.slice(6));
              const delta = json.choices?.[0]?.delta?.content || "";
              if (delta) {
                if (!firstTokenTime) {
                  firstTokenTime = Date.now();
                }
                tokenCount += delta.length > 3 ? Math.round(delta.length / 3) : 1;
                fullContent += delta;
                callbacks.onToken?.(fullContent);
              }
            } catch {
              // ignore malformed SSE line
            }
          }
        }
      }

      ctx.state.fullContent = fullContent;
      const totalDurationMs = Date.now() - startTime;
      const ttftMs = firstTokenTime ? firstTokenTime - startTime : totalDurationMs;
      const speedTokPerSec =
        totalDurationMs > ttftMs
          ? Math.round((tokenCount / ((totalDurationMs - ttftMs) / 1000)) * 10) / 10
          : 0;

      ctx.llmTelemetry = {
        provider: activeProvider?.name || "TokenRhythm",
        model,
        ttftMs,
        totalDurationMs,
        tokensCount: tokenCount,
        speedTokPerSec,
      };

      const diag: StageDiagnostic = {
        stageId: this.id,
        stageName: this.name,
        status: "pass",
        durationMs: totalDurationMs,
        timestamp: Date.now(),
        summary: `Model: ${model}, TTFT: ${ttftMs}ms, Generated ~${tokenCount} tokens (${speedTokPerSec} tok/s)`,
        metrics: [
          { label: "Model", value: model, status: "pass" },
          { label: "TTFT (First Token)", value: ttftMs, unit: "ms", status: ttftMs < 1500 ? "pass" : "warn" },
          { label: "Token Count", value: tokenCount, unit: "tokens", status: "pass" },
          { label: "Throughput", value: speedTokPerSec, unit: "tok/s", status: "pass" },
          { label: "Total Stream Time", value: totalDurationMs, unit: "ms", status: "pass" },
        ],
        evidence: {
          provider: activeProvider?.name,
          model,
          ttftMs,
          totalDurationMs,
        },
      };
      ctx.diagnostics[this.id] = diag;
      callbacks.onDiagnosticUpdate?.(diag);
    } catch (err: any) {
      const totalDurationMs = Date.now() - startTime;
      if (ctx.signal?.aborted || err?.name === "AbortError") {
        fullContent += "\n\n[已手动中止分析]";
      } else {
        fullContent += `\n\n[执行异常: ${err.message || String(err)}]`;
      }
      callbacks.onToken?.(fullContent);

      const diag: StageDiagnostic = {
        stageId: this.id,
        stageName: this.name,
        status: ctx.signal?.aborted ? "warn" : "fail",
        durationMs: totalDurationMs,
        timestamp: Date.now(),
        summary: ctx.signal?.aborted
          ? "Stream halted by user"
          : `Stream error: ${err.message || String(err)}`,
        metrics: [
          { label: "Model", value: model, status: "info" },
          { label: "Stream Status", value: ctx.signal?.aborted ? "Aborted" : "Failed", status: "fail" },
        ],
        error: err.message || String(err),
      };
      ctx.diagnostics[this.id] = diag;
      callbacks.onDiagnosticUpdate?.(diag);
      throw err;
    }
  }
}
