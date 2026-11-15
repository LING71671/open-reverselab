import { PipelineStage, PipelineContext, PipelineCallbacks, StageDiagnostic } from "../../../core";
import { llmService } from "../../../services/llm/llmService";
import { modelFetch, modelResponseError, usesNativeNetwork } from "../../../services/network/networkService";
import { buildAnalysisMessages, estimateMessageTokens, refreshMcpTools } from "../analysisPrompt";
import { parseAcceptancePlan } from "../goalVerifier";
import { HealthFault } from "../../../core/contracts/health";
import { canRetryModelRequest, recoverModelRequest } from "../modelRecovery";

export class LlmStreamStage implements PipelineStage {
  readonly id = "llm-stream";
  readonly name = "分析与计划";
  readonly description = "Streams forensic synthesis and assembly-level reasoning from LLM provider";
  readonly category = "llm" as const;
  enabled = true;

  async execute(ctx: PipelineContext, callbacks: PipelineCallbacks): Promise<void> {
    if (ctx.state.builtinHash) {
      callbacks.onTitle?.("SHA256 核验");
      const script = `import hashlib, json\nfrom pathlib import Path\ntarget = ${JSON.stringify(ctx.target)}\npath = Path(target)\nif not path.is_file():\n    raise ValueError("Target must be a file")\nwith path.open("rb") as source:\n    digest = hashlib.file_digest(source, "sha256").hexdigest()\nprint(json.dumps({"target": target, "sha256": digest, "observations": [{"name": "file_size", "value": path.stat().st_size, "source": target}]}))`;
      ctx.state.fullContent = `SHA256 核验\n\n\`\`\`python\n${script}\n\`\`\``;
      callbacks.onToken?.(ctx.state.fullContent);
      const diag: StageDiagnostic = { stageId: this.id, stageName: this.name, status: "skipped", durationMs: 0, timestamp: Date.now(), summary: "使用内置 SHA256 核验脚本，未调用模型", metrics: [] };
      ctx.diagnostics[this.id] = diag;
      callbacks.onDiagnosticUpdate?.(diag);
      return;
    }
    await recoverModelRequest(ctx, callbacks, signal => this.generate(ctx, callbacks, signal), {
      id: `${ctx.sessionId}:${ctx.budget.attempts}:${this.id}`, title: this.name, agentId: this.id, parentId: ctx.state.lastStepId || null,
    });
  }

  private async generate(ctx: PipelineContext, callbacks: PipelineCallbacks, requestSignal: AbortSignal): Promise<void> {
    const startTime = Date.now();
    const activeProvider = ctx.state.modelSnapshot?.provider || llmService.getActiveProvider();
    let baseUrl =
      activeProvider?.baseUrl ||
      (import.meta.env.VITE_LLM_BASE_URL as string) ||
      "";
    if (!baseUrl) {
      ctx.state.globalBlocker = true;
      throw new Error("尚未配置模型服务");
    }
    const apiKey = ctx.state.modelSnapshot ? activeProvider?.apiKey || "" : activeProvider?.apiKey || llmService.getApiKey();
    const model = ctx.state.modelSnapshot?.model || llmService.getModel();

    // In dev mode, route through Vite proxy to avoid CORS preflight issues
    if (
      import.meta.env.DEV && !usesNativeNetwork() &&
      (baseUrl.includes("tokenrhythm.studio") || baseUrl.startsWith("/api/llm"))
    ) {
      baseUrl = `/api/llm/v1`;
    }

    const cleanBase = baseUrl.replace(/\/+$/, "");
    await refreshMcpTools(ctx);
    const messagesPayload = buildAnalysisMessages(ctx);
    const inputEstimate = estimateMessageTokens(messagesPayload);
    if (ctx.state.refreshTokenBudget) ctx.budget.maxTokens = ctx.state.refreshTokenBudget();
    const remaining = Math.floor(ctx.budget.maxTokens - ctx.budget.tokensUsed);
    if (remaining <= inputEstimate + 32) {
      ctx.state.tokenBudgetExhausted = true;
      throw new Error("剩余额度不足以发送本轮上下文");
    }
    const outputLimit = Number.isFinite(remaining) ? remaining - inputEstimate : undefined;
    const previousUsage = ctx.budget.tokensUsed;
    const previousEstimated = ctx.budget.usageEstimated;
    let chargedInput = false;
    let actualUsage = false;

    let fullContent = "";
    let firstTokenTime = 0;
    let tokenCount = 0;
    let titleSent = false;

    try {
      const url = `${cleanBase}/chat/completions`;
      chargedInput = true;
      ctx.budget.tokensUsed = previousUsage + inputEstimate;
      ctx.budget.usageEstimated = true;
      const res = await modelFetch(url, {
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
          max_tokens: outputLimit,
          stream_options: { include_usage: true },
        }),
        signal: requestSignal,
      });

      if (!res.ok) {
        throw await modelResponseError(res);
      }

      const reader = res.body?.getReader();
      if (!reader) throw new Error("Response body is not readable");

      const decoder = new TextDecoder();
      let buffer = "";
      let isStreamDone = false;
      let finishedChoice = false;
      const consume = (line: string) => {
        const trimmed = line.trim();
        if (trimmed === "data: [DONE]") { isStreamDone = true; return; }
        if (!trimmed.startsWith("data:")) return;
        let json;
        try { json = JSON.parse(trimmed.slice(5).trim()); } catch { return; }
        if (!json || typeof json !== "object") return;
        if (json.error) throw Object.assign(new Error(JSON.stringify(json.error)), { status: json.error.status });
        if (typeof json.usage?.total_tokens === "number" && json.usage.total_tokens >= 0) {
          ctx.budget.tokensUsed = previousUsage + json.usage.total_tokens;
          actualUsage = true;
        }
        const choice = json.choices?.[0];
        if (choice?.finish_reason != null) finishedChoice = true;
        const delta = choice?.delta?.content || "";
        if (delta) {
          if (!firstTokenTime) firstTokenTime = Date.now();
          tokenCount += delta.length > 3 ? Math.round(delta.length / 3) : 1;
          fullContent += delta;
          if (!titleSent && fullContent.includes('"title"') && parseAcceptancePlan(fullContent, ctx) && ctx.state.suggestedTitle) {
            callbacks.onTitle?.(ctx.state.suggestedTitle);
            titleSent = true;
          }
          if (!actualUsage) ctx.budget.tokensUsed = previousUsage + inputEstimate + Math.ceil(new TextEncoder().encode(fullContent).length / 3);
          callbacks.onToken?.(fullContent);
        }
      };
      try {
        while (!isStreamDone) {
          const { done, value } = await reader.read();
          buffer += decoder.decode(value, { stream: !done });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";
          for (const line of lines) { consume(line); if (isStreamDone) break; }
          if (done && !isStreamDone && buffer.trim()) consume(buffer);
          if (ctx.budget.tokensUsed >= ctx.budget.maxTokens) {
            ctx.state.tokenBudgetExhausted = true;
            throw new Error("Token 额度已耗尽");
          }
          if (done) break;
        }
        if (!isStreamDone && !finishedChoice) throw new HealthFault("NETWORK_FAILED", "模型响应未完成，连接已中断");
      } finally {
        await reader.cancel().catch(() => {});
        reader.releaseLock();
      }

      if (!fullContent.trim()) throw new Error("模型未返回可用内容");
      ctx.budget.usageEstimated = previousEstimated || !actualUsage || !!ctx.state.priorEstimatedUsage;
      ctx.state.priorEstimatedUsage = ctx.budget.usageEstimated;
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
      if (chargedInput && !actualUsage) ctx.budget.usageEstimated = true;
      if (!ctx.signal?.aborted && !ctx.state.tokenBudgetExhausted && canRetryModelRequest(err)) {
        ctx.state.fullContent = fullContent;
        throw err;
      }
      ctx.state.globalBlocker = !ctx.signal?.aborted && !ctx.state.tokenBudgetExhausted;
      if (ctx.signal?.aborted || err?.name === "AbortError") {
        fullContent += "\n\n[已手动中止分析]";
      } else {
        fullContent += `\n\n[执行异常: ${err.message || String(err)}]`;
      }
      ctx.state.fullContent = fullContent;
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
