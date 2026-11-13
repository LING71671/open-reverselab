import type { PipelineContext } from "../../core/contracts/pipeline";
import type { PythonExecResult } from "../../services/native/nativeBridge";
import type { TrackVerification } from "./contract";

/** A deliberately narrow goal with an independent native-triage verifier. */
export function isHashObjective(prompt: string): boolean {
  const text = prompt.trim().replace(/[。.！!？?]+$/, "");
  return /^(?:请)?(?:计算|获取|查看|检查|验证)(?:目标|该文件|文件)?(?:的)?\s*sha-?256(?:\s*(?:值|哈希|校验和))?$/i.test(text) ||
    /^(?:calculate|compute|get|show|verify) (?:the )?sha-?256(?: hash)?(?: of (?:the )?(?:target|file))?$/i.test(text);
}

export function verifyTargetEvidence(ctx: PipelineContext, result?: PythonExecResult): TrackVerification {
  const executionSucceeded = !!result?.success;
  let evidence: { target?: string; sha256?: string; observations?: unknown[] } | undefined;
  for (const line of (result?.stdout || "").trim().split("\n").reverse()) {
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === "object" && typeof parsed.sha256 === "string") {
        evidence = parsed;
        break;
      }
    } catch { /* Only the structured observation line is considered. */ }
  }
  const normalizePath = (value: string) => value.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  const expectedTarget = ctx.target;
  const targetMatches = typeof evidence?.target === "string" && normalizePath(evidence.target) === normalizePath(expectedTarget);
  const expectedHash = ctx.triage?.sha256?.toLowerCase();
  const hashMatches = !!expectedHash && /^[a-f0-9]{64}$/.test(expectedHash) && evidence?.sha256?.toLowerCase() === expectedHash;
  const evidenceAccepted = executionSucceeded && targetMatches && hashMatches;
  const goalVerified = isHashObjective(ctx.prompt) && evidenceAccepted;
  const reason = !executionSucceeded ? result?.stderr || "取证脚本执行失败"
    : !evidenceAccepted ? "输出尚未与独立初筛的目标路径和 SHA256 对齐"
    : goalVerified ? "SHA256 与独立初筛结果一致"
    : "已收集目标证据；当前执行器尚无该任务目标的独立验证器";
  return {
    executionSucceeded,
    evidenceAccepted,
    goalVerified,
    reason,
    goal: {
      objective: ctx.prompt,
      status: goalVerified ? "verified" : "in_progress",
      passRate: `${Number(targetMatches) + Number(hashMatches)}/2 evidence checks`,
      assertions: [
        { name: "Target identity", expected: expectedTarget, actual: evidence?.target || "Missing", passed: targetMatches },
        { name: "Independent SHA256", expected: expectedHash || "Unavailable", actual: evidence?.sha256 || "Missing", passed: hashMatches },
      ],
      timestamp: Date.now(),
    },
  };
}
