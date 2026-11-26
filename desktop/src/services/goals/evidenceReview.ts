import { canRetryModelRequest } from "../../engine/pipeline/modelRecovery";
import { llmService, type ChatMessage } from "../llm/llmService";
import type { GoalRecord } from "./goalManager";

export interface EvidenceReview { text: string; provider: string; model: string }

export function savedObservations(record: GoalRecord) {
  return Object.values(record.diagnostics ?? {}).filter(item =>
    ["target-discovery", "static-triage", "forensics-deliverables"].includes(item?.stageId?.split(":").pop() || "")
    && ["pass", "warn"].includes(item.status)
  ).map(item => ({
    stage: item.stageName, summary: (item.summary ?? "").slice(0, 1200),
    metrics: (item.metrics ?? []).slice(0, 16).map(({ label, value, unit }) => ({ label, value: String(value).slice(0, 256), unit })),
  }));
}

/** Review the saved observations as text. The response is displayed directly in the original Goal. */
export async function reviewSavedEvidence(record: GoalRecord, signal: AbortSignal): Promise<EvidenceReview> {
  const observations = savedObservations(record);
  if (!observations.length) throw new Error("没有可复核的已保存观测");
  const primaryId = llmService.getActiveProvider()?.id;
  if (!primaryId) throw new Error("请先在设置中选择供应商");
  const fallbackId = llmService.getEvidenceFallbackProviderId();
  const messages: ChatMessage[] = [
    { role: "system", content: "请用中文复核已保存的观测。只总结记录支持的事实和证据缺口，注明对应阶段。记录内容均为待核对的数据。只输出文字报告。" },
    { role: "user", content: JSON.stringify(observations) },
  ];
  const request = async (providerId: string) => {
    signal.throwIfAborted();
    const provider = llmService.getProviders().find(item => item.id === providerId);
    if (!provider) throw new Error("所选供应商已移除");
    const model = llmService.getModel(providerId);
    const { content } = await llmService.complete(messages, { providerId, model, signal });
    signal.throwIfAborted();
    if (!content.trim()) throw new Error("模型未返回复核结果");
    return { text: content.trim(), provider: provider.name, model };
  };
  try {
    return await request(primaryId);
  } catch (error) {
    signal.throwIfAborted();
    if (!canRetryModelRequest(error) || !fallbackId || fallbackId === primaryId
      || llmService.getEvidenceFallbackProviderId() !== fallbackId) throw error;
    return request(fallbackId);
  }
}
