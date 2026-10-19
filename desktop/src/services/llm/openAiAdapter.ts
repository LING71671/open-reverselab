import { createOpenAI } from "@ai-sdk/openai";
import { llmService } from "./llmService";

export function getAiModel() {
  const provider = llmService.getActiveProvider();
  let baseUrl = provider?.baseUrl || (import.meta.env.VITE_LLM_BASE_URL as string) || "https://tokenrhythm.studio/v1";
  const apiKey = provider?.apiKey || llmService.getApiKey();
  const modelName = llmService.getModel() || "deepseek-v4-flash-0731";

  // Use Vite proxy in local dev to bypass CORS preflight if needed
  if (
    import.meta.env.DEV &&
    (baseUrl.includes("tokenrhythm.studio") || baseUrl.startsWith("/api/llm"))
  ) {
    baseUrl = `${window.location.origin}/api/llm/v1`;
  }

  const cleanBase = baseUrl.replace(/\/+$/, "");

  const openai = createOpenAI({
    baseURL: cleanBase,
    apiKey: apiKey,
  });

  return openai(modelName);
}
