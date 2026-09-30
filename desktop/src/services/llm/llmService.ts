export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface CompletionResult {
  content: string;
  reasoning?: string;
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  durationMs: number;
  model: string;
}

export class LlmService {
  private baseUrl: string;
  private apiKey: string;
  private defaultModel: string;

  constructor() {
    this.baseUrl = (import.meta.env.VITE_LLM_BASE_URL as string) || "https://tokenrhythm.studio/v1";
    this.apiKey =
      localStorage.getItem("reverselab_api_key") ||
      (import.meta.env.VITE_LLM_API_KEY as string) ||
      "";
    this.defaultModel =
      localStorage.getItem("reverselab_model") ||
      (import.meta.env.VITE_LLM_MODEL as string) ||
      "qwen3.8-flash";
  }

  public getApiKey(): string {
    return this.apiKey;
  }

  public setApiKey(key: string): void {
    this.apiKey = key;
    localStorage.setItem("reverselab_api_key", key);
  }

  public getModel(): string {
    return this.defaultModel;
  }

  public setModel(model: string): void {
    this.defaultModel = model;
    localStorage.setItem("reverselab_model", model);
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  public setBaseUrl(url: string): void {
    this.baseUrl = url;
    localStorage.setItem("reverselab_base_url", url);
  }

  private resolveUrl(path: string): string {
    // In dev mode, route through Vite proxy to bypass browser CORS preflight
    if (
      import.meta.env.DEV &&
      (this.baseUrl.includes("tokenrhythm.studio") || this.baseUrl.startsWith("/api/llm"))
    ) {
      return `/api/llm/v1${path}`;
    }
    return `${this.baseUrl}${path}`;
  }

  public async checkHealth(): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
    const start = performance.now();
    try {
      const url = this.resolveUrl("/chat/completions");
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model: this.defaultModel,
          messages: [{ role: "user", content: "ping" }],
          max_tokens: 5,
        }),
      });

      const latencyMs = Math.round(performance.now() - start);
      if (!res.ok) {
        const text = await res.text();
        return { ok: false, latencyMs, error: `HTTP ${res.status}: ${text}` };
      }
      return { ok: true, latencyMs };
    } catch (err: any) {
      return {
        ok: false,
        latencyMs: Math.round(performance.now() - start),
        error: err.message || String(err),
      };
    }
  }

  public async complete(
    messages: ChatMessage[],
    options?: {
      model?: string;
      temperature?: number;
      maxTokens?: number;
      timeoutMs?: number;
      signal?: AbortSignal;
    }
  ): Promise<CompletionResult> {
    const start = performance.now();
    const model = options?.model || this.defaultModel;
    const url = this.resolveUrl("/chat/completions");

    const timeoutMs = options?.timeoutMs ?? 5000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const abortHandler = () => controller.abort();
    if (options?.signal) {
      options.signal.addEventListener("abort", abortHandler);
    }

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages,
          temperature: options?.temperature ?? 0.3,
          max_tokens: options?.maxTokens ?? 2048,
        }),
        signal: controller.signal,
      });

      const durationMs = Math.round(performance.now() - start);

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`LLM Error ${res.status}: ${errText}`);
      }

      const data = await res.json();
      const choice = data.choices?.[0];
      const message = choice?.message || {};

      return {
        content: message.content || "",
        reasoning: message.reasoning_content || undefined,
        usage: data.usage
          ? {
              promptTokens: data.usage.prompt_tokens || 0,
              completionTokens: data.usage.completion_tokens || 0,
              totalTokens: data.usage.total_tokens || 0,
            }
          : undefined,
        durationMs,
        model,
      };
    } finally {
      clearTimeout(timer);
      if (options?.signal) {
        options.signal.removeEventListener("abort", abortHandler);
      }
    }
  }
}

export const llmService = new LlmService();
