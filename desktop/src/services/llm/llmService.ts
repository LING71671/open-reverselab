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

export interface ProviderConfig {
  id: string;
  name: string;
  baseUrl: string;
  apiKey?: string;
}

export function deriveProviderName(urlOrHost: string): string {
  try {
    const raw = urlOrHost.startsWith("http") ? new URL(urlOrHost).hostname : urlOrHost;
    if (raw.includes("tokenrhythm.studio")) return "TokenRhythm";
    if (raw.includes("openai.com")) return "OpenAI";
    if (raw.includes("anthropic.com")) return "Anthropic";
    if (raw.includes("deepseek.com")) return "DeepSeek";
    if (raw.includes("siliconflow.cn")) return "SiliconFlow";
    return raw.replace(/^api\./, "").split(".")[0] || "Custom";
  } catch {
    return "Custom";
  }
}

export class LlmService {
  private providers: ProviderConfig[] = [];
  private activeProviderId: string = "";
  private defaultModel: string;

  constructor() {
    const savedModel = localStorage.getItem("reverselab_model");
    if (!savedModel || savedModel.includes("deepseek")) {
      this.defaultModel = "mimo-v2.6-flash";
      try {
        localStorage.setItem("reverselab_model", "mimo-v2.6-flash");
      } catch {}
    } else {
      this.defaultModel = savedModel;
    }

    this.loadProviders();
  }

  private loadProviders(): void {
    const raw = localStorage.getItem("reverselab_providers");
    if (raw) {
      try {
        this.providers = JSON.parse(raw);
      } catch {
        this.providers = [];
      }
    }

    // Upgrade any generic "Default" / "默认" names to real provider name derived from baseUrl
    let updated = false;
    for (const p of this.providers) {
      if (!p.name || p.name === "Default" || p.name === "默认") {
        p.name = deriveProviderName(p.baseUrl);
        updated = true;
      }
    }

    // If no providers in storage, seed ONLY from actual environment variables if present
    if (this.providers.length === 0 && import.meta.env.VITE_LLM_BASE_URL) {
      const envUrl = import.meta.env.VITE_LLM_BASE_URL as string;
      const envKey = (import.meta.env.VITE_LLM_API_KEY as string) || "";
      const initial: ProviderConfig = {
        id: "env-provider",
        name: deriveProviderName(envUrl),
        baseUrl: envUrl,
        apiKey: envKey,
      };
      this.providers = [initial];
      updated = true;
    }

    if (updated) {
      this.saveProviders();
    }

    const savedActiveId = localStorage.getItem("reverselab_active_provider_id");
    if (savedActiveId && this.providers.some((p) => p.id === savedActiveId)) {
      this.activeProviderId = savedActiveId;
    } else {
      this.activeProviderId = this.providers[0]?.id || "";
    }
  }

  private saveProviders(): void {
    localStorage.setItem("reverselab_providers", JSON.stringify(this.providers));
  }

  public getProviders(): ProviderConfig[] {
    return [...this.providers];
  }

  public getActiveProviderId(): string {
    return this.activeProviderId;
  }

  public getActiveProvider(): ProviderConfig | undefined {
    return this.providers.find((p) => p.id === this.activeProviderId) || this.providers[0];
  }

  public setActiveProviderId(id: string): void {
    if (this.providers.some((p) => p.id === id)) {
      this.activeProviderId = id;
      localStorage.setItem("reverselab_active_provider_id", id);
    }
  }

  public addProvider(provider: ProviderConfig): void {
    const exists = this.providers.findIndex((p) => p.id === provider.id);
    if (exists >= 0) {
      this.providers[exists] = provider;
    } else {
      this.providers.push(provider);
    }
    this.saveProviders();
    this.setActiveProviderId(provider.id);
  }

  public removeProvider(id: string): void {
    this.providers = this.providers.filter((p) => p.id !== id);
    this.saveProviders();
    if (this.activeProviderId === id) {
      this.activeProviderId = this.providers[0]?.id || "";
      localStorage.setItem("reverselab_active_provider_id", this.activeProviderId);
    }
  }

  public getApiKey(): string {
    const active = this.getActiveProvider();
    return active?.apiKey || (import.meta.env.VITE_LLM_API_KEY as string) || "";
  }

  public setApiKey(key: string): void {
    const active = this.getActiveProvider();
    if (active) {
      active.apiKey = key;
      this.saveProviders();
    }
  }

  public getModel(): string {
    return this.defaultModel;
  }

  public setModel(model: string): void {
    this.defaultModel = model;
    localStorage.setItem("reverselab_model", model);
  }

  public getBaseUrl(): string {
    const active = this.getActiveProvider();
    return active?.baseUrl || (import.meta.env.VITE_LLM_BASE_URL as string) || "";
  }

  public setBaseUrl(url: string): void {
    const active = this.getActiveProvider();
    if (active) {
      active.baseUrl = url;
      this.saveProviders();
    }
  }

  public async fetchModels(providerId?: string): Promise<string[]> {
    const provider = providerId
      ? this.providers.find((p) => p.id === providerId)
      : this.getActiveProvider();

    if (!provider || !provider.baseUrl) {
      return [];
    }

    try {
      const url = this.resolveUrl("/models", provider.baseUrl);
      const headers: Record<string, string> = {};
      const key = provider.apiKey || this.getApiKey();
      if (key) {
        headers["Authorization"] = `Bearer ${key}`;
      }

      const res = await fetch(url, { headers });
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data.data) ? data.data.map((m: any) => m.id) : [];
        if (list.length > 0) return list;
      }
    } catch {
      // live fetch error, return empty
    }
    return [];
  }

  private resolveUrl(path: string, customBase?: string): string {
    const base = customBase || this.getBaseUrl();
    if (
      import.meta.env.DEV &&
      (base.includes("tokenrhythm.studio") || base.startsWith("/api/llm"))
    ) {
      return `/api/llm/v1${path}`;
    }
    const cleanBase = base.replace(/\/+$/, "");
    return `${cleanBase}${path}`;
  }

  public async checkHealth(): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
    const start = performance.now();
    try {
      const active = this.getActiveProvider();
      const url = this.resolveUrl("/chat/completions", active?.baseUrl);
      const key = active?.apiKey || this.getApiKey();
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${key}`,
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
    const active = this.getActiveProvider();
    const model = options?.model || this.defaultModel;
    const url = this.resolveUrl("/chat/completions", active?.baseUrl);
    const key = active?.apiKey || this.getApiKey();

    const timeoutMs = options?.timeoutMs ?? 30000;
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
          Authorization: `Bearer ${key}`,
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
