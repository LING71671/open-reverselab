import { modelFetch, modelResponseError, usesNativeNetwork } from "../network/networkService";

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
  model?: string;
}

interface SavedProvider extends ProviderConfig {
  models?: string[];
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
  private providers: SavedProvider[] = [];
  private activeProviderId: string = "";
  private defaultModel: string;

  constructor() {
    const savedModel = localStorage.getItem("reverselab_model");
    this.defaultModel = (savedModel ?? (import.meta.env.VITE_LLM_MODEL as string) ?? "").trim();

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

    const savedActiveId = localStorage.getItem("reverselab_active_provider_id");
    if (savedActiveId && this.providers.some((p) => p.id === savedActiveId)) {
      this.activeProviderId = savedActiveId;
    } else {
      this.activeProviderId = this.providers[0]?.id || "";
    }
    const active = this.getActiveProvider();
    if (active && active.model === undefined && this.defaultModel) {
      active.model = this.defaultModel;
      updated = true;
    }
    if (updated) this.saveProviders();
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
      if (localStorage.getItem("reverselab_evidence_fallback_provider") === id) this.setEvidenceFallbackProviderId("");
      localStorage.setItem("reverselab_active_provider_id", id);
      localStorage.setItem("reverselab_model", this.getModel());
    }
  }

  public addProvider(provider: ProviderConfig, activate = true): void {
    const exists = this.providers.findIndex((p) => p.id === provider.id);
    if (exists >= 0) {
      const previous = this.providers[exists];
      const sameEndpoint = previous.baseUrl === provider.baseUrl && previous.apiKey === provider.apiKey;
      this.providers[exists] = { ...provider, model: provider.model ?? previous.model, models: sameEndpoint ? previous.models : undefined };
    } else {
      this.providers.push({ ...provider, model: provider.model ?? (this.providers.length ? "" : this.defaultModel) });
    }
    this.saveProviders();
    if (activate || !this.activeProviderId || provider.id === this.activeProviderId) this.setActiveProviderId(provider.id);
  }

  public removeProvider(id: string): void {
    this.providers = this.providers.filter((p) => p.id !== id);
    if (localStorage.getItem("reverselab_evidence_fallback_provider") === id) this.setEvidenceFallbackProviderId("");
    this.saveProviders();
    if (this.activeProviderId === id) {
      this.activeProviderId = this.providers[0]?.id || "";
      localStorage.setItem("reverselab_active_provider_id", this.activeProviderId);
      this.defaultModel = "";
      localStorage.setItem("reverselab_model", this.getModel());
    }
  }

  public getApiKey(): string {
    const active = this.getActiveProvider();
    return active?.apiKey || "";
  }

  public setApiKey(key: string): void {
    const active = this.getActiveProvider();
    if (active) this.addProvider({ ...active, apiKey: key });
  }

  public getModel(providerId = this.activeProviderId): string {
    if (!providerId) return this.defaultModel;
    return this.providers.find(p => p.id === providerId)?.model || "";
  }

  public setModel(model: string): void {
    const active = this.getActiveProvider();
    if (active) {
      active.model = model;
      this.saveProviders();
    } else {
      this.defaultModel = model;
    }
    localStorage.setItem("reverselab_model", model);
  }

  public getEvidenceFallbackProviderId(): string {
    const id = localStorage.getItem("reverselab_evidence_fallback_provider");
    return id && id !== this.activeProviderId && this.providers.some(p => p.id === id) ? id : "";
  }

  public setEvidenceFallbackProviderId(id: string): void {
    if (id && (id === this.activeProviderId || !this.providers.some(p => p.id === id))) throw new Error("请选择其他已保存的提供商");
    localStorage.setItem("reverselab_evidence_fallback_provider", id);
  }

  public getBaseUrl(): string {
    const active = this.getActiveProvider();
    return active?.baseUrl || (import.meta.env.VITE_LLM_BASE_URL as string) || "";
  }

  public setBaseUrl(url: string): void {
    const active = this.getActiveProvider();
    if (active) this.addProvider({ ...active, baseUrl: url });
  }

  public getCachedModels(providerId = this.getActiveProviderId()): string[] {
    const provider = this.providers.find(item => item.id === providerId);
    return [...(provider?.models || [])];
  }

  public async fetchModels(providerId?: string): Promise<string[]> {
    const provider = providerId
      ? this.providers.find((p) => p.id === providerId)
      : this.getActiveProvider();

    if (!provider || !provider.baseUrl) {
      return [];
    }

    const baseUrl = provider.baseUrl, apiKey = provider.apiKey;
    try {
      const url = this.resolveUrl("/models", provider.baseUrl);
      const headers: Record<string, string> = {};
      const key = provider.apiKey || "";
      if (key) {
        headers["Authorization"] = `Bearer ${key}`;
      }

      const res = await modelFetch(url, { headers, signal: AbortSignal.timeout(10000) });
      if (res.ok) {
        const data = await res.json();
        const list: string[] = Array.isArray(data.data) ? [...new Set<string>(data.data.map((m: any) => m?.id).filter((id: unknown): id is string => typeof id === "string" && Boolean(id.trim())))] : [];
        const current = this.providers.find(p => p.id === provider.id);
        if (!current || current.baseUrl !== baseUrl || current.apiKey !== apiKey) return [];
        current.models = list;
        this.saveProviders();
        return list;
      }
    } catch {
      // live fetch error, return empty
    }
    return [];
  }

  private resolveUrl(path: string, customBase?: string): string {
    const base = (customBase || this.getBaseUrl()).replace(/\/+$/, "");
    if (
      import.meta.env.DEV && !usesNativeNetwork() &&
      ["/api/llm", "https://tokenrhythm.studio", "https://tokenrhythm.studio/v1"].includes(base)
    ) {
      return `/api/llm/v1${path}`;
    }
    return `${base}${path}`;
  }

  public async checkHealth(providerId = this.activeProviderId): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
    const start = performance.now();
    try {
      const provider = this.providers.find(p => p.id === providerId);
      const model = this.getModel(providerId);
      if (!provider?.baseUrl) throw new Error("请先配置 API 地址");
      const url = this.resolveUrl(model ? "/chat/completions" : "/models", provider.baseUrl);
      const headers: Record<string, string> = {};
      if (provider.apiKey) headers.Authorization = `Bearer ${provider.apiKey}`;
      if (model) headers["Content-Type"] = "application/json";
      const res = await modelFetch(url, {
        method: model ? "POST" : "GET",
        headers,
        body: model ? JSON.stringify({ model, messages: [{ role: "user", content: "ping" }], max_tokens: 5 }) : undefined,
        signal: AbortSignal.timeout(10000),
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
      provider?: ProviderConfig;
      providerId?: string;
    }
  ): Promise<CompletionResult> {
    const start = performance.now();
    const explicitId = options?.providerId;
    const active = explicitId !== undefined ? this.providers.find(p => p.id === explicitId) : options?.provider || this.getActiveProvider();
    if (explicitId !== undefined && !active) throw new Error("选定的提供商不存在");
    const model = explicitId !== undefined ? this.getModel(explicitId) : options?.model || this.getModel();
    if (!active?.baseUrl || !model) throw new Error("请先配置 API 地址和模型 ID");
    const url = this.resolveUrl("/chat/completions", active?.baseUrl);
    const key = active.apiKey || "";

    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (options?.timeoutMs !== undefined && Number.isFinite(options.timeoutMs)) {
      const deadline = performance.now() + Math.max(0, options.timeoutMs);
      const checkDeadline = () => {
        const remaining = deadline - performance.now();
        if (remaining <= 0) controller.abort(new DOMException("Model request deadline exceeded", "TimeoutError"));
        else timer = setTimeout(checkDeadline, Math.min(remaining, 2147483647));
      };
      checkDeadline();
    }

    const abortHandler = () => controller.abort(options?.signal?.reason);
    if (options?.signal) {
      if (options.signal.aborted) controller.abort(options.signal.reason);
      else options.signal.addEventListener("abort", abortHandler, { once: true });
    }

    try {
      const res = await modelFetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({
          model,
          messages,
          temperature: options?.temperature ?? 0.3,
          ...(options?.maxTokens !== undefined && Number.isFinite(options.maxTokens) ? { max_tokens: options.maxTokens } : {}),
        }),
        signal: controller.signal,
      });

      const durationMs = Math.round(performance.now() - start);

      if (!res.ok) {
        throw await modelResponseError(res);
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
