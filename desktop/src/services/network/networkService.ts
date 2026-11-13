import { ProxyPool, type ProxyRoute } from "./proxyPool";

export const usesNativeNetwork = () => typeof window !== "undefined" && Boolean((window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);
async function invoke<T = unknown>(command: string, args?: Record<string, unknown>): Promise<T> { return (await import("@tauri-apps/api/core")).invoke<T>(command, args); }

let storage: Storage | undefined;
try { storage = localStorage; } catch { /* Session-only settings. */ }
export const proxyPool = new ProxyPool(storage);
type NativeEvent = { kind: "started" } | { kind: "headers"; status: number; headers: Record<string, string> } | { kind: "chunk"; data: number[] } | { kind: "end" };
interface NetworkFailure { code: string; retryable: boolean; message: string }
export const nativeRoute = (route: ProxyRoute) => ({ mode: route.mode, url: route.node?.url, username: route.node?.username, password: route.node?.password });

async function nativeFetch(url: string, init: RequestInit, route: ProxyRoute): Promise<Response> {
  const { Channel } = await import("@tauri-apps/api/core");
  return new Promise((resolve, reject) => {
    const id = crypto.randomUUID();
    let started = false;
    let ended = false;
    let stream!: ReadableStreamDefaultController<Uint8Array>;
    const cleanup = () => init.signal?.removeEventListener("abort", abort);
    const fail = (error: unknown) => {
      if (ended) return;
      ended = true; cleanup();
      const failure = error as NetworkFailure;
      const detail = error instanceof Error ? error : Object.assign(new Error(failure.message || "网络请求失败"), { code: failure.code || "NETWORK_FAILED", retryable: failure.retryable === true });
      if (started) stream.error(detail); else reject(detail);
    };
    const cancelNative = () => { void invoke("network_cancel", { id }).catch(() => {}); };
    const abortReason = () => init.signal?.reason instanceof Error ? init.signal.reason : new DOMException("Aborted", "AbortError");
    const abort = () => { cancelNative(); fail(abortReason()); };
    if (init.signal?.aborted) { reject(abortReason()); return; }
    const body = new ReadableStream<Uint8Array>({ start(controller) { stream = controller; }, cancel() { ended = true; cleanup(); void invoke("network_cancel", { id }).catch(() => {}); } });
    const events = new Channel<NativeEvent>();
    events.onmessage = event => {
      // Cancellation can arrive before the asynchronous command registers its ID.
      // Reassert it after registration so stopped requests cannot survive that race.
      if (event.kind === "started") {
        if (ended || init.signal?.aborted) cancelNative();
        return;
      }
      if (ended) return;
      if (event.kind === "headers") {
        started = true;
        resolve(new Response([204, 205, 304].includes(event.status) || init.method === "HEAD" ? null : body, { status: event.status, headers: event.headers }));
      } else if (event.kind === "chunk") stream.enqueue(new Uint8Array(event.data));
      else { ended = true; cleanup(); stream.close(); }
    };
    init.signal?.addEventListener("abort", abort, { once: true });
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((value, key) => { headers[key] = value; });
    void invoke("network_request", { request: { id, url, method: init.method || "GET", headers, body: init.body || null, route: nativeRoute(route) }, onEvent: events }).catch(fail);
  });
}

export async function modelFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const request = new Request(input instanceof Request ? input : new URL(String(input), typeof window === "undefined" ? "http://localhost" : window.location.href), init);
  const options: RequestInit = { method: request.method, headers: request.headers, signal: request.signal, body: ["GET", "HEAD"].includes(request.method) ? undefined : await request.clone().text() };
  const routes = proxyPool.routes("model");
  const policy = proxyPool.getSnapshot().config.model.mode;
  if (!usesNativeNetwork()) {
    if (routes[0].mode !== "system") throw Object.assign(new Error("指定代理与直连控制需要桌面应用；浏览器预览使用浏览器网络设置"), { code: "PROXY_CONFIG" });
    return fetch(request);
  }
  for (let index = 0; index < routes.length; index++) {
    const route = routes[index];
    const start = performance.now();
    try {
      const response = await nativeFetch(request.url, options, route);
      if (route.node) proxyPool.observe(route.node.id, { state: "healthy", checkedAt: Date.now(), latencyMs: Math.round(performance.now() - start) }, route.node);
      return response;
    } catch (error) {
      const fault = error as Error & { retryable?: boolean; code?: string };
      if (request.signal.aborted || fault.name === "AbortError") throw error;
      if (route.node) proxyPool.observe(route.node.id, { state: "failed", checkedAt: Date.now(), error: fault.message }, route.node);
      if (!fault.retryable || policy === "fixed" || index === routes.length - 1) throw error;
    }
  }
  throw new Error("代理池暂无可用节点");
}

export async function testProxy(id: string, url: string): Promise<void> {
  const node = proxyPool.getSnapshot().config.nodes.find(item => item.id === id);
  if (!node) return;
  if (!usesNativeNetwork()) throw new Error("请在桌面应用中测试代理连接");
  const target = new URL(url);
  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password) throw new Error("请填写 HTTP 或 HTTPS 测试地址");
  proxyPool.observe(id, { state: "checking", checkedAt: Date.now() }, node);
  try {
    const result = await invoke<{ latencyMs: number; status: number }>("network_probe", { url: target.href, route: nativeRoute({ mode: "proxy", node }) });
    proxyPool.observe(id, { state: "healthy", checkedAt: Date.now(), latencyMs: result.latencyMs }, node);
  } catch (error) {
    proxyPool.observe(id, { state: "failed", checkedAt: Date.now(), error: (error as NetworkFailure)?.message || "代理连接失败" }, node);
  }
}

export function redactProxyOutput(text: string, route: ProxyRoute): string {
  for (const value of [route.node?.password, route.node?.username]) {
    if (value) for (const form of new Set([value, encodeURIComponent(value)])) text = text.split(form).join("[redacted]");
  }
  return text;
}
