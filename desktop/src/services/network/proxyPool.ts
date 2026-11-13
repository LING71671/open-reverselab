export type ProxyMode = "system" | "direct" | "fixed" | "failover" | "round-robin";
export type NetworkScope = "model" | "tools";
export interface ProxyNode { id: string; name: string; url: string; username: string; password: string; enabled: boolean }
export interface ProxyPolicy { mode: ProxyMode; nodeId: string }
export interface ProxyConfig { nodes: ProxyNode[]; model: ProxyPolicy; tools: ProxyPolicy }
export interface ProxyRoute { mode: "system" | "direct" | "proxy"; node?: ProxyNode }
export interface ProxyHealth { state: "checking" | "healthy" | "failed"; latencyMs?: number; checkedAt: number; error?: string }
export interface ProxySnapshot { config: ProxyConfig; health: Record<string, ProxyHealth> }
export const defaultProxyConfig = (): ProxyConfig => ({ nodes: [], model: { mode: "system", nodeId: "" }, tools: { mode: "system", nodeId: "" } });
const modes = new Set(["system", "direct", "fixed", "failover", "round-robin"]);

export function validateProxyConfig(value: ProxyConfig): ProxyConfig {
  if (!value || !Array.isArray(value.nodes)) throw new Error("代理节点列表无效");
  const ids = new Set<string>();
  const nodes = value.nodes.map(node => {
    if (!node.id || ids.has(node.id)) throw new Error("代理节点 ID 重复");
    ids.add(node.id);
    let url: URL;
    try { url = new URL(node.url.trim()); } catch { throw new Error("请输入完整代理地址，如 http://127.0.0.1:8080"); }
    if (!["http:", "https:", "socks5:", "socks5h:"].includes(url.protocol) || !url.hostname || (url.protocol.startsWith("socks") && !url.port)) throw new Error("代理地址需包含 HTTP、HTTPS 或 SOCKS5 协议和端口");
    if (url.username || url.password || url.search || url.hash || (url.pathname && url.pathname !== "/")) throw new Error("地址只填写协议、主机和端口；认证使用单独的账号字段");
    if (typeof node.username !== "string" || typeof node.password !== "string" || node.username.length > 512 || node.password.length > 512) throw new Error("代理认证信息无效");
    if (node.password && !node.username) throw new Error("填写代理密码时也需要用户名");
    if (!node.name?.trim() || node.name.length > 80) throw new Error("请填写不超过 80 字的节点名称");
    return { ...node, name: node.name.trim(), url: url.href.replace(/\/$/, ""), enabled: Boolean(node.enabled) };
  });
  for (const scope of ["model", "tools"] as const) {
    const policy = value[scope];
    if (!policy || !modes.has(policy.mode)) throw new Error("请选择有效的代理策略");
    if (scope === "tools" && policy.mode === "failover") throw new Error("Python 任务使用固定节点或轮询，不重复执行脚本");
    if (policy.mode === "fixed" && !nodes.some(node => node.id === policy.nodeId && node.enabled)) throw new Error("固定代理需选择一个已启用的节点");
    const candidates = nodes.filter(node => node.enabled && (policy.mode !== "fixed" || node.id === policy.nodeId));
    if (!["system", "direct"].includes(policy.mode) && !candidates.length) throw new Error("请先添加并启用代理节点");
    if (scope === "tools" && !["system", "direct"].includes(policy.mode) && !candidates.some(node => /^https?:/.test(node.url))) throw new Error("Python 目标访问需要 HTTP 或 HTTPS 代理");
  }
  return { nodes, model: { ...value.model }, tools: { ...value.tools } };
}

export class ProxyPool {
  private snapshot: ProxySnapshot = { config: defaultProxyConfig(), health: {} };
  private listeners = new Set<() => void>();
  private cursors = { model: 0, tools: 0 };
  private storage?: Pick<Storage, "getItem" | "setItem">;
  private now: () => number;
  constructor(storage?: Pick<Storage, "getItem" | "setItem">, now = Date.now) {
    this.storage = storage;
    this.now = now;
    try { const raw = storage?.getItem("reverselab_proxy_pool"); if (raw) this.snapshot.config = validateProxyConfig(JSON.parse(raw)); } catch { /* Invalid saved configuration is reported before any network use. */ this.invalidStoredConfig = true; }
  }
  private invalidStoredConfig = false;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  getSnapshot = () => this.snapshot;
  private emit() { for (const listener of this.listeners) listener(); }
  save(config: ProxyConfig) {
    const valid = validateProxyConfig(config);
    this.storage?.setItem("reverselab_proxy_pool", JSON.stringify(valid));
    this.snapshot = { config: valid, health: {} };
    this.invalidStoredConfig = false;
    this.cursors = { model: 0, tools: 0 };
    this.emit();
  }
  observe(id: string, health: ProxyHealth, observedNode?: ProxyNode) {
    if (observedNode && !this.snapshot.config.nodes.some(node => node.id === id && node.url === observedNode.url && node.username === observedNode.username && node.password === observedNode.password && node.enabled === observedNode.enabled)) return;
    this.snapshot = { ...this.snapshot, health: { ...this.snapshot.health, [id]: health } };
    this.emit();
  }
  routes(scope: NetworkScope): ProxyRoute[] {
    if (this.invalidStoredConfig) throw Object.assign(new Error("代理配置无法读取，请在设置中重新保存"), { code: "PROXY_CONFIG" });
    const { config, health } = this.snapshot;
    const policy = config[scope];
    if (policy.mode === "direct" || policy.mode === "system") return [{ mode: policy.mode }];
    let nodes = config.nodes.filter(node => node.enabled && (scope !== "tools" || /^https?:/.test(node.url)));
    if (policy.mode === "fixed") nodes = nodes.filter(node => node.id === policy.nodeId);
    else nodes = nodes.filter(node => health[node.id]?.state !== "failed" || this.now() - health[node.id].checkedAt >= 30_000);
    if (!nodes.length) throw Object.assign(new Error("代理池暂无可用节点，请检查连接或等待 30 秒后重试"), { code: "PROXY_UNAVAILABLE" });
    if (policy.mode === "round-robin") {
      const offset = this.cursors[scope]++ % nodes.length;
      nodes = [...nodes.slice(offset), ...nodes.slice(0, offset)];
    }
    return nodes.map(node => ({ mode: "proxy", node: { ...node } }));
  }
}
