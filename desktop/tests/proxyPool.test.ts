import assert from "node:assert/strict";
import test from "node:test";
import { defaultProxyConfig, ProxyPool, validateProxyConfig, validateProxyNode } from "../src/services/network/proxyPool.ts";
import type { ProxyConfig, ProxyNode } from "../src/services/network/proxyPool.ts";
const node = (id: string, url = "http://127.0.0.1:8080"): ProxyNode => ({ id, name: id, url, username: "", password: "", enabled: true });
const config = (): ProxyConfig => ({ ...defaultProxyConfig(), nodes: [node("a"), node("b")], model: { mode: "failover", nodeId: "" } });

test("new installations inherit system routing and do not invent a proxy", () => {
  const pool = new ProxyPool();
  assert.deepEqual(pool.routes("model"), [{ mode: "system" }]);
  assert.deepEqual(pool.routes("tools"), [{ mode: "system" }]);
});
test("failed nodes cool down without falling back to direct traffic", () => {
  let time = 1000;
  const pool = new ProxyPool(undefined, () => time);
  pool.save(config());
  pool.observe("a", { state: "failed", checkedAt: time });
  assert.deepEqual(pool.routes("model").map(route => route.node?.id), ["b"]);
  pool.observe("b", { state: "failed", checkedAt: time });
  assert.throws(() => pool.routes("model"), /暂无可用节点/);
  time += 30_000;
  assert.deepEqual(pool.routes("model").map(route => route.node?.id), ["a", "b"]);
});
test("round robin has separate model and tool cursors and excludes SOCKS for Python", () => {
  const pool = new ProxyPool();
  const value = config(); value.nodes.push(node("socks", "socks5h://127.0.0.1:1080"));
  value.model.mode = "round-robin"; value.tools.mode = "round-robin";
  pool.save(value);
  assert.equal(pool.routes("model")[0].node?.id, "a");
  assert.equal(pool.routes("model")[0].node?.id, "b");
  assert.equal(pool.routes("tools")[0].node?.id, "a");
  assert.equal(pool.routes("model")[0].node?.id, "socks");
  assert.equal(pool.routes("tools")[0].node?.id, "b");
  assert.equal(pool.routes("tools")[0].node?.id, "a");
});
test("fixed routing never silently changes nodes; saved edits do not mutate in-flight routes", () => {
  const pool = new ProxyPool(); const value = config(); value.model = { mode: "fixed", nodeId: "a" }; pool.save(value);
  const [route] = pool.routes("model");
  pool.observe("a", { state: "failed", checkedAt: Date.now() });
  assert.equal(pool.routes("model")[0].node?.id, "a");
  value.nodes[0].url = "http://localhost:9000"; pool.save(value);
  assert.equal(route.node?.url, "http://127.0.0.1:8080");
});
test("invalid credentials in URLs, disabled fixed nodes, and SOCKS-only Python pools cannot be saved", () => {
  for (const url of ["http://user:password@localhost:8080", "file:///tmp/proxy", "http://localhost:8080/path", "http://localhost:8080?q=secret"]) {
    const value = config(); value.nodes[0].url = url; assert.throws(() => validateProxyConfig(value));
  }
  const value = config(); value.model = { mode: "fixed", nodeId: "a" }; value.nodes[0].enabled = false;
  assert.throws(() => validateProxyConfig(value), /已启用/);
  value.model.mode = "system"; value.tools.mode = "round-robin"; value.nodes = [node("socks", "socks5://localhost:1080")];
  assert.throws(() => validateProxyConfig(value), /HTTP/);
});
test("storage failure retains the active policy, corrupted saved configuration blocks traffic", () => {
  const pool = new ProxyPool({ getItem: () => null, setItem: () => { throw new Error("Storage full"); } });
  assert.throws(() => pool.save(config()), /Storage full/);
  assert.equal(pool.routes("model")[0].mode, "system");
  const broken = new ProxyPool({ getItem: () => "broken", setItem: () => {} });
  assert.throws(() => broken.routes("model"), /重新保存/);
  broken.save(defaultProxyConfig());
  assert.equal(broken.routes("model")[0].mode, "system");
});

test("proxy pools accept more than one hundred configured nodes", () => {
  const value = config();
  value.nodes = Array.from({ length: 128 }, (_, index) => node(`proxy-${index}`));
  const pool = new ProxyPool(); pool.save(value);
  assert.equal(pool.routes("model").length, 128);
});

test("old requests cannot mark an edited or removed proxy unhealthy", () => {
  const pool = new ProxyPool(); pool.save(config());
  const old = pool.routes("model")[0].node!;
  const edited = config(); edited.nodes[0].password = "new-password"; edited.nodes[0].username = "test-user";
  pool.save(edited);
  pool.observe(old.id, { state: "failed", checkedAt: Date.now() }, old);
  assert.equal(pool.getSnapshot().health[old.id], undefined);
  const current = pool.routes("model")[0].node!;
  pool.observe(current.id, { state: "healthy", checkedAt: Date.now() }, current);
  assert.equal(pool.getSnapshot().health[current.id].state, "healthy");
  pool.save({ ...edited, nodes: [edited.nodes[1]] });
  pool.observe(current.id, { state: "failed", checkedAt: Date.now() }, current);
  assert.equal(pool.getSnapshot().health[current.id], undefined);
});

test("adding, editing, disabling, re-enabling and removing nodes survives reload", () => {
  let saved = "";
  const storage = { getItem: () => saved || null, setItem: (_: string, value: string) => { saved = value; } };
  const pool = new ProxyPool(storage);
  const added = { ...defaultProxyConfig(), nodes: [node("first")] };
  pool.save(added);
  const edited = structuredClone(pool.getSnapshot().config);
  edited.nodes[0] = { ...edited.nodes[0], name: " Work proxy ", url: " https://localhost:8443/ ", username: "fixture-user", password: "fixture-password" };
  edited.model = { mode: "fixed", nodeId: "first" };
  pool.save(edited);
  const restored = new ProxyPool(storage);
  assert.deepEqual(restored.routes("model")[0].node, { ...edited.nodes[0], name: "Work proxy", url: "https://localhost:8443" });

  const disabled = structuredClone(restored.getSnapshot().config);
  disabled.nodes[0].enabled = false;
  assert.throws(() => restored.save(disabled), /已启用/);
  assert.equal(restored.routes("model")[0].node?.enabled, true, "an invalid edit must not silently change the active route");
  disabled.model = { mode: "system", nodeId: "" };
  restored.save(disabled);
  assert.equal(new ProxyPool(storage).getSnapshot().config.nodes[0].enabled, false);
  disabled.nodes[0].enabled = true;
  disabled.model = { mode: "fixed", nodeId: "first" };
  restored.save(disabled);
  assert.equal(new ProxyPool(storage).routes("model")[0].node?.id, "first");
  restored.save(defaultProxyConfig());
  assert.deepEqual(new ProxyPool(storage).getSnapshot().config.nodes, []);
});

test("node editor validates credentials and SOCKS ports before closing", () => {
  assert.throws(() => validateProxyNode(node("socks", "socks5h://localhost")), /端口/);
  assert.throws(() => validateProxyNode({ ...node("auth"), password: "fixture-password" }), /用户名/);
  assert.throws(() => validateProxyNode({ ...node("long"), name: "a".repeat(81) }), /80/);
  assert.equal(validateProxyNode({ ...node("auth"), username: "fixture-user", password: "fixture-password" }).password, "fixture-password");
});
