import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { EventEmitter } from "node:events";
import { loadConfigFromFile } from "vite";

const temporary = await mkdtemp(path.join(tmpdir(), "reverselab-utf8-test-"));
const previousData = process.env.REVERSELAB_DATA_DIR;
process.env.REVERSELAB_DATA_DIR = path.join(temporary, "registry");
const loaded = await loadConfigFromFile({ command: "serve", mode: "test" }, path.resolve(import.meta.dirname, "../vite.config.ts"));
const plugin = loaded.config.plugins.flat().find(item => item?.name === "reverselab-native-backend");
const routes = new Map();
plugin.configureServer({ middlewares: { use: (route, handler) => routes.set(route, handler) } });
after(async () => {
  if (previousData === undefined) delete process.env.REVERSELAB_DATA_DIR;
  else process.env.REVERSELAB_DATA_DIR = previousData;
  assert.ok(path.resolve(temporary).startsWith(path.resolve(tmpdir()) + path.sep));
  await rm(temporary, { recursive: true, force: true });
});

function request(route, payload, chunkSize = 1) {
  return new Promise((resolve, reject) => {
    const req = new PassThrough();
    req.method = "POST";
    const res = new EventEmitter();
    res.setHeader = () => {};
    res.end = body => { res.writableEnded = true; try { resolve({ status: res.statusCode || 200, body: JSON.parse(body) }); } catch (error) { reject(error); } };
    req.on("error", reject);
    routes.get(route)(req, res, () => reject(new Error("Route not handled")));
    const bytes = Buffer.from(JSON.stringify(payload), "utf8");
    // PassThrough preserves these chunk boundaries, including inside Unicode code points.
    for (let offset = 0; offset < bytes.length; offset += chunkSize) req.write(bytes.subarray(offset, offset + chunkSize));
    req.end();
  });
}

test("workspace save and load preserve Chinese and supplementary Unicode across byte boundaries", async () => {
  const root = path.join(temporary, "workspace");
  assert.equal((await request("/api/workspace", { action: "create", root })).status, 200);
  const content = "从真实目标计算 SHA256 并与 triage 比对。交叉验证 𠮷 🧪";
  const snapshot = { sessions: [{ id: "utf8", title: content }], records: { utf8: { messages: [{ content }], deliverables: { assertions: [{ name: content }] } } } };
  for (const chunkSize of [1, 2, 3, 7, 65536]) {
    assert.equal((await request("/api/workspace", { action: "save", root, snapshot }, chunkSize)).status, 200);
    const loaded = await request("/api/workspace", { action: "load", root });
    assert.equal(loaded.status, 200);
    assert.deepEqual(loaded.body, snapshot);
  }
});

test("Python receives the original Unicode script across byte boundaries", async () => {
  const content = "中文脚本 🧪 𠮷";
  const response = await request("/api/system/exec-python", { script: `print(${JSON.stringify(content)})` });
  assert.equal(response.status, 200);
  assert.equal(response.body.success, true);
  assert.equal(response.body.stdout.trim(), content);
});
