import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { EventEmitter } from "node:events";
import { loadConfigFromFile } from "vite";
import { setTimeout as delay } from "node:timers/promises";

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
  return startRequest(route, payload, chunkSize).result;
}

function startRequest(route, payload, chunkSize = 1) {
  const req = new PassThrough();
  const res = new EventEmitter();
  const result = new Promise((resolve, reject) => {
    req.method = "POST";
    res.setHeader = () => {};
    res.end = body => { res.writableEnded = true; try { resolve({ status: res.statusCode || 200, body: JSON.parse(body) }); } catch (error) { reject(error); } };
    req.on("error", reject);
    routes.get(route)(req, res, () => reject(new Error("Route not handled")));
    const bytes = Buffer.from(JSON.stringify(payload), "utf8");
    // PassThrough preserves these chunk boundaries, including inside Unicode code points.
    for (let offset = 0; offset < bytes.length; offset += chunkSize) req.write(bytes.subarray(offset, offset + chunkSize));
    req.end();
  });
  return { result, cancel() { res.destroyed = true; res.emit("close"); } };
}

async function ready(path) {
  for (let attempt = 0; attempt < 200; attempt++) {
    try { return JSON.parse(await readFile(path, "utf8")); } catch {}
    await delay(25);
  }
  assert.fail("Python fixture did not become ready");
}

const waitingScript = (readyPath, releasePath) => `import json, os, time\nwith open(${JSON.stringify(readyPath)}, 'w') as output: json.dump(os.getpid(), output)\nwhile not os.path.exists(${JSON.stringify(releasePath)}): time.sleep(0.01)\nprint('completed')`;

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

test("unbounded real Python keeps running beyond old deadlines under a controlled clock", async t => {
  let now = 0;
  const timers = [];
  t.mock.method(performance, "now", () => now);
  t.mock.method(globalThis, "setTimeout", (callback, duration) => { const timer = { callback, duration }; timers.push(timer); return timer; });
  t.mock.method(globalThis, "clearTimeout", () => {});
  const readyPath = path.join(temporary, "unbounded-ready.json"), releasePath = path.join(temporary, "unbounded-release");
  const running = startRequest("/api/system/exec-python", { script: waitingScript(readyPath, releasePath) });
  try {
    const pid = await ready(readyPath);
    now = 120000;
    assert.equal(timers.length, 0, "an omitted budget must not schedule a deadline");
    assert.doesNotThrow(() => process.kill(pid, 0));
    await writeFile(releasePath, "done");
    const result = await running.result;
    assert.equal(result.body.success, true);
    assert.equal(result.body.stdout.trim(), "completed");
    assert.equal(result.body.durationMs, 120000);
    const target = path.join(temporary, "triage.txt");
    await writeFile(target, "observed");
    const triage = await request("/api/system/triage", { target, timeoutMs: null });
    assert.equal(triage.status, 200);
    assert.equal(triage.body.sizeBytes, 8);
    assert.equal(timers.length, 0);
  } finally { running.cancel(); }
});

test("explicit tool deadlines preserve durations above 60 seconds and avoid timer overflow", async t => {
  let now = 0;
  const timers = [];
  t.mock.method(performance, "now", () => now);
  t.mock.method(globalThis, "setTimeout", (callback, duration) => { const timer = { callback, duration }; timers.push(timer); return timer; });
  t.mock.method(globalThis, "clearTimeout", () => {});
  for (const timeoutMs of [120000, 2147483647 + 60000]) {
    now = 0;
    const readyPath = path.join(temporary, `bounded-${timeoutMs}.json`);
    const running = startRequest("/api/system/exec-python", { script: waitingScript(readyPath, path.join(temporary, "never-release")), timeoutMs });
    try {
      const pid = await ready(readyPath);
      assert.equal(timers.at(-1).duration, Math.min(timeoutMs, 2147483647));
      now = timeoutMs === 120000 ? 61000 : 2147483647;
      timers.at(-1).callback();
      assert.equal(timers.at(-1).duration, timeoutMs - now);
      assert.doesNotThrow(() => process.kill(pid, 0));
      now = timeoutMs;
      timers.at(-1).callback();
      const result = await running.result;
      assert.equal(result.body.success, false);
      assert.match(result.body.stderr, /time budget exhausted/);
      assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
    } finally { running.cancel(); }
  }
});

test("disconnecting an unbounded request terminates its real Python descendants", async () => {
  const readyPath = path.join(temporary, "tree-ready.json");
  const script = `import json, os, subprocess, sys, time\nchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\nwith open(${JSON.stringify(readyPath)}, 'w') as output: json.dump([os.getpid(), child.pid], output)\ntime.sleep(60)`;
  const running = startRequest("/api/system/exec-python", { script });
  try {
    const pids = await ready(readyPath);
    for (const pid of pids) assert.doesNotThrow(() => process.kill(pid, 0));
    running.cancel();
    for (let attempt = 0; attempt < 200; attempt++) {
      const alive = pids.filter(pid => { try { process.kill(pid, 0); return true; } catch { return false; } });
      if (!alive.length) return;
      await delay(25);
    }
    assert.fail("A cancelled Python descendant is still running");
  } finally { running.cancel(); }
});

test("already exhausted budgets do not execute scripts", async () => {
  const marker = path.join(temporary, "must-not-exist");
  const result = await request("/api/system/exec-python", { script: `open(${JSON.stringify(marker)}, 'w').write('unexpected')`, timeoutMs: 0 });
  assert.equal(result.status, 400);
  assert.match(result.body.error, /time budget exhausted/);
  await assert.rejects(readFile(marker), { code: "ENOENT" });
});
