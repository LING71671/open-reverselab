import assert from "node:assert/strict";
import { test, after } from "node:test";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

const temporary = await mkdtemp(path.join(tmpdir(), "reverselab-performance-test-"));
const transpile = source => ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
await writeFile(path.join(temporary, "diagnostics.config.json"), await readFile(new URL("../diagnostics.config.json", import.meta.url)));
for (const name of ["diagnosticPolicy", "performanceMonitor", "performanceStore"]) {
  const source = transpile(await readFile(new URL(`../src/services/performance/${name}.ts`, import.meta.url), "utf8"))
    .replaceAll('"../../../diagnostics.config.json"', '"./diagnostics.config.json"')
    .replaceAll('"./diagnosticPolicy"', '"./diagnosticPolicy.mjs"')
    .replaceAll('"@tauri-apps/api/core"', JSON.stringify(import.meta.resolve("@tauri-apps/api/core")));
  await writeFile(path.join(temporary, `${name}.mjs`), source);
}
const { createPerformanceMonitor } = await import(pathToFileURL(path.join(temporary, "performanceMonitor.mjs")).href);
after(async () => { await rm(temporary, { recursive: true, force: true }); });

const policy = { sampleMs: 2000, sustainedMs: 15000, cpuPercent: 90, memoryBytes: 100, maxFrameGapMs: 250 };
const healthy = { cpuPercent: 20, memoryBytes: 10 };
const flush = () => new Promise(resolve => setImmediate(resolve));
function clock() {
  let now = 0, hidden = false, sequence = 0;
  const timers = new Map(), frames = new Map(), listeners = new Set();
  const environment = {
    now: () => now, hidden: () => hidden,
    schedule(callback, delay) { const id = sequence++; timers.set(id, { callback, at: now + delay }); return id; },
    cancelTimer: id => timers.delete(id),
    requestFrame(callback) { const id = sequence++; frames.set(id, callback); return id; },
    cancelFrame: id => frames.delete(id),
    onVisibilityChange(callback) { listeners.add(callback); return () => listeners.delete(callback); },
  };
  return {
    environment, timers, frames, listeners,
    async advance(duration) {
      const end = now + duration;
      for (;;) {
        const next = [...timers.entries()].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        now = next[1].at;
        timers.delete(next[0]); next[1].callback(); await flush();
      }
      now = end;
    },
    frame() { for (const [id, callback] of [...frames.entries()]) { frames.delete(id); callback(now); } },
    visibility(value) { hidden = value; for (const listener of listeners) listener(); },
  };
}

test("healthy monitoring stays quiet and disabling releases all scheduled work", async () => {
  const time = clock(), warnings = [];
  let samples = 0, stops = 0;
  const monitor = createPerformanceMonitor({ sample: async () => { samples++; return healthy; }, stop: async () => { stops++; } }, time.environment, policy);
  await time.advance(20000);
  assert.equal(samples, 0, "constructing the default-disabled monitor must not collect data");
  const session = monitor.start(warning => warnings.push(warning));
  await flush(); await time.advance(20000);
  assert.equal(samples, 11);
  assert.ok(warnings.every(warning => warning === null));
  await session.stop(); await session.stop();
  assert.equal(stops, 1);
  assert.equal(time.timers.size, 0); assert.equal(time.frames.size, 0); assert.equal(time.listeners.size, 0);
  await time.advance(20000); time.visibility(true); time.visibility(false);
  assert.equal(samples, 11);
});

test("a late sample cannot revive a stopped session or overtake its replacement", async () => {
  const time = clock(), calls = [], oldWarnings = [], newWarnings = [];
  let release;
  const monitor = createPerformanceMonitor({
    sample: () => { calls.push("sample"); return calls.length === 1 ? new Promise(resolve => { release = resolve; }) : Promise.resolve(healthy); },
    stop: async () => { calls.push("stop"); },
  }, time.environment, policy);
  const old = monitor.start(warning => oldWarnings.push(warning));
  await flush();
  const stopped = old.stop();
  const next = monitor.start(warning => newWarnings.push(warning));
  await flush();
  assert.deepEqual(calls, ["sample"]);
  release({ cpuPercent: 100, memoryBytes: 1000 });
  await stopped; await flush();
  assert.deepEqual(calls, ["sample", "stop", "sample"]);
  assert.deepEqual(oldWarnings, [null]);
  assert.ok(newWarnings.every(warning => warning === null));
  assert.equal(time.timers.size, 1); assert.equal(time.frames.size, 1);
  await next.stop();
});

test("hide and resume serialize native cleanup and discard an in-flight reading", async () => {
  const time = clock(), calls = [], warnings = [];
  let release;
  const monitor = createPerformanceMonitor({
    sample: () => { calls.push("sample"); return calls.length === 1 ? new Promise(resolve => { release = resolve; }) : Promise.resolve(healthy); },
    stop: async () => { calls.push("stop"); },
  }, time.environment, policy);
  const session = monitor.start(warning => warnings.push(warning));
  await flush(); time.visibility(true);
  assert.equal(time.timers.size, 0); assert.equal(time.frames.size, 0);
  await time.advance(60000); time.visibility(false); await flush();
  assert.deepEqual(calls, ["sample"]);
  release({ cpuPercent: 100, memoryBytes: 1000 }); await flush();
  assert.deepEqual(calls, ["sample", "stop", "sample"]);
  assert.ok(warnings.every(warning => warning === null));
  time.visibility(true); await flush();
  const count = calls.length; await time.advance(60000);
  assert.equal(calls.length, count);
  time.visibility(false); await flush();
  assert.equal(calls.at(-1), "sample");
  await session.stop();
});

test("failed readings break sustained load evidence and do not undo a dismissal", async () => {
  const time = clock(), warnings = [];
  let result = { cpuPercent: 95, memoryBytes: 10 }, missing = false;
  const monitor = createPerformanceMonitor({
    sample: async () => { if (missing) throw new Error("sample unavailable"); return result; }, stop: async () => {},
  }, time.environment, policy);
  const session = monitor.start(warning => warnings.push(warning));
  await flush(); await time.advance(14000); assert.equal(warnings.at(-1), null);
  missing = true; await time.advance(2000);
  missing = false; await time.advance(2000); assert.equal(warnings.at(-1), null);
  await time.advance(14000); assert.equal(warnings.at(-1), null);
  await time.advance(2000); assert.equal(warnings.at(-1), "cpu");
  session.dismiss("cpu"); assert.equal(warnings.at(-1), null);
  missing = true; await time.advance(2000);
  missing = false; await time.advance(20000); assert.equal(warnings.at(-1), null);
  result = healthy; await time.advance(2000);
  result = { cpuPercent: 95, memoryBytes: 10 }; await time.advance(18000);
  assert.equal(warnings.at(-1), "cpu");
  time.visibility(true); time.visibility(false); await flush();
  assert.equal(warnings.at(-1), null, "resuming begins a fresh observation period");
  await session.stop();
});

test("sustained memory and frame delays alert without displaying raw measurements", async () => {
  const time = clock(), warnings = [];
  let result = { cpuPercent: 95, memoryBytes: 110 };
  const monitor = createPerformanceMonitor({ sample: async () => result, stop: async () => {} }, time.environment, policy);
  const session = monitor.start(warning => warnings.push(warning));
  await flush(); await time.advance(16000);
  assert.equal(warnings.at(-1), "memory");
  result = healthy;
  for (let i = 0; i < 10; i++) { time.frame(); await time.advance(2000); }
  assert.equal(warnings.at(-1), "unresponsive");
  assert.ok(warnings.every(warning => warning === null || ["cpu", "memory", "unresponsive"].includes(warning)));
  await session.stop();
});

test("a start disabled before dispatch never creates a native sampler", async () => {
  const time = clock(); let samples = 0, stops = 0;
  const monitor = createPerformanceMonitor({ sample: async () => { samples++; return healthy; }, stop: async () => { stops++; } }, time.environment, policy);
  const session = monitor.start(() => {});
  await session.stop();
  assert.equal(samples, 0); assert.equal(stops, 1);
  assert.equal(time.timers.size, 0); assert.equal(time.frames.size, 0);
});

test("the local preference defaults off, persists toggles, and tolerates unavailable storage", async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const values = new Map();
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) } });
  const location = pathToFileURL(path.join(temporary, "performanceStore.mjs")).href;
  try {
    const { performancePreference: preference } = await import(location);
    assert.equal(preference.getSnapshot(), false);
    let changes = 0;
    const unsubscribe = preference.subscribe(() => { changes++; });
    preference.setEnabled(true);
    assert.equal(preference.getSnapshot(), true); assert.equal(changes, 1);
    const restored = (await import(`${location}?restored`)).performancePreference;
    assert.equal(restored.getSnapshot(), true);
    unsubscribe(); preference.setEnabled(false); assert.equal(changes, 1);
    Object.defineProperty(globalThis, "localStorage", { configurable: true, get() { throw new Error("storage unavailable"); } });
    const sessionOnly = (await import(`${location}?no-storage`)).performancePreference;
    assert.equal(sessionOnly.getSnapshot(), false); sessionOnly.setEnabled(true);
    assert.equal(sessionOnly.getSnapshot(), true);
  } finally {
    if (original) Object.defineProperty(globalThis, "localStorage", original); else delete globalThis.localStorage;
  }
});
