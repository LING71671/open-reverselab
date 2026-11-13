import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

test("the real SDK sends only diagnostic fields and cancels transport when disabled", async t => {
  const directory = await mkdtemp(path.join(tmpdir(), "reverselab-telemetry-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const windowDescriptor = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { value: new EventTarget(), configurable: true });
  t.after(() => windowDescriptor ? Object.defineProperty(globalThis, "window", windowDescriptor) : delete globalThis.window);
  const requests = [];
  let hold = false;
  t.mock.method(globalThis, "fetch", async (url, init) => {
    requests.push({ url, ...init });
    if (hold) await new Promise((_, reject) => {
      if (init.signal.aborted) reject(init.signal.reason);
      else init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
    });
    return new Response("{}", { status: 200 });
  });

  const modules = {
    health: "../src/core/contracts/health.ts",
    telemetryStore: "../src/services/telemetry/telemetryStore.ts",
    sanitize: "../src/services/telemetry/sanitize.ts",
    sentryService: "../src/services/telemetry/sentryService.ts",
  };
  for (const [name, file] of Object.entries(modules)) {
    const source = await readFile(new URL(file, import.meta.url), "utf8");
    const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText
      .replaceAll('"../../core/contracts/health.ts"', '"./health.mjs"')
      .replaceAll('"./telemetryStore"', '"./telemetryStore.mjs"')
      .replaceAll('"./sanitize"', '"./sanitize.mjs"')
      .replaceAll('"@sentry/react"', JSON.stringify(import.meta.resolve("@sentry/react")))
      .replace('import packageInfo from "../../../package.json";', 'const packageInfo = { name: "desktop", version: "test" };')
      .replace('import diagnosticsConfig from "../../../diagnostics.config.json";', 'const diagnosticsConfig = { remote: { enabled: false, traceSampleRate: 1 } };')
      .replaceAll("import.meta.env.VITE_SENTRY_DSN", '"https://fixture@example.test/1"')
      .replaceAll("import.meta.env.MODE", '"test"');
    await writeFile(path.join(directory, `${name}.mjs`), compiled);
  }
  const { telemetryPreference, reportHealth } = await import(pathToFileURL(path.join(directory, "telemetryStore.mjs")));
  const { captureUiError, startRemoteDiagnostics } = await import(pathToFileURL(path.join(directory, "sentryService.mjs")));
  const sentry = await import("@sentry/react");
  const tick = () => new Promise(resolve => setImmediate(resolve));
  const until = async predicate => {
    for (let i = 0; i < 100 && !predicate(); i++) await new Promise(resolve => setTimeout(resolve, 10));
    assert.ok(predicate(), "diagnostic operation did not settle");
  };
  const stop = startRemoteDiagnostics();
  t.after(stop);
  captureUiError(new Error("PRIVATE_BEFORE_ENABLE"));
  await tick(); assert.equal(requests.length, 0);
  telemetryPreference.set({ enabled: true, traceSampleRate: 1 });
  await until(() => Boolean(sentry.getClient()?.getOptions().enabled !== false && sentry.getClient()));
  sentry.setUser({ id: "PRIVATE_USER", email: "PRIVATE_EMAIL" });
  sentry.setContext("target", { path: "PRIVATE_PATH" });
  sentry.setExtra("prompt", "PRIVATE_PROMPT");
  captureUiError(new Error("PRIVATE_ERROR_TEXT"));
  const event = { eventId: "PRIVATE_EVENT_ID", goalId: "PRIVATE_GOAL_ID", layer: "tool", status: "failed", timestamp: 1, code: "TOOL_FAILED", durationMs: 40, detail: "PRIVATE_SCRIPT" };
  reportHealth(event);
  await sentry.flush(2000);
  assert.ok(requests.length >= 2);
  const payloads = requests.map(request => String(request.body));
  assert.ok(payloads.some(body => body.includes("UI_UNHANDLED")));
  assert.ok(payloads.some(body => body.includes("TOOL_FAILED")));
  assert.ok(payloads.some(body => body.includes("operation.tool")));
  assert.ok(payloads.every(body => !body.includes("PRIVATE_")), "SDK envelope leaked application data");
  for (const body of payloads) {
    const event = JSON.parse(body.split("\n")[2]);
    assert.equal(event.sdk?.settings?.infer_ip, "never", "the server must not infer a user IP");
    assert.deepEqual(event.user, { geo: {} }, "the server must not enrich the user's location");
  }
  assert.ok(requests.every(request => request.signal instanceof AbortSignal));

  hold = true;
  const before = requests.length;
  captureUiError(new TypeError("PRIVATE_IN_FLIGHT"));
  await until(() => requests.length > before);
  const active = requests.at(-1);
  telemetryPreference.set({ enabled: false, traceSampleRate: 1 });
  assert.equal(active.signal.aborted, true);
  captureUiError(new Error("PRIVATE_AFTER_DISABLE")); reportHealth(event);
  await tick(); await sentry.flush(2000);
  assert.equal(requests.length, before + 1);

  // A rapid enable/disable must not let the asynchronous SDK import reopen collection.
  telemetryPreference.set({ enabled: true, traceSampleRate: 1 });
  telemetryPreference.set({ enabled: false, traceSampleRate: 1 });
  await tick(); captureUiError(new Error("PRIVATE_AFTER_RACE")); reportHealth(event);
  await tick(); assert.equal(requests.length, before + 1);
  sentry.setUser(null); sentry.setContext("target", null); sentry.setExtra("prompt", undefined);
});
