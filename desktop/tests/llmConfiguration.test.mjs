import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(new URL("../src/services/llm/llmService.ts", import.meta.url), "utf8");
let importId = 0;
async function load(t, env = {}, saved = []) {
  const values = new Map(saved);
  const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
  } });
  t.after(() => original ? Object.defineProperty(globalThis, "localStorage", original) : delete globalThis.localStorage);
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText
    .replace(/import .* from "\.\.\/network\/networkService";/, `
      export const requests = [];
      const usesNativeNetwork = () => false;
      const modelFetch = async (url, init) => { requests.push({ url, ...init }); return new Response(JSON.stringify({ data: [{ id: "fixture-model" }], choices: [{ message: { content: "ok" } }] })); };
    `)
    .replaceAll("import.meta.env", JSON.stringify(env));
  const module = await import(`data:text/javascript;base64,${Buffer.from(compiled + `\n//${++importId}`).toString("base64")}`);
  return { ...module, values };
}

test("unconfigured installs do not invent a model or send a request", async t => {
  const { llmService, requests, values } = await load(t);
  assert.equal(llmService.getModel(), "");
  assert.equal(values.has("reverselab_model"), false);
  assert.deepEqual(llmService.getProviders(), []);
  assert.equal((await llmService.checkHealth()).ok, false);
  await assert.rejects(llmService.complete([{ role: "user", content: "fixture" }]), /模型 ID/);
  assert.equal(requests.length, 0);
});

test("explicit model configuration is respected without sharing provider credentials", async t => {
  const { llmService, requests } = await load(t, {
    VITE_LLM_BASE_URL: "https://env.example.test/v1", VITE_LLM_MODEL: "env-model", VITE_LLM_API_KEY: "fixture-env-key",
  });
  assert.equal(llmService.getModel(), "env-model");
  assert.equal(llmService.getApiKey(), "fixture-env-key");
  llmService.addProvider({ id: "local", name: "Local", baseUrl: "http://localhost:1234/v1" });
  assert.equal(llmService.getApiKey(), "");
  await llmService.fetchModels();
  assert.equal(requests.at(-1).headers.Authorization, undefined);
  llmService.setActiveProviderId("env-provider");
  await llmService.fetchModels("local");
  assert.equal(requests.at(-1).headers.Authorization, undefined);
  await llmService.complete([{ role: "user", content: "fixture" }], { provider: { id: "local", name: "Local", baseUrl: "http://localhost:1234/v1" } });
  assert.equal(requests.at(-1).headers.Authorization, "Bearer ");
  assert.ok(!JSON.stringify(requests).includes("fixture-env-key"));
});

test("a saved model takes precedence over build environment configuration", async t => {
  const { llmService } = await load(t, { VITE_LLM_MODEL: "env-model" }, [["reverselab_model", "saved-model"]]);
  assert.equal(llmService.getModel(), "saved-model");
});

test("model catalogs are shared with the composer but isolated by provider, endpoint and credentials", async t => {
  const { llmService, requests, values } = await load(t);
  llmService.addProvider({ id: "first", name: "First", baseUrl: "https://first.example.test/v1", apiKey: "fixture-key" });
  assert.deepEqual(llmService.getCachedModels(), []);
  await llmService.fetchModels();
  assert.deepEqual(llmService.getCachedModels(), ["fixture-model"]);
  llmService.getCachedModels().push("must-not-mutate-cache");
  assert.deepEqual(llmService.getCachedModels(), ["fixture-model"]);
  llmService.setModel("fixture-model");
  assert.equal(values.get("reverselab_model"), "fixture-model");
  assert.equal(requests.length, 1, "choosing a cached model does not send a completion");
  llmService.addProvider({ id: "second", name: "Second", baseUrl: "https://second.example.test/v1" });
  assert.deepEqual(llmService.getCachedModels(), []);
  llmService.setActiveProviderId("first");
  assert.deepEqual(llmService.getCachedModels(), ["fixture-model"]);
  llmService.setBaseUrl("https://changed.example.test/v1");
  assert.deepEqual(llmService.getCachedModels(), []);
  await llmService.fetchModels();
  llmService.setApiKey("changed-fixture-key");
  assert.deepEqual(llmService.getCachedModels(), []);
  await llmService.fetchModels();
  llmService.removeProvider("first");
  llmService.addProvider({ id: "first", name: "First", baseUrl: "https://changed.example.test/v1", apiKey: "changed-fixture-key" });
  assert.deepEqual(llmService.getCachedModels(), []);
});

test("editing, testing and syncing a different provider preserves the active model across reloads", async t => {
  const initial = [{ id: "first", name: "First", baseUrl: "https://first.example.test/v1" }];
  const { llmService, LlmService, requests } = await load(t, {}, [
    ["reverselab_providers", JSON.stringify(initial)], ["reverselab_model", "old-model"],
  ]);
  const second = { id: "second", name: "Second", baseUrl: "https://second.example.test/v1", apiKey: "fixture-second", model: "second-model" };
  llmService.addProvider(second, false);
  llmService.addProvider({ ...second, model: "" }, false);
  assert.equal((await llmService.checkHealth(second.id)).ok, true);
  assert.equal(requests.at(-1).method, "GET");
  assert.equal(requests.at(-1).url, second.baseUrl + "/models");
  llmService.addProvider(second, false);
  await llmService.fetchModels(second.id);
  assert.equal((await llmService.checkHealth(second.id)).ok, true);
  assert.equal(requests.at(-1).url, second.baseUrl + "/chat/completions");
  assert.equal(requests.at(-1).headers.Authorization, "Bearer fixture-second");
  assert.equal(JSON.parse(requests.at(-1).body).model, "second-model");
  const restored = new LlmService();
  assert.equal(restored.getActiveProviderId(), "first");
  assert.equal(restored.getModel(), "old-model");
  restored.setActiveProviderId(second.id);
  assert.equal(restored.getModel(), second.model);
  assert.deepEqual(restored.getCachedModels(), ["fixture-model"]);
  restored.setModel("fixture-model");
  restored.setActiveProviderId("first");
  assert.equal(restored.getModel(), "old-model");
  assert.equal(restored.getModel(second.id), "fixture-model");
});

test("a model catalog response is discarded when the provider credentials changed during sync", async t => {
  const { llmService } = await load(t);
  llmService.addProvider({ id: "first", name: "First", baseUrl: "https://first.example.test/v1" });
  const inFlight = llmService.fetchModels();
  llmService.setApiKey("changed-fixture-key");
  assert.deepEqual(await inFlight, []);
  assert.deepEqual(llmService.getCachedModels(), []);
});

test("evidence fallback requires a saved, explicitly selected alternative and uses its own model", async t => {
  const { llmService, LlmService, requests } = await load(t, { DEV: true });
  const first = { id: "first", name: "First", baseUrl: "https://first.example.test/v1", model: "first-model", apiKey: "fixture-first" };
  const second = { id: "second", name: "Second", baseUrl: "https://second.example.test/tokenrhythm.studio/v1", model: "second-model" };
  llmService.addProvider(first);
  llmService.addProvider(second, false);
  assert.equal(llmService.getEvidenceFallbackProviderId(), "");
  assert.throws(() => llmService.setEvidenceFallbackProviderId(first.id));
  assert.throws(() => llmService.setEvidenceFallbackProviderId("missing"));
  llmService.setEvidenceFallbackProviderId(second.id);
  const restored = new LlmService();
  assert.equal(restored.getEvidenceFallbackProviderId(), second.id);
  assert.equal(restored.getActiveProviderId(), first.id);
  const messages = [{ role: "user", content: "fixture" }];
  await restored.complete(messages, { providerId: second.id, model: first.model });
  assert.equal(requests.at(-1).url, second.baseUrl + "/chat/completions");
  assert.equal(requests.at(-1).headers.Authorization, "Bearer ");
  assert.equal(JSON.parse(requests.at(-1).body).model, second.model);
  restored.setActiveProviderId(second.id);
  assert.equal(restored.getEvidenceFallbackProviderId(), "");
  restored.setActiveProviderId(first.id);
  assert.equal(restored.getEvidenceFallbackProviderId(), "");
  restored.setEvidenceFallbackProviderId(second.id);
  restored.removeProvider(second.id);
  assert.equal(restored.getEvidenceFallbackProviderId(), "");
  await assert.rejects(restored.complete(messages, { providerId: second.id }), /不存在/);
  await assert.rejects(restored.complete(messages, { providerId: "" }), /不存在/);
  assert.equal(requests.length, 1);
});
