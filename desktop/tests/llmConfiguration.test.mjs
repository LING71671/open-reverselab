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
