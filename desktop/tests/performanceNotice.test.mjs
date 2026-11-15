import assert from "node:assert/strict";
import { test, after } from "node:test";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";

const directory = await mkdtemp(path.join(tmpdir(), "reverselab-performance-notice-"));
after(() => rm(directory, { recursive: true, force: true }));
const source = await readFile(new URL("../src/views/shell/PerformanceMonitor.tsx", import.meta.url), "utf8");
let compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX } }).outputText;
for (const name of ["react", "react/jsx-runtime", "lucide-react", "@tauri-apps/api/core"]) compiled = compiled.replaceAll(`"${name}"`, JSON.stringify(import.meta.resolve(name)));
// The notice renders without enabling process sampling. Its monitor's separate
// tests exercise the real scheduling and native lifecycle adapter.
compiled = compiled.replace(/import \{ performancePreference \}[^;]+;/, "const performancePreference = {};")
  .replace(/import \{ performanceMonitor \}[^;]+;/, "const performanceMonitor = {};");
const file = path.join(directory, "PerformanceMonitor.mjs");
await writeFile(file, compiled);
const { PerformanceWarningNotice } = await import(pathToFileURL(file).href);

test("the real warning component renders a dismissible live notice only for an active condition", () => {
  const render = warning => renderToStaticMarkup(createElement(PerformanceWarningNotice, { warning, onDismiss() {} }));
  assert.equal(render(null), "", "normal performance must not occupy a status strip");
  for (const [warning, label] of [["cpu", "持续高负载"], ["memory", "内存占用持续偏高"], ["unresponsive", "持续响应缓慢"]]) {
    const html = render(warning);
    assert.match(html, /role="status"/);
    assert.match(html, new RegExp(label));
    assert.match(html, /<button[^>]+type="button"[^>]+aria-label="关闭此提醒"/);
    assert.doesNotMatch(html, /disabled=|role="alertdialog"|[0-9]+\s*(?:MiB|GiB|%)/);
  }
});
