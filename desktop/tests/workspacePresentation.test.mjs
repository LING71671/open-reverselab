import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(new URL("../src/state/harness/workspacePresentation.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
const moduleUrl = `data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`;
const { readWorkspaceDrafts, saveWorkspaceDrafts, readWorkspaceSelection, saveWorkspaceSelection } = await import(moduleUrl);
const drafts = {
  "new:red": { target: "fixture-red.txt", prompt: "红队草稿\n逐条核对证据。", instruction: "保留追加要求", minutes: "", tokens: "", limitsOpen: false },
  "goal-blue": { target: "fixture-blue.txt", prompt: "蓝队草稿", instruction: "尚未发送的补充要求", minutes: "1.5", tokens: "", limitsOpen: true },
};
const storage = () => {
  const values = new Map();
  return { values, getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
};

test("drafts and selected goals survive workspace remount and cold reload without mixing tracks", async () => {
  const saved = storage();
  const sessions = [{ id: "goal-blue", track: "blue" }, { id: "goal-both", track: "both" }];
  saveWorkspaceDrafts("workspace-a", drafts, saved);
  saveWorkspaceSelection("workspace-a", { track: "both", byTrack: { blue: "goal-blue", both: "goal-both" } }, saved);
  saveWorkspaceDrafts("workspace-b", { "goal-blue": { ...drafts["goal-blue"], prompt: "另一个工作区" } }, saved);
  assert.deepEqual(readWorkspaceDrafts("workspace-a", saved), drafts);
  assert.equal(readWorkspaceDrafts("workspace-b", saved)["goal-blue"].prompt, "另一个工作区");
  // A new module instance has no in-memory fallback, like reloading the app.
  const restored = await import(`${moduleUrl}#cold-reload`);
  assert.deepEqual(restored.readWorkspaceDrafts("workspace-a", saved), drafts);
  assert.deepEqual(restored.readWorkspaceSelection("workspace-a", sessions, "red", saved), { track: "both", byTrack: { blue: "goal-blue", both: "goal-both" } });
});

test("deleted and foreign-track selections cannot resurrect unrelated goals", () => {
  const saved = storage();
  saveWorkspaceSelection("deleted-goals", { track: "red", byTrack: { red: "removed", blue: "red-goal", both: "both-goal" } }, saved);
  const actual = readWorkspaceSelection("deleted-goals", [{ id: "red-goal", track: "red" }, { id: "both-goal", track: "both" }], "blue", saved);
  assert.deepEqual(actual, { track: "red", byTrack: { both: "both-goal" } });
});

test("unavailable or full storage preserves the latest drafts during workspace switching", () => {
  const blocked = { getItem: () => { throw new Error("disabled"); }, setItem: () => { throw new Error("quota"); } };
  saveWorkspaceDrafts("blocked-storage", drafts, blocked);
  assert.deepEqual(readWorkspaceDrafts("blocked-storage", blocked), drafts);
  const full = { getItem: () => JSON.stringify({ old: drafts["new:red"] }), setItem: blocked.setItem };
  saveWorkspaceDrafts("full-storage", drafts, full);
  assert.deepEqual(readWorkspaceDrafts("full-storage", full), drafts);
});

test("malformed saved state is ignored while valid Unicode drafts have no artificial size limit", () => {
  const malformed = { getItem: () => "{", setItem() {} };
  assert.deepEqual(readWorkspaceDrafts("malformed", malformed), {});
  assert.deepEqual(readWorkspaceSelection("malformed", [], "red", malformed), { track: "red", byTrack: {} });
  const partial = { getItem: () => JSON.stringify({ valid: drafts["new:red"], broken: { target: 2 } }), setItem() {} };
  assert.deepEqual(readWorkspaceDrafts("partial", partial), { valid: drafts["new:red"] });
  const saved = storage();
  const long = { ...drafts["new:red"], prompt: "中英混合 🌐\n".repeat(20_000) };
  saveWorkspaceDrafts("long-draft", { long }, saved);
  assert.equal(readWorkspaceDrafts("long-draft", saved).long.prompt, long.prompt);
  saveWorkspaceDrafts("long-draft", {}, saved);
  assert.deepEqual(readWorkspaceDrafts("long-draft", saved), {});
});
