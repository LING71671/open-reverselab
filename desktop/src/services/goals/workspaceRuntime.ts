import type { Workspace } from "../../core/contracts/workspace";
import { GoalManager, type GoalSnapshot } from "./goalManager";
import { nativeBridge } from "../native/nativeBridge";
import { runOpenSourceAgent } from "../../engine/openSourceAgent";
import { reportHealth } from "../telemetry/telemetryStore";

export interface WorkspaceRuntime { workspace: Workspace; manager: GoalManager; waitForWrites: () => Promise<void> }
const runtimes = new Map<string, WorkspaceRuntime>();
const pending = new Map<string, Promise<WorkspaceRuntime>>();
const workloadListeners = new Set<() => void>();
export const subscribeWorkload = (listener: () => void) => { workloadListeners.add(listener); return () => { workloadListeners.delete(listener); }; };
export const getWorkloadCount = () => [...runtimes.values()].reduce((count, { manager }) => count + manager.getSnapshot().sessions.filter(session => session.status === "running" || session.status === "queued").length, 0);

/** Managers stay alive when their workspace is not visible. Disk writes are serialized. */
export function loadWorkspaceRuntime(workspace: Workspace): Promise<WorkspaceRuntime> {
  const key = workspace.root;
  if (runtimes.has(key)) return Promise.resolve(runtimes.get(key)!);
  if (pending.has(key)) return pending.get(key)!;
  const loading = (async () => {
    const saved = await nativeBridge.workspace<GoalSnapshot | null>({ action: "load", root: workspace.root });
    let cache = saved ? JSON.stringify(saved) : "";
    let writes = Promise.resolve();
    const manager = new GoalManager((goal, callbacks, signal) => runOpenSourceAgent(goal.target, goal.objective, goal.history || [], callbacks, signal, goal.track, goal.budget, goal.id, workspace.root, goal.revision), {
      getItem: key => {
        if (key === "reverselab_goals_v2") return cache || null;
        if (!saved && workspace.name === "默认工作区") { try { return localStorage.getItem(key); } catch { return null; } }
        return null;
      },
      setItem: (_key, value) => {
        if (value === cache) return writes;
        cache = value;
        const snapshot = JSON.parse(value);
        writes = writes.catch(() => {}).then(async () => {
          try { await nativeBridge.workspace({ action: "save", root: workspace.root, snapshot }); }
          catch (error) { if (cache === value) cache = ""; throw error; }
        });
        return writes;
      },
      removeItem: () => {},
    });
    const runtime = { workspace, manager, waitForWrites: () => writes };
    manager.subscribeHealth(reportHealth);
    runtimes.set(key, runtime);
    manager.subscribe(() => workloadListeners.forEach(listener => listener()));
    workloadListeners.forEach(listener => listener());
    return runtime;
  })();
  pending.set(key, loading);
  void loading.finally(() => pending.delete(key)).catch(() => {});
  return loading;
}

export function flushWorkspaces() { for (const { manager } of runtimes.values()) manager.flush(); }

/** Await disk persistence before an application update is allowed to exit. */
export async function persistWorkspacesForUpdate() {
  await Promise.all(pending.values());
  flushWorkspaces();
  await Promise.all([...runtimes.values()].map(runtime => runtime.waitForWrites()));
  for (const { manager } of runtimes.values()) {
    const error = manager.getSnapshot().persistenceError;
    if (error) throw new Error(error);
  }
}
