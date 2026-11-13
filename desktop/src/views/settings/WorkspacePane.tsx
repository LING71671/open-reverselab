import { useEffect, useState } from "react";
import { Check, FolderOpen, Loader2 } from "lucide-react";
import { isTauri } from "@tauri-apps/api/core";
import type { Workspace } from "../../core/contracts/workspace";
import { nativeBridge } from "../../services/native/nativeBridge";
import { useHarness } from "../../state";

export function WorkspacePane({ active, onOpened }: { active: boolean; onOpened: () => void }) {
  const { workspace, openWorkspace } = useHarness();
  const [recent, setRecent] = useState<Workspace[]>([]);
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!active) return;
    let disposed = false;
    nativeBridge.workspace<Workspace[]>({ action: "list" }).then(items => { if (!disposed) setRecent(items); }).catch(err => { if (!disposed) setError(String(err)); });
    return () => { disposed = true; };
  }, [active, workspace.root]);
  const activate = async (action: "create" | "open", root = path) => {
    if (!root.trim() || busy) return;
    setBusy(true); setError("");
    try { await openWorkspace(await nativeBridge.workspace<Workspace>({ action, root: root.trim() })); setPath(""); onOpened(); }
    catch (err) { setError(String(err)); }
    finally { setBusy(false); }
  };
  return <section className="settings-fields workspace-pane" id="settings-workspace" role="tabpanel" aria-labelledby="settings-tab-workspace">
    <div className="recent-workspaces">{recent.map(item => <button key={item.root} disabled={busy} onClick={() => item.root === workspace.root ? onOpened() : void activate("open", item.root)} aria-current={item.root === workspace.root ? "true" : undefined}><FolderOpen size={18} /><span>{item.name}<small title={item.root}>{item.root}</small></span>{item.root === workspace.root && <Check size={16} aria-label="当前工作区" />}</button>)}</div>
    <form onSubmit={event => { event.preventDefault(); void activate("open"); }}>
      <label>打开或新建工作区<div className="workspace-path-input"><input value={path} onChange={event => setPath(event.target.value)} placeholder="工作区目录" aria-label="工作区路径" disabled={busy} />{isTauri() && <button type="button" className="icon-button" aria-label="选择工作区目录" disabled={busy} onClick={async () => {
        try { const { open } = await import("@tauri-apps/plugin-dialog"); const selected = await open({ directory: true, multiple: false, title: "选择工作区目录" }); if (typeof selected === "string") setPath(selected); }
        catch { setError("无法打开目录选择器，请直接填写路径"); }
      }}><FolderOpen size={17} /></button>}</div></label>
      <div className="settings-feedback" aria-live="polite">{error && <p className="field-error" role="alert">{error}</p>}</div>
      <footer className="settings-actions">{busy && <Loader2 size={15} className="loading-spinner" />}<button type="button" className="secondary-button" disabled={busy || !path.trim()} onClick={() => void activate("create")}>新建工作区</button><button type="submit" className="primary-button" disabled={busy || !path.trim()}>打开工作区</button></footer>
    </form>
  </section>;
}
