import { useEffect, useRef, useState } from "react";
import { FolderOpen, Loader2, X } from "lucide-react";
import { isTauri } from "@tauri-apps/api/core";
import type { Workspace } from "../../core/contracts/workspace";
import { nativeBridge } from "../../services/native/nativeBridge";
import { useHarness } from "../../state";

export function WorkspaceDialog({ onClose }: { onClose: () => void }) {
  const { workspace, openWorkspace } = useHarness();
  const dialog = useRef<HTMLDialogElement>(null);
  const [recent, setRecent] = useState<Workspace[]>([]);
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { dialog.current?.showModal(); nativeBridge.workspace<Workspace[]>({ action: "list" }).then(setRecent).catch(err => setError(String(err))); }, []);
  const activate = async (action: "create" | "open", root = path) => {
    if (!root.trim()) return;
    setBusy(true); setError("");
    try { await openWorkspace(await nativeBridge.workspace<Workspace>({ action, root: root.trim() })); onClose(); }
    catch (err) { setError(String(err)); }
    finally { setBusy(false); }
  };
  return <dialog ref={dialog} className="settings-dialog workspace-dialog" onClose={onClose} onCancel={onClose}>
    <header><h2>工作区</h2><button className="icon-button" aria-label="关闭工作区选择" onClick={onClose}><X size={18} /></button></header>
    <div className="settings-fields"><div className="recent-workspaces">{recent.map(item => <button key={item.root} disabled={busy} onClick={() => void activate("open", item.root)} aria-current={item.root === workspace.root ? "true" : undefined}><FolderOpen size={17} /><span>{item.name}<small>{item.root}</small></span>{item.root === workspace.root && <small>当前</small>}</button>)}</div>
      <label>目录<div className="workspace-path-input"><input value={path} onChange={e => setPath(e.target.value)} placeholder="工作区路径" aria-label="工作区路径" />{isTauri() && <button className="icon-button" aria-label="选择工作区目录" onClick={async () => { const { open } = await import("@tauri-apps/plugin-dialog"); const selected = await open({ directory: true, multiple: false, title: "选择工作区目录" }); if (typeof selected === "string") setPath(selected); }}><FolderOpen size={17} /></button>}</div></label>
      {error && <p className="inline-error" role="alert">{error}</p>}
    </div><footer>{busy && <Loader2 size={15} className="loading-spinner" />}<span className="grow" /><button className="secondary-button" disabled={busy || !path.trim()} onClick={() => void activate("create")}>新建工作区</button><button className="primary-button" disabled={busy || !path.trim()} onClick={() => void activate("open")}>打开工作区</button></footer>
  </dialog>;
}
