import { useEffect, useState } from "react";
import { ArrowUpRight, FolderOpen, Loader2, Upload } from "lucide-react";
import { isTauri } from "@tauri-apps/api/core";
import type { WorkspaceSample } from "../../core/contracts/workspace";
import { nativeBridge } from "../../services/native/nativeBridge";
import { useHarness } from "../../state";
export function SamplesView({ onSelect }: { onSelect: (target: string) => void }) {
  const { workspace } = useHarness();
  const [samples, setSamples] = useState<WorkspaceSample[]>([]);
  const [source, setSource] = useState("");
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let disposed = false;
    nativeBridge.workspace<WorkspaceSample[]>({ action: "samples", root: workspace.root }).then(items => { if (!disposed) setSamples(items); }).catch(err => { if (!disposed) setError(String(err)); }).finally(() => { if (!disposed) setBusy(false); });
    return () => { disposed = true; };
  }, [workspace.root]);
  const importSample = async (path = source) => {
    if (!path.trim()) return;
    setBusy(true); setError("");
    try { const sample = await nativeBridge.workspace<WorkspaceSample>({ action: "import", root: workspace.root, source: path.trim() }); setSamples(previous => [sample, ...previous]); setSource(""); }
    catch (err) { setError(String(err)); }
    finally { setBusy(false); }
  };
  const choose = async (directory: boolean) => {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const path = await open({ directory, multiple: false, title: directory ? "导入样本目录" : "导入样本文件" });
    if (typeof path === "string") await importSample(path);
  };
  return <section className="samples-workspace"><form className="sample-import" onSubmit={e => { e.preventDefault(); void importSample(); }}><label><span className="sr-only">样本路径</span><input value={source} onChange={e => setSource(e.target.value)} placeholder="样本文件或目录路径" aria-label="样本路径" /></label><button className="primary-button" disabled={busy || !source.trim()}><Upload size={14} />导入</button>{isTauri() && <><button type="button" className="secondary-button" disabled={busy} onClick={() => void choose(false)}>选择文件</button><button type="button" className="icon-button" title="导入目录" aria-label="导入目录" disabled={busy} onClick={() => void choose(true)}><FolderOpen size={17} /></button></>}</form>
    {busy && <p className="sample-loading" role="status"><Loader2 size={15} className="loading-spinner" />正在处理样本</p>}{error && <p className="inline-error" role="alert">{error}</p>}
    <div className="sample-list">{samples.map(sample => <article key={sample.id}><div><h2>{sample.name}</h2><small>{sample.kind === "directory" ? "目录" : "文件"} · {(sample.sizeBytes / 1024).toFixed(1)} KB</small><code title={sample.sha256}>SHA256 {sample.sha256}</code></div><button className="secondary-button" onClick={() => onSelect(sample.target)}>创建 Goal<ArrowUpRight size={15} /></button></article>)}</div>
  </section>;
}
