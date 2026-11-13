import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Search, RefreshCw, ArrowUpRight, ArrowLeft, X, BookOpen } from "lucide-react";
import { matchesTrack, type SecurityTrack } from "../../core";
import { nativeBridge, type KbTechnique } from "../../services/native/nativeBridge";
import { MarkdownViewer } from "./MarkdownViewer";
import { Select } from "../controls/Select";
import { ResizeHandle, usePaneSize } from "../controls/ResizeHandle";

interface KbNavigatorProps {
  track: SecurityTrack;
  onTrackChange: (track: SecurityTrack) => void;
  onSelectTechnique: (path: string, title: string) => void;
}
const boardNames: Record<string, string> = { "ctf-website": "Web / CTF", "apk-reverse": "Android / APK", "pe-reverse": "Windows / PE", general: "通用", windows: "Windows" };

export function KbNavigator({ track, onTrackChange, onSelectTechnique }: KbNavigatorProps) {
  const [libraryWidth, setLibraryWidth] = usePaneSize("library", 300);
  const [catalog, setCatalog] = useState<KbTechnique[]>([]);
  const [search, setSearch] = useState("");
  const [board, setBoard] = useState("all");
  const [activePath, setActivePath] = useState("");
  const [readerOpen, setReaderOpen] = useState(false);
  const cache = useRef(new Map<string, string>());
  const scrollPositions = useRef(new Map<string, number>());
  const reader = useRef<HTMLDivElement>(null);
  const [document, setDocument] = useState<{ path: string; content?: string; error?: string }>({ path: "" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [docError, setDocError] = useState("");
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError("");
    nativeBridge.listKb("both").then(items => { if (!cancelled) setCatalog(items); }).catch(err => { if (!cancelled) setError(String(err.message || err)); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [revision]);
  const available = useMemo(() => catalog.filter(item => matchesTrack(item.track, track)), [catalog, track]);
  const boards = [...new Set(available.map(item => item.board))];
  const filtered = useMemo(() => {
    const words = search.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    return available.filter(item => (board === "all" || item.board === board) && words.every(word => `${item.title} ${item.path} ${item.signals.join(" ")} ${item.mcp_tools.join(" ")}`.toLocaleLowerCase().includes(word)));
  }, [available, board, search]);
  const active = filtered.find(item => item.path === activePath) || filtered[0];
  const content = active ? cache.current.get(active.path) ?? (document.path === active.path ? document.content : undefined) : undefined;
  const readError = document.path === active?.path ? document.error : undefined;
  const reading = !!active && content === undefined && !readError;
  useLayoutEffect(() => {
    if (reader.current && active && !reading) reader.current.scrollTop = scrollPositions.current.get(active.path) || 0;
  }, [active?.path, reading]);
  const refresh = () => { cache.current.clear(); setDocument({ path: "" }); setRevision(n => n + 1); };
  useEffect(() => {
    let cancelled = false;
    setDocError("");
    if (!active || cache.current.has(active.path)) return;
    const path = active.path;
    nativeBridge.readKb(path).then(text => {
      if (cancelled) return;
      if (text === null) setDocument({ path, error: "文档不存在，请刷新知识库" });
      else {
        if (cache.current.size >= 40) {
          const oldest = cache.current.keys().next().value!;
          cache.current.delete(oldest);
          scrollPositions.current.delete(oldest);
        }
        cache.current.set(path, text);
        setDocument({ path, content: text });
      }
    }).catch(err => { if (!cancelled) setDocument({ path, error: String(err.message || err) }); });
    return () => { cancelled = true; };
  }, [active?.path, revision]);
  const related = active ? catalog.filter(item => active.related_paths.includes(item.path)) : [];
  const openDocument = (path: string) => {
    const item = catalog.find(item => item.path === path);
    if (!item) { setDocError(`文档未收录：${path}`); return; }
    if (!matchesTrack(item.track, track)) onTrackChange(item.track);
    setSearch(""); setBoard("all"); setActivePath(path); setReaderOpen(true);
  };
  return (
    <section className="knowledge-workspace" aria-label="知识库" data-reading={readerOpen}>
      <div className="knowledge-library" style={{ width: libraryWidth }}>
        <div className="knowledge-filters">
          <label className="knowledge-search"><Search size={16} /><input type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder="搜索文档、信号或工具" aria-label="搜索知识库" />{search && <button className="icon-button" aria-label="清除搜索" onClick={() => setSearch("")}><X size={14} /></button>}</label>
          <div className="knowledge-filter-row"><Select label="知识库领域" value={board} onChange={setBoard} options={[{ value: "all", label: "所有领域" }, ...boards.map(value => ({ value, label: boardNames[value] || value }))]} /><span>{filtered.length} 篇</span><button className="icon-button" onClick={refresh} disabled={loading} aria-label="刷新知识库"><RefreshCw size={14} className={loading ? "loading-spinner" : ""} /></button></div>
        </div>
        <div className="knowledge-list" aria-label="文档列表" aria-busy={loading}>
          {loading ? <div className="skeleton-list" aria-label="正在加载知识库">{[0,1,2,3,4,5].map(n => <div className="skeleton-row" key={n} />)}</div> : error ? <div className="inline-error" role="alert"><p>{error}</p><button className="text-button" onClick={() => setRevision(n => n + 1)}>重试</button></div> : filtered.length === 0 ? <div className="compact-empty">没有匹配文档<button className="text-button" onClick={() => { setSearch(""); setBoard("all"); }}>清除筛选</button></div> : filtered.map(item => <button key={item.path} className="knowledge-row" aria-current={active?.path === item.path ? "true" : undefined} onClick={() => { setActivePath(item.path); setReaderOpen(true); }}><span>{item.title}</span><small><span>{boardNames[item.board] || item.board}</span><span className={`track-text track-${item.track}`}>{item.track}</span></small></button>)}
        </div>
        <ResizeHandle label="调整文档列表宽度" axis="x" size={libraryWidth} min={240} max={440} initial={300} onChange={setLibraryWidth} />
      </div>
      <article className="knowledge-reader" aria-busy={reading}>
        {active && <>
          <header className="reader-toolbar"><button className="icon-button reader-back" aria-label="返回文档列表" onClick={() => setReaderOpen(false)}><ArrowLeft size={16} /></button><span className="reader-path" title={active.path}><BookOpen size={15} />{boardNames[active.board] || active.board}</span><span className="grow" /><button className="secondary-button" title="参考此文档创建 Goal" onClick={() => onSelectTechnique(active.path, active.title)}>创建 Goal<ArrowUpRight size={15} /></button></header>
          {related.length > 0 && <div className="paired-documents"><span>关联文档</span>{related.map(item => <button key={item.path} className="text-button" onClick={() => openDocument(item.path)} title={item.title}><ArrowLeft size={12} /><span className={`track-text track-${item.track}`}>{item.track}</span><span className="paired-title">{item.title}</span></button>)}</div>}
          <div className="reader-content" key={active.path} ref={reader} onScroll={event => { if (!reading) scrollPositions.current.set(active.path, event.currentTarget.scrollTop); }}>
            {docError || readError ? <div className="inline-error" role="alert"><p>{docError || readError}</p><button className="text-button" onClick={refresh}>重试</button></div> : reading ? <div className="reader-skeleton" aria-label="正在读取文档"><div /><div /><div /></div> : <MarkdownViewer content={content || ""} docPath={active.path} onNavigate={openDocument} />}
          </div>
        </>}
      </article>
    </section>
  );
}
