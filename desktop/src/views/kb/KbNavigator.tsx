import { useState, useEffect } from "react";
import { BookOpen, FileCode, Search, ChevronRight, X, Play, Code2 } from "lucide-react";
import { useI18n } from "../../core";

interface KbNavigatorProps {
  onSelectTechnique?: (ref: string) => void;
}

interface TechniqueMeta {
  id: string;
  board: string;
  titleZh: string;
  titleEn: string;
  category: string;
  signals: string[];
  mcpTool: string;
  docPath: string;
}

const DEFAULT_CURATED: TechniqueMeta[] = [
  {
    id: "pe-reverse:00-triage-pe",
    board: "pe-reverse",
    titleZh: "PE 初筛与加壳研判",
    titleEn: "PE Triage & Packer Analysis",
    category: "00-triage",
    signals: ["UPX", "Entropy", "Overlay"],
    mcpTool: "triage_pe / die_scan",
    docPath: "kb/pe-reverse/techniques/00-triage/00-triage-pe.md",
  },
  {
    id: "pe-reverse:00-anti-debug-bypass",
    board: "pe-reverse",
    titleZh: "反调试与反虚拟机绕过",
    titleEn: "Anti-Debug & Anti-VM Bypass",
    category: "02-dynamic",
    signals: ["IsDebuggerPresent", "NtGlobalFlag"],
    mcpTool: "patch_pe / x64dbg_scaffold",
    docPath: "kb/pe-reverse/techniques/02-dynamic/00-anti-debug-bypass.md",
  },
  {
    id: "pe-reverse:00-ghidra-headless",
    board: "pe-reverse",
    titleZh: "Ghidra 符号与交叉引用反编译",
    titleEn: "Ghidra Headless Decompilation",
    category: "01-static",
    signals: ["WinMain", "Xrefs", "ImportTable"],
    mcpTool: "ghidra_headless_analyze",
    docPath: "kb/pe-reverse/techniques/01-static/00-ghidra-headless.md",
  },
  {
    id: "apk-reverse:00-unpack-dex",
    board: "apk-reverse",
    titleZh: "Android 脱壳与内存转储",
    titleEn: "Android Dex Unpack & Memory Dump",
    category: "00-unpack",
    signals: ["SecShell", "Legu", "Bangcle"],
    mcpTool: "android_crypto_unpack_recipe",
    docPath: "kb/apk-reverse/techniques/00-unpack/00-unpack-dex.md",
  },
  {
    id: "apk-reverse:00-frida-hook",
    board: "apk-reverse",
    titleZh: "Frida 动态插桩与 Hook",
    titleEn: "Frida Dynamic Instrumentation & Hook",
    category: "02-dynamic",
    signals: ["JNI_OnLoad", "Java.use", "Interceptor"],
    mcpTool: "android_http_observation_recipe",
    docPath: "kb/apk-reverse/techniques/02-dynamic/00-frida-hook.md",
  },
  {
    id: "ctf-website:00-jwt-attacks",
    board: "ctf-website",
    titleZh: "JWT 密钥爆破与算法混淆",
    titleEn: "JWT Token Cracking & Algorithm Confusion",
    category: "02-auth",
    signals: ["NoneAlgorithm", "WeakSecret", "JKU"],
    mcpTool: "jwt_tool / ctf_autopilot",
    docPath: "kb/ctf-website/techniques/02-auth/00-jwt-attacks.md",
  },
  {
    id: "general:01-custom-xor-tea",
    board: "general",
    titleZh: "对称加解密与哈希算法还原",
    titleEn: "Symmetric Crypto & Hash Reconstruction",
    category: "00-crypto",
    signals: ["TEA", "XOR", "CRC32", "RC4"],
    mcpTool: "solve_crypto_from_evidence",
    docPath: "kb/general/techniques/00-crypto/01-custom-xor-tea.md",
  },
];

async function tauriInvoke<T>(cmd: string, args?: Record<string, any>): Promise<T | null> {
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    return await invoke<T>(cmd, args);
  } catch {
    return null;
  }
}

export function KbNavigator({ onSelectTechnique }: KbNavigatorProps) {
  const { t, locale } = useI18n();
  const [selectedBoard, setSelectedBoard] = useState<string>("all");
  const [search, setSearch] = useState<string>("");
  const [techniques, setTechniques] = useState<TechniqueMeta[]>(DEFAULT_CURATED);
  const [activeDoc, setActiveDoc] = useState<{ path: string; title: string; content: string } | null>(null);

  useEffect(() => {
    let mounted = true;
    (async () => {
      const liveList = await tauriInvoke<any[]>("list_kb_techniques");
      if (mounted && liveList && liveList.length > 0) {
        const mapped: TechniqueMeta[] = liveList.map((item) => ({
          id: item.id,
          board: item.board,
          category: item.category,
          titleZh: item.title,
          titleEn: item.title,
          signals: item.signals.length > 0 ? item.signals : ["General"],
          mcpTool: item.mcp_tools.length > 0 ? item.mcp_tools.join(", ") : "kb_router",
          docPath: item.path,
        }));
        setTechniques(mapped);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  const handleReadDoc = async (item: TechniqueMeta, e: React.MouseEvent) => {
    e.stopPropagation();
    const content = await tauriInvoke<string>("read_kb_doc", { relativePath: item.docPath });
    setActiveDoc({
      path: item.docPath,
      title: item.titleZh,
      content: content || `# ${item.titleZh}\n\n*暂无法直接读取本机文档文本，请查阅: ${item.docPath}*`,
    });
  };

  const boards = [
    { id: "all", label: t.kb.all },
    { id: "pe-reverse", label: "PE" },
    { id: "apk-reverse", label: "APK" },
    { id: "ctf-website", label: "CTF" },
    { id: "general", label: "General" },
  ];

  const filtered = techniques.filter((item) => {
    const matchBoard = selectedBoard === "all" || item.board === selectedBoard;
    const title = locale === "zh" ? item.titleZh : item.titleEn;
    const matchSearch =
      !search.trim() ||
      title.toLowerCase().includes(search.toLowerCase()) ||
      item.signals.some((s) => s.toLowerCase().includes(search.toLowerCase())) ||
      item.mcpTool.toLowerCase().includes(search.toLowerCase()) ||
      item.docPath.toLowerCase().includes(search.toLowerCase());
    return matchBoard && matchSearch;
  });

  return (
    <div className="w-full h-full p-6 flex flex-col gap-4 font-sans select-none overflow-y-auto">
      {/* Top Header */}
      <div className="flex items-center justify-between pb-3 border-b border-zinc-900">
        <div className="flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-zinc-400" />
          <h2 className="text-sm font-semibold tracking-wide text-zinc-100">{t.kb.title}</h2>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-zinc-900 border border-zinc-800 text-zinc-400">
            Live KB
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-zinc-400">
            {filtered.length} / {techniques.length} 篇技术文件
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t.kb.searchPlaceholder}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-zinc-950 border border-zinc-800 text-xs text-zinc-200 placeholder-zinc-600 font-mono focus:outline-none focus:border-zinc-700"
          />
        </div>

        <div className="flex items-center gap-1 p-0.5 rounded-lg bg-zinc-950 border border-zinc-900">
          {boards.map((b) => (
            <button
              key={b.id}
              onClick={() => setSelectedBoard(b.id)}
              className={`px-2.5 py-1 rounded text-xs font-mono transition cursor-pointer ${
                selectedBoard === b.id
                  ? "bg-zinc-800 text-zinc-100"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {b.label}
            </button>
          ))}
        </div>
      </div>

      {/* Technique Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
        {filtered.map((item) => {
          const title = locale === "zh" ? item.titleZh : item.titleEn;
          return (
            <div
              key={item.id}
              className="p-4 rounded-xl bg-zinc-950/60 border border-zinc-900 hover:border-zinc-800 transition flex flex-col justify-between gap-3 group"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                    {item.board}
                  </span>
                  <span className="text-xs font-mono text-zinc-500 flex items-center gap-1">
                    <span>{item.category}</span>
                    <ChevronRight className="w-3 h-3 text-zinc-700 group-hover:text-zinc-400 transition" />
                  </span>
                </div>

                <div className="text-xs font-medium text-zinc-200 group-hover:text-white transition">
                  {title}
                </div>

                {/* Signals */}
                <div className="flex flex-wrap gap-1 pt-1">
                  {item.signals.map((sig, idx) => (
                    <span
                      key={idx}
                      className="text-xs font-mono px-1.5 py-0.5 rounded bg-zinc-900/90 text-zinc-400 border border-zinc-800/60"
                    >
                      {sig}
                    </span>
                  ))}
                </div>
              </div>

              {/* Action Toolbar */}
              <div className="flex items-center justify-between pt-2 border-t border-zinc-900 text-xs font-mono text-zinc-500">
                <div className="flex items-center gap-1.5 truncate max-w-[180px]">
                  <FileCode className="w-3 h-3 text-zinc-600 shrink-0" />
                  <span className="text-zinc-400 truncate">{item.mcpTool}</span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={(e) => handleReadDoc(item, e)}
                    className="flex items-center gap-1 px-2 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 text-zinc-300 transition cursor-pointer"
                  >
                    <Code2 className="w-3 h-3" />
                    <span>阅读</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => onSelectTechnique?.(item.docPath)}
                    className="flex items-center gap-1 px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-100 transition cursor-pointer"
                  >
                    <Play className="w-3 h-3" />
                    <span>执行</span>
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Slide-over / Modal for Markdown Reading */}
      {activeDoc && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-6">
          <div className="w-full max-w-4xl h-[85vh] bg-[#0c0c0e] border border-zinc-800 rounded-2xl flex flex-col shadow-2xl overflow-hidden font-sans">
            {/* Header */}
            <div className="px-5 py-3 border-b border-zinc-800/80 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-zinc-400" />
                <h3 className="text-xs font-semibold text-zinc-200">{activeDoc.title}</h3>
                <span className="text-[11px] font-mono text-zinc-500">{activeDoc.path}</span>
              </div>
              <button
                type="button"
                onClick={() => setActiveDoc(null)}
                className="p-1 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-zinc-100 transition cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Content Area */}
            <div className="flex-1 p-6 overflow-y-auto font-mono text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap select-text bg-[#09090b]">
              {activeDoc.content}
            </div>

            {/* Footer */}
            <div className="px-5 py-3 border-t border-zinc-800/80 flex items-center justify-between bg-zinc-950">
              <span className="text-[11px] font-mono text-zinc-500">
                可复制脚本直接在目标中验证
              </span>
              <button
                type="button"
                onClick={() => {
                  onSelectTechnique?.(activeDoc.path);
                  setActiveDoc(null);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-100 text-zinc-900 font-medium text-xs hover:bg-white transition cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                <span>基于此篇发起逆向分析</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
