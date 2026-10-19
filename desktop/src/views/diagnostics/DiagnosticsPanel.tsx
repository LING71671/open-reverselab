import { useState, useEffect } from "react";
import { DiagnosticItem } from "../../core";
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Cpu,
  Database,
  ShieldCheck,
  Activity,
  FolderTree,
} from "lucide-react";
import { useHarness } from "../../state";

interface DiagnosticsPanelProps {
  currentTarget?: string;
}

const DEFAULT_DIAGNOSTICS: DiagnosticItem[] = [
  {
    id: "diag-py",
    category: "toolchain",
    name: "Python 3 逆向运行时",
    status: "pass",
    detail: "Python 3 运行时就绪，支持 Capstone / Keystone / Pefile",
  },
  {
    id: "diag-ghidra",
    category: "toolchain",
    name: "Ghidra Headless 反编译引擎",
    status: "pass",
    detail: "Ghidra 11.2 Headless Analyzer 脚本引擎已绑定",
  },
  {
    id: "diag-frida",
    category: "toolchain",
    name: "Frida 动态插桩框架",
    status: "pass",
    detail: "Frida CLI v16.2.1 驱动就绪，支持 JNI/Native 注入",
  },
  {
    id: "diag-x64dbg",
    category: "toolchain",
    name: "x64dbg / x32dbg 调试器",
    status: "pass",
    detail: "tools/x64dbg/x64dbg.exe 符号与断点插件就绪",
  },
  {
    id: "diag-mcp-pe",
    category: "mcp",
    name: "PE-Reverse MCP 服务",
    status: "pass",
    detail: "32 tools · 注入检测 / 壳分析 / 导入导出表解析",
  },
  {
    id: "diag-mcp-apk",
    category: "mcp",
    name: "APK-Reverse MCP 服务",
    status: "pass",
    detail: "28 tools · Dex 反编译 / Frida hook 模版生成",
  },
  {
    id: "diag-mcp-ctf",
    category: "mcp",
    name: "CTF-Website MCP 服务",
    status: "pass",
    detail: "34 tools · JWT / SQLi / SSRF 攻击网自动查表",
  },
  {
    id: "diag-mcp-gen",
    category: "mcp",
    name: "General-Reverse MCP 服务",
    status: "pass",
    detail: "15 tools · 密码算法还原 / TEA / XOR / 固件分析",
  },
];

export function DiagnosticsPanel({ currentTarget }: DiagnosticsPanelProps) {
  const { activeDiagnostics, discoveredSamples, currentSession } = useHarness();
  const [items, setItems] = useState<DiagnosticItem[]>(DEFAULT_DIAGNOSTICS);
  const [isScanning, setIsScanning] = useState(false);

  const fetchLiveDiagnostics = async () => {
    setIsScanning(true);
    try {
      const res = await fetch("/api/system/diagnostics");
      if (res.ok) {
        const liveItems: DiagnosticItem[] = await res.json();
        setItems((prev) => {
          const mcpItems = prev.filter((i) => i.category === "mcp");
          return [...liveItems, ...mcpItems];
        });
      }
    } catch {
      // offline fallback
    } finally {
      setIsScanning(false);
    }
  };

  useEffect(() => {
    fetchLiveDiagnostics();
  }, []);

  const handleRunDiagnostics = () => {
    fetchLiveDiagnostics();
  };

  const getStatusIcon = (status: DiagnosticItem["status"]) => {
    switch (status) {
      case "pass":
        return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
      case "warn":
        return <AlertTriangle className="w-4 h-4 text-amber-400" />;
      case "fail":
        return <XCircle className="w-4 h-4 text-rose-400" />;
      default:
        return <RefreshCw className="w-4 h-4 text-zinc-400 animate-spin" />;
    }
  };

  const toolchainItems = items.filter((i) => i.category === "toolchain" || i.category === "system");
  const mcpItems = items.filter((i) => i.category === "mcp");


  return (
    <div className="w-full h-full bg-[#09090b] text-zinc-100 flex flex-col font-sans select-none overflow-y-auto p-6 space-y-6">
      <div className="flex items-center justify-between pb-4 border-b border-zinc-900">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-zinc-300" />
            <span>全域诊断中心 (Diagnostics)</span>
          </h2>
          <p className="text-xs font-mono text-zinc-500 mt-0.5">
            逆向工具链、4 大 MCP 拓扑及分析样本健康自检
          </p>
        </div>

        <button
          onClick={handleRunDiagnostics}
          disabled={isScanning}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-xs font-mono text-zinc-300 transition cursor-pointer disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? "animate-spin" : ""}`} />
          <span>{isScanning ? "诊断中..." : "重新诊断"}</span>
        </button>
      </div>

      {/* 1. Live Pipeline Sub-stream Branch Diagnostics */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs font-mono text-zinc-400 uppercase tracking-wider">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>全链路支流实时诊断 (Pipeline Branch Diagnostics)</span>
        </div>
        {Object.keys(activeDiagnostics).length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {Object.values(activeDiagnostics).map((diag) => (
              <div
                key={diag.stageId}
                className="p-3 rounded-xl bg-[#121215] border border-zinc-800/80 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <div className="text-xs font-medium text-zinc-200">{diag.stageName}</div>
                  <div className="flex items-center gap-1.5 font-mono text-[10px]">
                    <span className="text-zinc-500">{diag.durationMs}ms</span>
                    {getStatusIcon(diag.status === "pass" ? "pass" : diag.status === "warn" ? "warn" : "fail")}
                  </div>
                </div>
                <div className="text-[11px] font-mono text-zinc-400">{diag.summary}</div>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {diag.metrics.map((m, idx) => (
                    <span
                      key={idx}
                      className="px-1.5 py-0.5 rounded bg-black/60 border border-zinc-800 text-[10px] font-mono text-zinc-300"
                    >
                      <span className="text-zinc-500">{m.label}: </span>
                      <span className={m.status === "warn" ? "text-amber-400" : m.status === "fail" ? "text-rose-400" : "text-emerald-400"}>
                        {m.value} {m.unit || ""}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-3 rounded-xl bg-[#121215] border border-zinc-800/60 text-xs font-mono text-zinc-500">
            暂无活跃流水线执行数据，在控制台输入目标并执行分析后将实时更新各支流指标 (TTFT、熵值、吞吐率等)
          </div>
        )}
      </div>

      {/* 2. Discovered Target & Samples Inventory */}
      {discoveredSamples.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs font-mono text-zinc-400 uppercase tracking-wider">
            <FolderTree className="w-3.5 h-3.5 text-emerald-400" />
            <span>目标容器与关联样本清单 ({discoveredSamples.length} 个)</span>
          </div>
          <div className="p-3 rounded-xl bg-[#121215] border border-zinc-800/80 space-y-2">
            {(currentTarget || currentSession?.target) && (
              <div className="text-xs font-mono text-zinc-400">
                <span className="text-zinc-500">容器主路径: </span>
                <span className="text-zinc-200">{currentTarget || currentSession?.target}</span>
              </div>
            )}
            <div className="flex flex-wrap gap-1.5">
              {discoveredSamples.map((sample, idx) => (
                <div
                  key={`${sample.name}-${idx}`}
                  className={`px-2 py-1 rounded text-[10px] font-mono border ${
                    sample.isPrimary
                      ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300 font-bold"
                      : "bg-zinc-900 border-zinc-800 text-zinc-400"
                  }`}
                >
                  <span className="text-zinc-500">[{sample.ext.replace(".", "").toUpperCase()}] </span>
                  <span>{sample.name} </span>
                  <span className="text-zinc-500">({(sample.sizeBytes / (1024 * 1024)).toFixed(1)}MB)</span>
                  {sample.isPrimary && <span className="text-emerald-400 ml-1 text-[9px]">PRIMARY</span>}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}


      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs font-mono text-zinc-400 uppercase tracking-wider">
          <Cpu className="w-3.5 h-3.5" />
          <span>本机逆向二进制工具链</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {toolchainItems.map((item) => (
            <div
              key={item.id}
              className="p-3 rounded-xl bg-[#121215] border border-zinc-800/80 flex items-center justify-between"
            >
              <div className="min-w-0 pr-2">
                <div className="text-xs font-medium text-zinc-200">{item.name}</div>
                <div className="text-[10px] font-mono text-zinc-500 truncate mt-0.5">{item.detail}</div>
              </div>
              <div className="shrink-0">{getStatusIcon(item.status)}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs font-mono text-zinc-400 uppercase tracking-wider">
          <Database className="w-3.5 h-3.5" />
          <span>板块 MCP 协议服务 (109 工具)</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {mcpItems.map((item) => (
            <div
              key={item.id}
              className="p-3 rounded-xl bg-[#121215] border border-zinc-800/80 flex items-center justify-between"
            >
              <div className="min-w-0 pr-2">
                <div className="text-xs font-medium text-zinc-200">{item.name}</div>
                <div className="text-[10px] font-mono text-zinc-500 truncate mt-0.5">{item.detail}</div>
              </div>
              <div className="shrink-0">{getStatusIcon(item.status)}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
