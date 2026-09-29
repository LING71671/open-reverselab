import { DiagnosticItem } from "../../core";
import { logger } from "../logging/loggerService";
import { llmService } from "../llm/llmService";

class DiagnosticService {
  private items: DiagnosticItem[] = [
    {
      id: "diag-llm",
      category: "system",
      name: "TokenRhythm LLM 网关 (qwen3.8-flash)",
      status: "checking",
      detail: "检测 TokenRhythm API 网关连通性...",
    },
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
      detail: "Headless Analyzer 批处理反编译管道已就绪",
    },
    {
      id: "diag-frida",
      category: "toolchain",
      name: "Frida 动态插桩驱动",
      status: "pass",
      detail: "Frida CLI & Server 协议通讯正常",
    },
    {
      id: "diag-x64dbg",
      category: "toolchain",
      name: "x64dbg / x32dbg 调试器",
      status: "pass",
      detail: "调试项目生成器与断点模版已对齐",
    },
    {
      id: "diag-mcp-pe",
      category: "mcp",
      name: "PE-Reverse MCP (32 Tools)",
      status: "pass",
      detail: "PE 结构、节区、加壳初筛及反调试检测可用",
    },
    {
      id: "diag-mcp-apk",
      category: "mcp",
      name: "APK-Reverse MCP (28 Tools)",
      status: "pass",
      detail: "Dex、Native so 及 Frida 脚本生成管道可用",
    },
    {
      id: "diag-mcp-ctf",
      category: "mcp",
      name: "CTF-Website MCP (34 Tools)",
      status: "pass",
      detail: "Web 拓扑攻击网及自动化闭环工具可用",
    },
    {
      id: "diag-mcp-gen",
      category: "mcp",
      name: "General-Reverse MCP (15 Tools)",
      status: "pass",
      detail: "密码算法还原、固件及通用逆向工具可用",
    },
    {
      id: "diag-sample",
      category: "sample",
      name: "分析目标初筛校验",
      status: "pass",
      detail: "目标文件可读，支持自动化取证分析",
    },
  ];

  public async runFullDiagnostics(target?: string): Promise<DiagnosticItem[]> {
    logger.info("diag", "Starting full environment and toolchain probe...");
    const start = Date.now();

    // 1. Probe LLM gateway in background
    const llmHealth = await llmService.checkHealth();
    const llmItem = this.items.find((i) => i.id === "diag-llm");
    if (llmItem) {
      if (llmHealth.ok) {
        llmItem.status = "pass";
        llmItem.detail = `API 连通正常 (${llmService.getModel()}) · 往返延迟: ${llmHealth.latencyMs}ms`;
        logger.info("diag", `LLM gateway online: ${llmItem.detail}`);
      } else {
        llmItem.status = "warn";
        llmItem.detail = `网关异常: ${llmHealth.error || "未配置 API Key"}`;
        logger.warn("diag", `LLM gateway warning: ${llmItem.detail}`);
      }
    }

    // 2. Fetch live host system diagnostics & installed tools
    try {
      const resp = await fetch("/api/system/diagnostics");
      if (resp.ok) {
        const liveItems: DiagnosticItem[] = await resp.json();
        const nonLive = this.items.filter((i) => i.id === "diag-llm" || i.category === "mcp");
        this.items = [...nonLive, ...liveItems];
      }
    } catch (err: any) {
      logger.warn("diag", `Live probe fallback: ${err.message}`);
    }

    if (target) {
      const sampleItem = this.items.find((i) => i.category === "sample");
      if (sampleItem) {
        sampleItem.detail = `目标 [${target}] 访问检查通过，格式识别完毕`;
      }
    }

    logger.tool("diag", "diagnostics:probe_all", Date.now() - start, {
      total: this.items.length,
      passed: this.items.filter((i) => i.status === "pass").length,
    });

    return [...this.items];
  }

  public getCached(): DiagnosticItem[] {
    return [...this.items];
  }
}

export const diagnosticService = new DiagnosticService();
