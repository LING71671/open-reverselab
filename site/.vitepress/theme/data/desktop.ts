export interface DesktopFeature {
  titleZh: string
  titleEn: string
  descZh: string
  descEn: string
}

export const desktopFeatures: DesktopFeature[] = [
  {
    titleZh: '可视化逆向流水线画布',
    titleEn: 'Visual Pipeline Canvas',
    descZh: '基于 React 19 与 @xyflow/react 构建：自由编排初筛、反编译、内存 Hook 流水线，节点状态与数据流拓扑一目了然。',
    descEn: 'Built on React 19 & xyflow: drag-and-drop nodes to orchestrate triage, decompilation, and dynamic hooking with real-time state telemetry.',
  },
  {
    titleZh: '本地逆向工具链自动桥接',
    titleEn: 'Local Toolchain Bridge',
    descZh: '智能探测并无缝桥接本地已安装的 Ghidra、Frida、x64dbg、DiE 等逆向工具，开箱即用。',
    descEn: 'Auto-detects and bridges installed tools (Ghidra, Frida, x64dbg, DiE, Cutter) via high-performance native IPC.',
  },
  {
    titleZh: 'AI 逆向分析常驻智能体',
    titleEn: 'Autonomous Agent Sidecar',
    descZh: '集成 LangGraph 与 AI SDK，支持流式推理思考、多模型接入、自主调用逆向 MCP 工具链并自动归档证据。',
    descEn: 'Powered by LangGraph & AI SDK: multi-model reasoning, autonomous MCP tool invocation, and structured evidence drawers.',
  },
  {
    titleZh: '纯本地运行与严格合规隔离',
    titleEn: 'Zero-Cloud Air-Gapped Safety',
    descZh: '采用 Tauri v2 极小轻量化架构，分析样本、内存 Dump 与调试日志严禁上云，保障研究合规与隐私。',
    descEn: 'Tauri v2 minimal memory footprint: samples, memory dumps, and logs stay strictly on your local machine.',
  },
]

export const desktopConfig = {
  branch: 'dev',
  runCommand: 'git checkout dev && cd desktop && pnpm install && pnpm run dev',
  githubUrl: 'https://github.com/LING71671/open-reverselab/tree/dev/desktop',
}
