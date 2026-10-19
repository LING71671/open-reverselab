export interface PipelineStage {
  num: string
  titleZh: string
  titleEn: string
  tools: string
  descZh: string
  descEn: string
}

export const pipelineStages: PipelineStage[] = [
  {
    num: '01',
    titleZh: '初始初筛与特征分析',
    titleEn: 'Initial Triage & Entropy',
    tools: 'DiE / PE-bear / Binwalk / Strings',
    descZh: '快速解析文件格式头、节区熵值异常、打包器/加壳签名与可疑 API 导入表特征。',
    descEn: 'Inspect headers, section entropy spikes, packer signatures, and imported symbol anomalies.',
  },
  {
    num: '02',
    titleZh: '攻击网语义精准路由',
    titleEn: 'KB Attack Network Routing',
    tools: 'kb_router / Semantic Index',
    descZh: '根据观测到的入口信号，毫秒级检索 5 大板块中 185 篇实战手册与分叉节点。',
    descEn: 'Match detected entry signals against 185 test-driven playbooks across 5 attack boards.',
  },
  {
    num: '03',
    titleZh: '静态反编译与解包',
    titleEn: 'Static Decompilation',
    tools: 'Ghidra Headless / JADX / Rizin',
    descZh: '无头调用反编译器还原函数原型、恢复数据结构、分析混淆控制流与算法逻辑。',
    descEn: 'Recover function prototypes, decompile control flows, dissect DEX/PE, and identify crypto routines.',
  },
  {
    num: '04',
    titleZh: '动态插桩与内存断点',
    titleEn: 'Dynamic Tracing & Hooks',
    tools: 'Frida Hooks / x64dbg / Procmon',
    descZh: '实时注入 Frida 脚本拦截关键参数，下发条件硬件断点并抓取内存解密态。',
    descEn: 'Deploy runtime instrumentation, intercept function arguments, set conditional breakpoints, and dump memory.',
  },
  {
    num: '05',
    titleZh: '算法重放与证据闭环',
    titleEn: 'Crypto Replay & Evidence',
    tools: 'Python / Diff Patch / YARA / Sigma',
    descZh: '用 Python 复现还原算法生成测试桩，产出二进制差异补丁与 YARA/Sigma 防御检测规则。',
    descEn: 'Reconstruct standalone Python replay solvers, generate patched diff binaries, and emit detection rules.',
  },
]
