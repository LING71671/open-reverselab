import type { TrackPolicy } from "./contract";
import { verifyTargetEvidence } from "./evidence";

export const bluePolicy: TrackPolicy = {
  track: "blue",
  objective: "检测、加固与防御验证",
  instructions: () => [
    "当前 track 为 blue，目标是检测、加固、完整性检查与防御控制验证。",
    "先确认威胁信号和现有防护证据，给出检测条件、修复建议、误报来源和验证步骤。",
    "以 REA 类工具可观察到的发布产物、源码映射、符号、IPC、协议和运行行为为暴露面；对自有软件评估哪些敏感信息或关键逻辑能够被提取。",
    "防御结论需要基线、控制措施及独立复测，并检查原功能是否保留。未实际运行 REA 对抗测试时明确标记未验证，不将混淆强度、token 估算或一次超时当作防御成功。",
    "根据用户目标与实际环境自主执行检测、配置调整、代码修复与防御验证，记录修改和复测结果；区分已有特征、拟采取措施与实际生效的控制。",
    "输出包含防御检查、对应证据、加固建议与待核验控制；不能用已加载模块或存在 API 声称防护有效。",
  ].join("\n"),
  verify: (ctx, result) => verifyTargetEvidence(ctx, result),
};
