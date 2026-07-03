export const meta = {
  name: 'ctf-full-pipeline',
  description: 'CTF 全链路评估流水线 — 资产发现 → DoS攻击面 → 全面漏洞挖掘 → 漏洞逐条验证 → 综合报告',
  phases: [
    { title: '阶段一：资产发现' },
    { title: '阶段二：DoS 攻击面评估' },
    { title: '阶段三：全面漏洞挖掘' },
    { title: '阶段四：漏洞逐条验证' },
    { title: '阶段五：综合报告生成' },
  ],
}

// ================================================================
// args 规范：
//   string          → 直接当 domain
//   object.domain   → 目标域名
//   object.caseDir  → 案例目录（默认 cases/<domain-dashed>/）
//   object.skipDos  → 跳过 DoS 阶段（默认 false）
//   object.skipVerify → 跳过验证阶段（默认 false）
// ================================================================
const domain = typeof args === 'string' ? args : args?.domain || args?.target || ''
if (!domain) {
  throw new Error('ctf-full-pipeline requires args.domain/args.target or string domain')
}
const caseRoot = typeof args === 'object' && args?.caseRoot ? args.caseRoot : 'cases'
const caseDir =
  typeof args === 'object' && args?.caseDir
    ? args.caseDir
    : `${caseRoot}/${domain.replace(/\./g, '-')}`
const skipDos = typeof args === 'object' && args?.skipDos === true
const skipVerify = typeof args === 'object' && args?.skipVerify === true
const sharedOptions = typeof args === 'object' ? {
  caseRoot,
  testOrigin: args?.testOrigin,
  redirectProbeHost: args?.redirectProbeHost,
  ssrfProbeTargets: args?.ssrfProbeTargets,
  credentialPairs: args?.credentialPairs,
  forwardedIp: args?.forwardedIp,
  dnsNs: args?.dnsNs,
  geofenced: args?.geofenced,
  unprobed: args?.unprobed,
} : { caseRoot }

// 确保 caseDir 存在（Write 工具通常自行创建目录，此处仅做占位）
// 如需强制创建，可在执行前通过 Bash 工具运行: mkdir -p "<caseDir>"

// ================================================================
// 阶段一：资产发现（6 并行子代理 + 综合研判）
// ================================================================
phase('阶段一：资产发现')

const recon = await workflow('ctf-asset-discovery', { domain, caseDir, ...sharedOptions })

// ================================================================
// 数据提取：从资产发现产出中解析结构化数据供下游使用
// ================================================================
const reconExtraction = await agent(
  `你是 CTF 侦察数据提取器。从下面的资产发现报告中提取结构化 JSON。

=== 目标域名 ===
${domain}

=== 资产发现综合报告 ===
${recon.synthesis || '(无综合报告)'}

=== crt.sh 原始结果 ===
${recon.crtsh || '(无)'}

=== DNS 原始结果 ===
${recon.dns || '(无)'}

=== WHOIS 原始结果 ===
${recon.whois || '(无)'}

=== HTTP 指纹原始结果 ===
${recon.http || '(无)'}

=== 邮件安全原始结果 ===
${recon.email || '(无)'}

=== 搜索引擎暴露原始结果 ===
${recon.search || '(无)'}

## 提取要求

返回 **纯 JSON**，不要 Markdown 代码块标记（\`\`\`json），直接输出 JSON 对象：

{
  "subdomains": ["www", "mail", "cas", ...],
  "ip_addresses": ["1.2.3.4", ...],
  "targets": [
    {"host": "<host>", "ip": "<ip>", "stack": "Java/Tomcat", "cdn": false, "waf": false, "h2": true}
  ],
  "tech_stack": {
    "web": ["Java/JSP", "nginx"],
    "mail": ["enterprise mail"],
    "waf": ["Cloudflare"],
    "cms": ["WordPress", "Drupal", "custom CMS"],
    "backend": ["Java", "PHP"]
  },
  "interesting": [
    {"type": "subdomain_takeover|info_leak|weak_security", "target": "...", "note": "..."}
  ]
}

规则：
1. subdomains 包含所有发现的子域名（去重）
2. ip_addresses 包含所有 IP（去重）
3. targets 包含所有可达的、有意义的子域名；如调用方提供 targetLimit 才按该参数截断
4. tech_stack 从 Server/X-Powered-By/CMS 指纹推断
5. interesting 列出值得关注的发现（弱 SPF、无 DMARC、开发接口暴露等）
6. 如果某个字段无法确定，使用空数组/空对象`,
  { label: '数据提取', phase: '阶段一：资产发现' },
)

// ================================================================
// 阶段二：DoS 攻击面评估（13 种技术 → 全目标映射）
// ================================================================
let dosResult = null
if (!skipDos) {
  phase('阶段二：DoS 攻击面评估')

  let dosTargets = []
  let dosFingerprints = {}
  try {
    const extracted = JSON.parse(reconExtraction)
    dosTargets = extracted.targets || []
    dosFingerprints = extracted.tech_stack || {}
  } catch (_) {
    // 提取失败时使用空数据，workflow 内部有默认值兜底
  }

  dosResult = await workflow('ctf-dos-assessment', {
    domain,
    targets: dosTargets,
    fingerprints: dosFingerprints,
    caseDir,
    ...sharedOptions,
  })
}

// ================================================================
// 阶段三：全面漏洞挖掘（8 并行子代理 + 综合研判）
// ================================================================
phase('阶段三：全面漏洞挖掘')

let subdomainsForVuln = []
try {
  const extracted = JSON.parse(reconExtraction)
  subdomainsForVuln = extracted.subdomains || []
} catch (_) {}

const vuln = await workflow('ctf-vuln-discovery', {
  domain,
  subdomains: subdomainsForVuln.length > 0 ? subdomainsForVuln : undefined,
  caseDir,
  ...sharedOptions,
})

// ================================================================
// 阶段四：漏洞逐条验证（8 并行子代理 + 综合研判）
// ================================================================
let verifyResult = null
if (!skipVerify) {
  phase('阶段四：漏洞逐条验证')

  let verifyTargets =
    subdomainsForVuln.length > 0
      ? subdomainsForVuln
      : [domain, `www.${domain}`, `mail.${domain}`, `cas.${domain}`]

  verifyResult = await workflow('ctf-vuln-verify', {
    domain,
    findings: vuln.synthesis,
    techStack: vuln.fingerprint,
    targets: verifyTargets,
    caseDir,
    ...sharedOptions,
  })
}

// ================================================================
// 阶段五：综合报告生成
// ================================================================
phase('阶段五：综合报告生成')

const finalReport = await agent(
  `你是 CTF 综合评估报告的最终生成器。请基于以下四个阶段的全部输出，生成一份完整的 Markdown 综合报告。

# 数据输入

## 资产发现
${recon.synthesis || recon}

## DoS 攻击面评估
${dosResult?.synthesis || dosResult || '(已跳过)'}

## 全面漏洞挖掘
${vuln.synthesis || vuln}

## 漏洞验证
${verifyResult?.synthesis || verifyResult || '(已跳过)'}

# 报告要求

将完整报告写入文件：${caseDir}/FINAL-REPORT.md

## 报告结构

### 1. 执行摘要
- 目标域名：${domain}
- 评估日期：（由执行环境自动填充）
- 总体风险等级：🔴 高危 / 🟠 中危 / 🟡 低危
- 关键发现数量统计（已确认 / 潜在 / 误报）

### 2. 资产全景
- 子域名总数与分类
- 技术栈矩阵（每子域名对应技术）
- 暴露面概述

### 3. DoS 攻击面
- 13 种 DoS 技术的可利用性矩阵（✅ 可利用 / ⚠️ 潜在 / ❌ 不可用）
- 每条记录的优先级（风险 = 可能性 × 影响）
- 攻击链组合场景

### 4. 已确认漏洞
对每个已确认漏洞，包含：
- 目标 URL
- 漏洞类型（CWE 编号）
- 严重等级（CVSS 估算）
- 复现步骤（含请求/响应）
- 利用 Payload
- 修复建议

### 5. 潜在漏洞
- 每条的置信度分析
- 当前阻塞点
- 建议的下一步验证方法

### 6. 攻击链分析
- 可组合的漏洞链（如：XSS + CSRF → 账户接管）
- 每条链的成功概率评估
- Flag 获取路径假设

### 7. 修复优先级
| 优先级 | 项目 | 修复动作 |
|--------|------|----------|
| P0 | ... | ... |
| P1 | ... | ... |
| P2 | ... | ... |

### 8. 附录
- 子域名完整清单
- 参考文档链接
- 生成文件索引

## 写作规范
- 使用中文
- 保留英文术语：域名、CVE/CWE 编号、HTTP 方法、工具名
- 代码/Payload 用 fenced code block
- 表格用 Markdown 表格
- 不要缩写内容 — 该流水线产出的是交付物，不是草稿`,
  { label: '最终报告', phase: '阶段五：综合报告生成' },
)

return {
  domain,
  caseDir,
  stages: {
    recon,
    dos: dosResult,
    vuln,
    verify: verifyResult,
  },
  finalReport,
  generatedAt: 'pipeline-executed',  // 由执行环境填充实际时间
  skipped: {
    dos: skipDos,
    verify: skipVerify,
  },
}
