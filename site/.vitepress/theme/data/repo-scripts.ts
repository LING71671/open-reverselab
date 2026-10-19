export interface RepoScript {
  name: string
  cmd: string
  category: 'audit' | 'gen' | 'agent'
  categoryLabel: { zh: string; en: string }
  zhDesc: string
  enDesc: string
}

export const repoScripts: RepoScript[] = [
  {
    name: 'public_release_check.py',
    cmd: 'python scripts/misc/public_release_check.py',
    category: 'audit',
    categoryLabel: { zh: '发布审计', en: 'Release Audit' },
    zhDesc: '开源公开发布红线审计：递归扫描全仓敏感文件、私有 case、明文凭据与本机绝对路径。',
    enDesc: 'Pre-release security scan: detects sensitive samples, private cases, tokens, and absolute paths.',
  },
  {
    name: 'kb_doc_audit.py',
    cmd: 'python scripts/misc/kb_doc_audit.py',
    category: 'audit',
    categoryLabel: { zh: '规范审计', en: 'Doc Standard' },
    zhDesc: '合规性扫描：校验 185 篇实战知识库的文章结构、标题层级、可运行代码块与 MCP 映射表。',
    enDesc: 'Validates structure, headings, runnable code snippets, and MCP tool mapping tables across 185 articles.',
  },
  {
    name: 'check_dead_links.py',
    cmd: 'python scripts/misc/check_dead_links.py',
    category: 'audit',
    categoryLabel: { zh: '死链扫描', en: 'Link Linter' },
    zhDesc: '全库链接检查：扫描 Markdown 跨板块跳转与内部引用，确保所有 relative link 100% 存在且有效。',
    enDesc: 'Dead-link scanner for Markdown cross-references and internal relative links.',
  },
  {
    name: 'seo_audit.py',
    cmd: 'python scripts/misc/seo_audit.py',
    category: 'audit',
    categoryLabel: { zh: '元数据审计', en: 'SEO Audit' },
    zhDesc: '站点元数据检查：校验每篇文章与板块页面的标题、描述、OpenGraph 标签与搜索引擎索引规范。',
    enDesc: 'Audits page titles, descriptions, and OpenGraph tags to ensure indexing compliance.',
  },
  {
    name: 'gen_vitepress_sidebar.py',
    cmd: 'python scripts/misc/gen_vitepress_sidebar.py',
    category: 'gen',
    categoryLabel: { zh: '目录生成', en: 'Sidebar Gen' },
    zhDesc: '自动化建站核心：扫描 kb/ 目录，自动生成 VitePress sidebar.ts、boards.json 与 mcp-tools.json。',
    enDesc: 'Scans kb/ directory to auto-generate VitePress sidebar tree, boards.json, and tool catalogs.',
  },
  {
    name: 'generate_llms_txt.py',
    cmd: 'python scripts/misc/generate_llms_txt.py',
    category: 'gen',
    categoryLabel: { zh: 'LLMs 标准', en: 'LLMs.txt' },
    zhDesc: '按标准输出 /llms.txt 与 /llms-full.txt，便于外部大模型及 Agent 工具高速摄取全库逆向知识。',
    enDesc: 'Generates standard /llms.txt and /llms-full.txt specs for AI agents and LLM ingestion.',
  },
  {
    name: 'gen_social_preview.py',
    cmd: 'python scripts/misc/gen_social_preview.py',
    category: 'gen',
    categoryLabel: { zh: '视觉卡片', en: 'Social Card' },
    zhDesc: '基于纯 Python 渲染生成 1200×630 官网社交分享预览图（白底、深靛标题与 5 大板块徽章）。',
    enDesc: 'Automates generation of 1200x630 social preview card for OpenGraph sharing.',
  },
  {
    name: 'add_frontmatter.py',
    cmd: 'python scripts/misc/add_frontmatter.py',
    category: 'gen',
    categoryLabel: { zh: '元数据补齐', en: 'Frontmatter' },
    zhDesc: '批量为缺少 YAML 头的文档自动补充 title 与 description，确保站点渲染与检索无断裂。',
    enDesc: 'Batches YAML frontmatter completion for all markdown documentation files.',
  },
  {
    name: 'fix_kb_links.py',
    cmd: 'python scripts/misc/fix_kb_links.py',
    category: 'gen',
    categoryLabel: { zh: '路径校正', en: 'Path Fixer' },
    zhDesc: '全自动校正知识库历史相对链接，保持本地 Git 查看与 VitePress Web 站内跳转一致。',
    enDesc: 'Automatically realigns historical relative paths across knowledge-base documents.',
  },
  {
    name: 'setup_unattended_ctf_runner.py',
    cmd: 'python scripts/misc/setup_unattended_ctf_runner.py --overwrite',
    category: 'agent',
    categoryLabel: { zh: '无人值守', en: 'Unattended' },
    zhDesc: '一键配置本地 Codex 及 Claude Code 权限，赋予 24h 自动化长跑打靶的本地执行审批协议。',
    enDesc: 'Sets up local runner permissions for unattended 24h autonomous loops in Codex and Claude Code.',
  },
  {
    name: 'mcp_smoke_check.py',
    cmd: 'python scripts/misc/mcp_smoke_check.py',
    category: 'agent',
    categoryLabel: { zh: 'MCP 冒烟', en: 'MCP Smoke' },
    zhDesc: '真实启动 reverse_lab_tools 服务端并调用核心逆向工具，验证 JSON-RPC 通信协议与响应。',
    enDesc: 'Spawns reverse_lab_tools MCP server and fires test calls to verify protocol compliance.',
  },
  {
    name: 'ai_toolcheck.py',
    cmd: 'python scripts/misc/ai_toolcheck.py',
    category: 'agent',
    categoryLabel: { zh: '工具链探测', en: 'Tool Probe' },
    zhDesc: '深度探测本机逆向生态（Ghidra, Frida, x64dbg, rizin, apktool, lief, capstone 等）可用性。',
    enDesc: 'Probes local reversing toolchain readiness (Ghidra, Frida, x64dbg, rizin, lief, capstone).',
  },
  {
    name: 'verify_codex_ctf_profile.ps1',
    cmd: 'powershell -ExecutionPolicy Bypass -File scripts/misc/verify_codex_ctf_profile.ps1',
    category: 'agent',
    categoryLabel: { zh: 'Codex 预检', en: 'Codex Check' },
    zhDesc: '校验 Codex CTF 执行环境配置、系统环境变量及 Python 逆向库完备度。',
    enDesc: 'Verifies Codex environment variables, tool configurations, and Python reverse dependencies.',
  },
  {
    name: 'triage_target.py',
    cmd: 'python scripts/misc/triage_target.py <file>',
    category: 'agent',
    categoryLabel: { zh: '命令行初筛', en: 'CLI Triage' },
    zhDesc: '无头快速初筛脚本：自动计算哈希、检查格式头、解析导入表并在几秒内输出初步研判结论。',
    enDesc: 'Headless triage engine: hashes, format inspection, imports analysis, and instant summary.',
  },
  {
    name: 'new_task.py',
    cmd: 'python scripts/misc/new_task.py --board <board> --case <name>',
    category: 'agent',
    categoryLabel: { zh: '任务脚手架', en: 'Task Scaffold' },
    zhDesc: '快速按"目录即约定"规范生成新任务骨架：包含标准 cases/、notes/、exports/ 与 reports/ 目录。',
    enDesc: 'Scaffolds a new analysis task strictly following directory-as-convention standards.',
  },
]
