<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'
import boards from '../boards.json'
import mcpTools from '../mcp-tools.json'

interface Board {
  name: string
  zh: string
  hue: string
  blurb: string
  articles: number
  categories: number
}

interface McpGroup {
  board: string
  tools: string[]
}

const { lang } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const boardList = boards as Record<string, Board>
const boardKeys = Object.keys(boardList)

const mcpGroups = mcpTools as McpGroup[]
const mcpBoardNames: Record<string, Record<string, string>> = {
  'ctf-website': { zh: 'CTF / Web', en: 'CTF / Web' },
  android: { zh: 'Android', en: 'Android' },
  windows: { zh: 'Windows / PE', en: 'Windows / PE' },
  common: { zh: '通用', en: 'Common' },
  misc: { zh: '脚本工具', en: 'Scripts' },
}

// English board blurbs (the generated boards.json only carries Chinese copy).
const enBlurbs: Record<string, string> = {
  'ctf-website': 'JWT / SQLi / SSRF / XSS / CORS / OAuth / CVE / payment attacks — from signal to closed-loop attack network.',
  'apk-reverse': 'DEX / Native / IL2CPP / Frida hooks / unpacking / crypto cracking — from APK to memory.',
  'pe-reverse': 'Ghidra / x64dbg / triage / IOC / YARA / patch / evasion — the full binary lifecycle.',
  general: 'Cryptography / protocol reversing / kernel exploitation / game cheating / firmware / SDR / AI security.',
  windows: 'Windows-specific deep dives: config injection / privilege escalation / process injection.',
}

const totalArticles = Object.values(boardList).reduce((s, b) => s + b.articles, 0)
const totalTools = mcpGroups.reduce((s, g) => s + g.tools.length, 0)

const t = computed(() => ({
  kicker: isEn.value ? 'Open-source reverse engineering lab' : '开源逆向工程实验环境',
  tagline: isEn.value
    ? `Agent-native, conventions as contracts. ${totalArticles} articles, ${totalTools} core tools, 5 analysis boards: from entry signal to evidence loop, every step is runnable.`
    : `Agent 原生，目录即约定。${totalArticles} 篇文章，${totalTools} 个核心工具，5 大分析板块：从入口信号到证据闭环，每一步都能运行。`,
  enterKb: isEn.value ? 'Enter Knowledge Base' : '进入知识库',
  viewGitHub: isEn.value ? 'View on GitHub' : '在 GitHub 上查看',
  stats: isEn.value
    ? `${boardKeys.length} boards · ${totalArticles} articles · ${totalTools} core tools · 100+ MCP tools`
    : `${boardKeys.length} 个板块 · ${totalArticles} 篇文章 · ${totalTools} 个核心工具 · 100+ MCP 工具`,
  boardsTitle: isEn.value ? 'Analysis Boards' : '分析板块',
  boardsDesc: isEn.value
    ? 'Each board is one attack network: entry signal → payload scripts → path forks → evidence loop.'
    : '每个板块一条攻击网：入口信号 → 打点脚本 → 路径分叉 → 证据闭环。',
  articleUnit: isEn.value ? 'articles' : '篇',
  categoryUnit: isEn.value ? 'categories' : '类',
  enterBoard: isEn.value ? 'Enter →' : '进入板块 →',
  mcpTitle: isEn.value ? 'MCP Tool Ecosystem' : 'MCP 工具生态',
  mcpDesc: isEn.value
    ? '100+ MCP tools that AI agents can call directly for automated reversing: capture, unpack, crypto recovery, sample workflows — drive it all from one config.'
    : '100+ MCP 工具，AI Agent 可直接调用做自动化逆向：抓包、脱壳、加密还原、样本工作流，一次配置即可驱动。',
  mcpNote: isEn.value
    ? 'Full tool list and setup: <code>tools/ai-tool-registry.json</code> and <code>.mcp.json</code> in the repo.'
    : '完整工具清单与配置见仓库 <code>tools/ai-tool-registry.json</code> 与 <code>.mcp.json</code>。',
  startTitle: isEn.value ? 'Quick Start' : '快速开始',
  startDesc: isEn.value
    ? 'Clone the repo, generate wrappers, install tools per board. Windows beginners: double-click <code>START_HERE.bat</code>.'
    : '克隆仓库，生成 wrappers，按板块安装工具。Windows 新手先双击 <code>START_HERE.bat</code>。',
}))

const kbPath = (b: string) => `${isEn.value ? '/en' : ''}/kb/${b}/README`
const mcpBoardName = (board: string) => mcpBoardNames[board]?.[isEn.value ? 'en' : 'zh'] ?? board
const blurbOf = (b: Board) => (isEn.value ? enBlurbs[b.name] ?? b.blurb : b.blurb)

const quickStart = `git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
.\\scripts\\misc\\bootstrap.ps1
.\\scripts\\misc\\install_tools.ps1 -CTF      # Web 工具
.\\scripts\\misc\\install_tools.ps1 -Android  # APK 工具
.\\scripts\\misc\\install_tools.ps1 -Windows  # PE 工具
.\\scripts\\misc\\install_tools.ps1 -Common   # Ghidra + Maven`
</script>

<template>
  <div class="rl-home">
    <!-- Hero -->
    <section class="rl-hero">
      <p class="rl-hero-kicker">{{ t.kicker }}</p>
      <h1 class="rl-hero-title">Open-ReverseLab — AI Reverse Engineering Agent &amp; MCP Lab</h1>
      <p class="rl-hero-tagline">
        {{ t.tagline }}
      </p>
      <div class="rl-hero-actions">
        <a class="rl-btn rl-btn-primary" :href="kbPath('ctf-website')">{{ t.enterKb }}</a>
        <a class="rl-btn rl-btn-ghost" href="https://github.com/LING71671/open-reverselab" target="_blank" rel="noopener">{{ t.viewGitHub }}</a>
      </div>
      <div class="rl-hero-stats">
        {{ t.stats }}
      </div>
    </section>

    <!-- Board directory: primary entry -->
    <section class="rl-section" aria-labelledby="boards-title">
      <h2 id="boards-title" class="rl-section-title">{{ t.boardsTitle }}</h2>
      <p class="rl-section-desc">{{ t.boardsDesc }}</p>
      <div class="rl-board-grid">
        <a
          v-for="(b, i) in boardKeys"
          :key="b"
          class="rl-board-card"
          :class="{ 'rl-board-wide': boardKeys.length % 2 === 1 && i === boardKeys.length - 1 }"
          :href="kbPath(b)"
          :style="{ '--bd-hue': boardList[b].hue }"
        >
          <span class="rl-badge" :style="{ color: `hsl(var(--bd-hue) 40% 30%)`, background: `hsl(var(--bd-hue) 55% 96%)` }">
            {{ boardList[b].name }}
          </span>
          <h3>{{ boardList[b].name }}<span v-if="!isEn" class="rl-board-zh">{{ boardList[b].zh }}</span></h3>
          <p class="blurb">{{ blurbOf(boardList[b]) }}</p>
          <div class="meta">
            <span>{{ boardList[b].articles }} {{ t.articleUnit }}</span>
            <span>{{ boardList[b].categories }} {{ t.categoryUnit }}</span>
            <span class="enter">{{ t.enterBoard }}</span>
          </div>
        </a>
      </div>
    </section>

    <!-- MCP ecosystem -->
    <section class="rl-section" aria-labelledby="mcp-title">
      <h2 id="mcp-title" class="rl-section-title">{{ t.mcpTitle }}</h2>
      <p class="rl-section-desc">
        {{ t.mcpDesc }}
      </p>
      <div class="rl-mcp-group" v-for="g in mcpGroups" :key="g.board">
        <h3 class="rl-mcp-group-title">{{ mcpBoardName(g.board) }}</h3>
        <div class="rl-mcp-tools">
          <code v-for="tool in g.tools" :key="tool.id" class="rl-tool">{{ tool.id }}</code>
        </div>
      </div>
      <p class="rl-mcp-note" v-html="t.mcpNote"></p>
    </section>

    <!-- Quick start -->
    <section class="rl-section" aria-labelledby="start-title">
      <h2 id="start-title" class="rl-section-title">{{ t.startTitle }}</h2>
      <p class="rl-section-desc" v-html="t.startDesc"></p>
      <pre class="rl-code"><code>{{ quickStart }}</code></pre>
    </section>
  </div>
</template>

<style scoped>
.rl-home {
  max-width: 1080px;
  margin: 0 auto;
  padding: 0 24px 64px;
}

/* hero */
.rl-hero {
  padding: 72px 0 56px;
  text-align: center;
}
.rl-hero-kicker {
  font-family: var(--rl-font-display);
  font-size: 14px;
  font-weight: 600;
  color: var(--rl-accent);
  margin: 0 0 12px;
}
.rl-hero-title {
  font-family: var(--rl-font-display);
  font-size: clamp(2.75rem, 7vw, 4.5rem);
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1.05;
  margin: 0 0 20px;
  color: var(--rl-ink);
  text-wrap: balance;
}
.rl-hero-tagline {
  max-width: 62ch;
  margin: 0 auto 32px;
  font-size: 1.125rem;
  line-height: 1.7;
  color: var(--rl-ink-soft);
  text-wrap: pretty;
}
.rl-hero-actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  flex-wrap: wrap;
  margin-bottom: 24px;
}
.rl-btn {
  display: inline-flex;
  align-items: center;
  padding: 10px 22px;
  border-radius: 10px;
  font-weight: 600;
  font-size: 15px;
  text-decoration: none !important;
  transition: background-color 160ms ease-out, border-color 160ms ease-out, transform 160ms ease-out;
}
.rl-btn-primary {
  background: var(--rl-primary);
  color: #fff;
}
.rl-btn-primary:hover {
  background: var(--rl-primary-2);
  transform: translateY(-1px);
}
.rl-btn-ghost {
  border: 1px solid var(--rl-line);
  color: var(--rl-ink);
  background: var(--rl-bg);
}
.rl-btn-ghost:hover {
  border-color: var(--rl-primary);
  color: var(--rl-primary);
}
.rl-hero-stats {
  font-size: 14px;
  color: var(--rl-muted);
  font-variant-numeric: tabular-nums;
}

/* sections */
.rl-section {
  padding: 40px 0;
  border-top: 1px solid var(--rl-line);
}
.rl-section-title {
  font-size: 1.5rem;
  font-weight: 700;
  margin: 0 0 8px;
  color: var(--rl-ink);
}
.rl-section-desc {
  color: var(--rl-ink-soft);
  margin: 0 0 24px;
  max-width: 70ch;
}

/* board grid: asymmetric, no identical icon cards */
.rl-board-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 16px;
}
.rl-board-wide {
  grid-column: 1 / -1;
}
.rl-board-card {
  display: flex;
  flex-direction: column;
  gap: 10px;
  border: 1px solid var(--rl-line);
  border-radius: 12px;
  padding: 22px 24px;
  background: var(--rl-bg);
  text-decoration: none !important;
  transition: border-color 180ms ease-out, transform 180ms ease-out;
}
.rl-board-card:hover {
  border-color: hsl(var(--bd-hue) 45% 55%);
  transform: translateY(-2px);
}
.rl-board-card h3 {
  font-family: var(--rl-font-display);
  font-size: 1.125rem;
  font-weight: 700;
  margin: 0;
  display: flex;
  align-items: baseline;
  gap: 10px;
}
.rl-board-zh {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--rl-muted);
}
.rl-board-card .blurb {
  margin: 0;
  color: var(--rl-ink-soft);
  font-size: 0.9rem;
  line-height: 1.65;
  flex: 1;
}
.rl-board-card .meta {
  display: flex;
  align-items: center;
  gap: 16px;
  font-size: 13px;
  color: var(--rl-muted);
  font-variant-numeric: tabular-nums;
}
.rl-board-card .enter {
  margin-left: auto;
  color: hsl(var(--bd-hue) 45% 38%);
  font-weight: 600;
  font-size: 13.5px;
}

/* mcp groups */
.rl-mcp-group {
  margin-bottom: 22px;
}
.rl-mcp-group-title {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--rl-ink-soft);
  margin: 0 0 10px;
  font-family: var(--rl-font-display);
}
.rl-mcp-tools {
  display: flex;
  flex-wrap: wrap;
}
.rl-mcp-note {
  font-size: 13.5px;
  color: var(--rl-muted);
}

/* quick start */
.rl-code {
  background: var(--rl-code-bg);
  color: oklch(0.90 0.01 280);
  border-radius: 12px;
  padding: 20px 24px;
  overflow-x: auto;
  font-size: 13.5px;
  line-height: 1.7;
}

/* entrance: fade-up stagger, default visible, reduced-motion safe */
@media (prefers-reduced-motion: no-preference) {
  .rl-hero, .rl-section {
    animation: rl-fade-up 300ms ease-out both;
  }
  .rl-hero { animation-delay: 0ms; }
  .rl-section:nth-of-type(1) { animation-delay: 60ms; }
  .rl-section:nth-of-type(2) { animation-delay: 120ms; }
  .rl-section:nth-of-type(3) { animation-delay: 180ms; }
}
@keyframes rl-fade-up {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

@media (max-width: 640px) {
  .rl-hero { padding: 48px 0 40px; }
  .rl-board-wide { grid-column: auto; }
}
</style>
