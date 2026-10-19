<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'
import boards from '../../boards.json'
import mcpTools from '../../mcp-tools.json'

const { lang } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const boardList = boards as Record<string, { articles: number }>
const totalArticles = Object.values(boardList).reduce((s, b) => s + b.articles, 0)
const totalTools = (mcpTools as { tools: unknown[] }[]).reduce((s, g) => s + g.tools.length, 0)

const t = computed(() => ({
  kicker: isEn.value ? 'REVERSELAB // DEFENSIVE REVERSE-ENGINEERING BENCH' : 'REVERSELAB // 精密逆向工程实验台',
  title: isEn.value ? 'AI-Native Reverse Engineering & MCP Suite' : '开源逆向工程实验环境与自动化套件',
  tagline: isEn.value
    ? `An executable reverse-engineering lab with ${totalArticles} articles and ${totalTools} core tools across 5 attack networks: from entry signals to memory breakpoints, every technique is test-driven and agent-ready.`
    : `面向研究员与 AI Agent 的可执行逆向实验室：${totalArticles} 篇实战知识库与 ${totalTools} 个自动化工具，覆盖 5 大完整攻防攻击网，从入口信号到内存断点，每步皆可验证。`,
  enterKb: isEn.value ? 'Explore Knowledge Base' : '进入实战知识库',
  mcpExplorer: isEn.value ? 'MCP Tool Matrix' : '查看 MCP 工具生态',
  viewDesktop: isEn.value ? 'Desktop Workbench (dev)' : '桌面工作台 (dev 分支)',
  viewGitHub: isEn.value ? 'GitHub Repository' : 'GitHub 源码仓',
  statsArticles: isEn.value ? 'Executable Articles' : '篇实战手册',
  statsTools: isEn.value ? 'MCP & Core Tools' : '个自动化工具',
  statsBoards: isEn.value ? 'Attack Networks' : '大攻击网板块',
  statsVerified: isEn.value ? 'Test-Driven Playbooks' : '闭环实战打法',
}))

const kbPath = computed(() => `${isEn.value ? '/en' : ''}/kb/ctf-website/README`)
</script>

<template>
  <section class="rl-hero">
    <div class="rl-hero-meta">
      <span class="rl-hero-kicker">{{ t.kicker }}</span>
    </div>
    <h1 class="rl-hero-title">{{ t.title }}</h1>
    <p class="rl-hero-tagline">{{ t.tagline }}</p>

    <div class="rl-hero-actions">
      <a class="rl-btn rl-btn-primary" :href="kbPath">
        <span>{{ t.enterKb }}</span>
        <span class="rl-btn-badge">{{ totalArticles }}</span>
      </a>
      <a class="rl-btn rl-btn-secondary" href="#mcp-ecosystem">
        <span>{{ t.mcpExplorer }}</span>
        <span class="rl-btn-badge rl-badge-accent">{{ totalTools }}+</span>
      </a>
      <a class="rl-btn rl-btn-secondary" href="#desktop-workbench">
        <span>{{ t.viewDesktop }}</span>
      </a>
      <a class="rl-btn rl-btn-ghost" href="https://github.com/LING71671/open-reverselab" target="_blank" rel="noopener">
        <svg class="rl-icon" viewBox="0 0 16 16" width="16" height="16" fill="currentColor">
          <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
        </svg>
        <span>{{ t.viewGitHub }}</span>
      </a>
    </div>

    <!-- Instrument Gauges -->
    <div class="rl-gauge-grid">
      <div class="rl-gauge-card">
        <div class="rl-gauge-val">{{ totalArticles }}</div>
        <div class="rl-gauge-lbl">{{ t.statsArticles }}</div>
      </div>
      <div class="rl-gauge-card">
        <div class="rl-gauge-val">{{ totalTools }}+</div>
        <div class="rl-gauge-lbl">{{ t.statsTools }}</div>
      </div>
      <div class="rl-gauge-card">
        <div class="rl-gauge-val">5</div>
        <div class="rl-gauge-lbl">{{ t.statsBoards }}</div>
      </div>
      <div class="rl-gauge-card">
        <div class="rl-gauge-val">100%</div>
        <div class="rl-gauge-lbl">{{ t.statsVerified }}</div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.rl-hero {
  padding: 24px 0 48px;
  text-align: left;
}
.rl-hero-meta {
  margin-bottom: 16px;
}
.rl-hero-kicker {
  font-family: var(--rl-font-mono);
  font-size: 13px;
  font-weight: 600;
  color: var(--rl-accent);
  letter-spacing: 0.05em;
  background: var(--rl-accent-soft);
  padding: 4px 10px;
  border-radius: 4px;
  border: 1px solid oklch(0.580 0.150 65 / 0.2);
}
.rl-hero-title {
  font-family: var(--rl-font-display);
  font-size: clamp(2.4rem, 5vw, 4rem);
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1.15;
  margin: 0 0 20px;
  color: var(--rl-ink);
  text-wrap: balance;
}
.rl-hero-tagline {
  max-width: 72ch;
  font-size: 1.125rem;
  line-height: 1.7;
  color: var(--rl-ink-soft);
  margin-bottom: 32px;
  text-wrap: pretty;
}
.rl-hero-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 44px;
}
.rl-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 18px;
  border-radius: 8px;
  font-weight: 600;
  font-size: 14px;
  text-decoration: none !important;
  transition: all 160ms ease-out;
}
.rl-btn-primary {
  background: var(--rl-primary);
  color: #fff !important;
  border: 1px solid var(--rl-primary);
}
.rl-btn-primary:hover {
  background: var(--rl-primary-2);
  transform: translateY(-1px);
}
.rl-btn-secondary {
  background: var(--rl-surface);
  color: var(--rl-ink) !important;
  border: 1px solid var(--rl-line);
}
.rl-btn-secondary:hover {
  border-color: var(--rl-primary);
  color: var(--rl-primary) !important;
}
.rl-btn-ghost {
  border: 1px solid var(--rl-line);
  color: var(--rl-muted) !important;
  background: transparent;
}
.rl-btn-ghost:hover {
  border-color: var(--rl-ink-soft);
  color: var(--rl-ink) !important;
}
.rl-btn-badge {
  background: rgba(255, 255, 255, 0.2);
  color: #fff;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 12px;
  font-family: var(--rl-font-mono);
}
.rl-badge-accent {
  background: var(--rl-accent-soft);
  color: var(--rl-accent);
}

/* Gauge Cards */
.rl-gauge-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--rl-line);
}
.rl-gauge-card {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  padding: 16px 20px;
  border-radius: 8px;
}
.rl-gauge-val {
  font-family: var(--rl-font-mono);
  font-size: 2rem;
  font-weight: 700;
  color: var(--rl-ink);
  line-height: 1.1;
  margin-bottom: 4px;
}
.rl-gauge-lbl {
  font-size: 13px;
  color: var(--rl-muted);
  font-weight: 500;
}
</style>
