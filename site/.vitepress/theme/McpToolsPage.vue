<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'
import mcpTools from '../mcp-tools.json'

interface McpTool {
  id: string
  name: string
  launch_mode: string
  ai_callable: boolean
  notes: string
}

interface McpGroup {
  board: string
  tools: McpTool[]
}

const { lang } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const groups = mcpTools as McpGroup[]

const boardNames: Record<string, Record<string, string>> = {
  'ctf-website': { zh: 'CTF / Web', en: 'CTF / Web' },
  android: { zh: 'Android', en: 'Android' },
  windows: { zh: 'Windows / PE', en: 'Windows / PE' },
  common: { zh: '通用', en: 'Common' },
  misc: { zh: '脚本工具', en: 'Scripts' },
}

const total = groups.reduce((s, g) => s + g.tools.length, 0)
const aiCallable = groups.reduce((s, g) => s + g.tools.filter((t) => t.ai_callable).length, 0)

const t = computed(() => ({
  title: isEn.value ? 'MCP Tools Directory' : 'MCP 工具目录',
  desc: isEn.value
    ? `${total} core tools, ${aiCallable} marked AI-callable. Configure via <code>tools/ai-tool-registry.json</code> and <code>.mcp.json</code> in the repo; the full 100+ tool set is verified by <code>mcp_smoke_check.py</code>.`
    : `${total} 个核心工具，${aiCallable} 个标记为 AI 可调用。配置见仓库 <code>tools/ai-tool-registry.json</code> 与 <code>.mcp.json</code>；完整 100+ 工具集由 <code>mcp_smoke_check.py</code> 验证。`,
  manual: isEn.value ? 'Manual' : '手动',
}))

const boardName = (board: string) => boardNames[board]?.[isEn.value ? 'en' : 'zh'] ?? board
</script>

<template>
  <div class="rl-tools">
    <header class="rl-tools-hero">
      <h1>{{ t.title }}</h1>
      <p v-html="t.desc"></p>
    </header>

    <section v-for="g in groups" :key="g.board" class="rl-tools-group">
      <h2>{{ boardName(g.board) }}<span class="rl-count">{{ g.tools.length }}</span></h2>
      <div class="rl-tools-grid">
        <div v-for="tool in g.tools" :key="tool.id" class="rl-tool-card">
          <div class="rl-tool-head">
            <code>{{ tool.id }}</code>
            <span class="rl-badge" :class="tool.ai_callable ? 'is-ai' : 'is-manual'">
              {{ tool.ai_callable ? 'AI' : t.manual }}
            </span>
          </div>
          <div class="rl-tool-name">{{ tool.name }}</div>
          <div class="rl-tool-mode">{{ tool.launch_mode }}</div>
          <p v-if="tool.notes">{{ tool.notes }}</p>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.rl-tools {
  max-width: 1000px;
  margin: 0 auto;
  padding: 32px 24px 64px;
}
.rl-tools-hero h1 {
  font-family: var(--rl-font-display);
  font-size: 2rem;
  letter-spacing: -0.02em;
  margin: 0 0 10px;
}
.rl-tools-hero p {
  color: var(--rl-ink-soft);
  max-width: 72ch;
  line-height: 1.7;
}
.rl-tools-group {
  margin-top: 36px;
}
.rl-tools-group h2 {
  font-family: var(--rl-font-display);
  font-size: 1.15rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 0 0 14px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--rl-line);
}
.rl-count {
  font-family: var(--rl-font-mono);
  font-size: 0.8rem;
  color: var(--rl-muted);
  background: var(--rl-surface);
  border-radius: 999px;
  padding: 1px 9px;
}
.rl-tools-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 12px;
}
.rl-tool-card {
  border: 1px solid var(--rl-line);
  border-radius: 10px;
  padding: 14px 16px;
  background: var(--rl-bg);
}
.rl-tool-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.rl-tool-head code {
  font-family: var(--rl-font-mono);
  font-size: 12.5px;
  color: var(--rl-primary);
  overflow-wrap: anywhere;
}
.rl-badge {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 999px;
  white-space: nowrap;
}
.rl-badge.is-ai {
  background: var(--rl-primary-soft);
  color: var(--rl-primary);
}
.rl-badge.is-manual {
  background: var(--rl-surface-2);
  color: var(--rl-muted);
}
.rl-tool-name {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--rl-ink);
  margin-top: 8px;
}
.rl-tool-mode {
  font-family: var(--rl-font-mono);
  font-size: 11.5px;
  color: var(--rl-muted);
  margin-top: 2px;
}
.rl-tool-card p {
  font-size: 12.5px;
  color: var(--rl-ink-soft);
  line-height: 1.6;
  margin: 8px 0 0;
}
</style>
