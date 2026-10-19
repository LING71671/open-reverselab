<script setup lang="ts">
import { ref, computed } from 'vue'
import { useData } from 'vitepress'
import mcpTools from '../../mcp-tools.json'

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

const mcpGroups = mcpTools as McpGroup[]
const mcpBoardNames: Record<string, Record<string, string>> = {
  'ctf-website': { zh: 'CTF / Web 攻防', en: 'CTF / Web' },
  android: { zh: 'Android 逆向', en: 'Android Reversing' },
  windows: { zh: 'Windows / PE 二进制', en: 'Windows / PE' },
  common: { zh: '通用逆向工具链', en: 'Core Toolchain' },
  misc: { zh: '自动化脚本工具', en: 'Automation Scripts' },
}

const activeMcpTab = ref<string>('all')
const mcpSearchQuery = ref<string>('')
const selectedTool = ref<McpTool | null>(mcpGroups[0]?.tools[0] || null)

const filteredMcpGroups = computed(() => {
  return mcpGroups
    .filter(g => activeMcpTab.value === 'all' || g.board === activeMcpTab.value)
    .map(g => ({
      ...g,
      tools: g.tools.filter(t => {
        const q = mcpSearchQuery.value.trim().toLowerCase()
        if (!q) return true
        return t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
      })
    }))
    .filter(g => g.tools.length > 0)
})

const selectTool = (tool: McpTool) => {
  selectedTool.value = tool
}

const mcpBoardName = (board: string) => mcpBoardNames[board]?.[isEn.value ? 'en' : 'zh'] ?? board

const t = computed(() => ({
  mcpTitle: isEn.value ? 'Agent MCP Tool Ecosystem' : 'Agent 原生 MCP 工具矩阵',
  mcpDesc: isEn.value
    ? 'Standardized tools that autonomous AI agents (Codex, Claude Code) call directly to execute triage, static analysis, hook deployment, and crypto recovery.'
    : '标准化逆向自动化工具库，支持 AI Agent（Codex、Claude Code）直连调用，自动完成初筛、静态解包、Frida Hook 与加密还原。',
  mcpSearchPlaceholder: isEn.value ? 'Filter tools by name or id...' : '过滤工具名称或标识符...',
  allTabs: isEn.value ? 'All Boards' : '全板块',
  toolInspectorTitle: isEn.value ? 'Agent Invocation Inspector' : 'AI Agent 调用示意',
}))
</script>

<template>
  <section id="mcp-ecosystem" class="rl-section" aria-labelledby="mcp-title">
    <div class="rl-section-header">
      <div>
        <h2 id="mcp-title" class="rl-section-title">{{ t.mcpTitle }}</h2>
        <p class="rl-section-desc">{{ t.mcpDesc }}</p>
      </div>
    </div>

    <!-- Controls: Tabs + Filter -->
    <div class="rl-mcp-controls">
      <div class="rl-tabs">
        <button
          class="rl-tab-btn"
          :class="{ active: activeMcpTab === 'all' }"
          @click="activeMcpTab = 'all'"
        >
          {{ t.allTabs }}
        </button>
        <button
          v-for="g in mcpGroups"
          :key="g.board"
          class="rl-tab-btn"
          :class="{ active: activeMcpTab === g.board }"
          @click="activeMcpTab = g.board"
        >
          {{ mcpBoardName(g.board) }}
        </button>
      </div>

      <div class="rl-search-box">
        <input
          v-model="mcpSearchQuery"
          type="text"
          class="rl-search-input"
          :placeholder="t.mcpSearchPlaceholder"
        />
      </div>
    </div>

    <!-- Split Layout: Tool Catalog + Inspector -->
    <div class="rl-mcp-workbench">
      <div class="rl-mcp-catalog">
        <div v-for="g in filteredMcpGroups" :key="g.board" class="rl-mcp-group-block">
          <div class="rl-group-badge">{{ mcpBoardName(g.board) }} ({{ g.tools.length }})</div>
          <div class="rl-tools-wrap">
            <button
              v-for="tool in g.tools"
              :key="tool.id"
              class="rl-tool-pill"
              :class="{ active: selectedTool?.id === tool.id }"
              @click="selectTool(tool)"
            >
              <span class="rl-tool-dot" :class="{ 'ai-ready': tool.ai_callable }"></span>
              <span class="rl-tool-name">{{ tool.id }}</span>
              <span class="rl-tool-mode">{{ tool.launch_mode }}</span>
            </button>
          </div>
        </div>
      </div>

      <!-- Tool Detail / Protocol Inspector -->
      <div class="rl-mcp-inspector">
        <div class="rl-inspector-header">
          <span class="rl-inspector-title">{{ t.toolInspectorTitle }}</span>
          <span v-if="selectedTool" class="rl-status-pill">● ACTIVE</span>
        </div>

        <div v-if="selectedTool" class="rl-inspector-body">
          <div class="rl-inspector-row">
            <span class="lbl">TOOL ID:</span>
            <code class="val">{{ selectedTool.id }}</code>
          </div>
          <div class="rl-inspector-row">
            <span class="lbl">NAME:</span>
            <span class="val">{{ selectedTool.name }}</span>
          </div>
          <div class="rl-inspector-row">
            <span class="lbl">CALLABLE:</span>
            <span class="val">{{ selectedTool.ai_callable ? 'YES (AI Agent Ready)' : 'NO' }}</span>
          </div>
          <div class="rl-inspector-row">
            <span class="lbl">EXEC_MODE:</span>
            <span class="val">{{ selectedTool.launch_mode.toUpperCase() }}</span>
          </div>
          <div class="rl-inspector-code">
            <div class="rl-code-label">Agent JSON-RPC Payload:</div>
            <pre><code>{{ JSON.stringify({
  "server": "reverse_lab_tools",
  "tool": selectedTool.id,
  "arguments": {
    "target": "sample.bin",
    "mode": selectedTool.launch_mode
  }
}, null, 2) }}</code></pre>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.rl-section {
  padding: 56px 0 24px;
  border-top: 1px solid var(--rl-line);
}
.rl-section-header {
  margin-bottom: 28px;
}
.rl-section-title {
  font-family: var(--rl-font-display);
  font-size: 1.75rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--rl-ink);
  margin: 0 0 8px;
}
.rl-section-desc {
  font-size: 1rem;
  color: var(--rl-ink-soft);
  margin: 0;
  max-width: 80ch;
}
.rl-mcp-controls {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  margin-bottom: 20px;
}
.rl-tabs {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.rl-tab-btn {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  color: var(--rl-ink-soft);
  padding: 6px 14px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 140ms ease;
}
.rl-tab-btn:hover {
  color: var(--rl-ink);
  border-color: var(--rl-muted);
}
.rl-tab-btn.active {
  background: var(--rl-primary);
  border-color: var(--rl-primary);
  color: #fff;
}
.rl-search-input {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  border-radius: 6px;
  padding: 6px 12px;
  font-size: 13px;
  color: var(--rl-ink);
  width: 240px;
  outline: none;
}
.rl-search-input:focus {
  border-color: var(--rl-primary);
}
.rl-mcp-workbench {
  display: grid;
  grid-template-columns: 1fr 380px;
  gap: 20px;
}
@media (max-width: 960px) {
  .rl-mcp-workbench {
    grid-template-columns: 1fr;
  }
}
.rl-mcp-catalog {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  border-radius: 8px;
  padding: 20px;
  max-height: 480px;
  overflow-y: auto;
}
.rl-mcp-group-block {
  margin-bottom: 20px;
}
.rl-mcp-group-block:last-child {
  margin-bottom: 0;
}
.rl-group-badge {
  font-family: var(--rl-font-mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--rl-muted);
  text-transform: uppercase;
  margin-bottom: 10px;
}
.rl-tools-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.rl-tool-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--rl-bg);
  border: 1px solid var(--rl-line);
  border-radius: 6px;
  padding: 5px 10px;
  font-family: var(--rl-font-mono);
  font-size: 12px;
  color: var(--rl-ink);
  cursor: pointer;
  transition: all 120ms ease;
}
.rl-tool-pill:hover {
  border-color: var(--rl-primary);
}
.rl-tool-pill.active {
  border-color: var(--rl-primary);
  background: var(--rl-primary-soft);
  color: var(--rl-primary);
  font-weight: 600;
}
.rl-tool-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--rl-muted);
}
.rl-tool-dot.ai-ready {
  background: var(--rl-ok);
}
.rl-tool-mode {
  font-size: 10px;
  background: var(--rl-surface-2);
  padding: 1px 4px;
  border-radius: 3px;
  color: var(--rl-muted);
}
.rl-mcp-inspector {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  border-radius: 8px;
  padding: 20px;
  display: flex;
  flex-direction: column;
}
.rl-inspector-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--rl-line);
  padding-bottom: 12px;
  margin-bottom: 16px;
}
.rl-inspector-title {
  font-family: var(--rl-font-mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--rl-ink);
}
.rl-status-pill {
  font-family: var(--rl-font-mono);
  font-size: 11px;
  color: var(--rl-ok);
  font-weight: 600;
}
.rl-inspector-row {
  display: flex;
  justify-content: space-between;
  font-size: 13px;
  margin-bottom: 10px;
}
.rl-inspector-row .lbl {
  font-family: var(--rl-font-mono);
  font-size: 11px;
  color: var(--rl-muted);
}
.rl-inspector-row .val {
  font-weight: 500;
  color: var(--rl-ink);
}
.rl-inspector-code {
  margin-top: 14px;
}
.rl-code-label {
  font-family: var(--rl-font-mono);
  font-size: 11px;
  color: var(--rl-muted);
  margin-bottom: 6px;
}
.rl-inspector-code pre {
  background: var(--rl-code-bg);
  color: #f1f5f9;
  padding: 12px;
  border-radius: 6px;
  font-size: 12px;
  margin: 0;
  overflow-x: auto;
}
</style>
