<script setup lang="ts">
import { computed, ref } from 'vue'
import { useData } from 'vitepress'
import mcpTools from '../mcp-tools.json'
import SelectField from './SelectField.vue'
const { lang } = useData()
const en = computed(() => lang.value.startsWith('en'))
const query = ref('')
const board = ref('')
const domains = computed(() => [{ value: '', label: en.value ? 'All domains' : '所有领域' }, ...mcpTools.map(group => ({ value: group.board, label: group.board }))])
const groups = computed(() => mcpTools.filter(g => !board.value || g.board === board.value).map(g => ({ ...g, tools: g.tools.filter(t => `${t.id} ${t.name} ${t.notes}`.toLowerCase().includes(query.value.trim().toLowerCase())) })).filter(g => g.tools.length))
</script>
<template>
  <div class="rl-tools">
    <h1>{{ en ? 'Tool registry' : '工具目录' }}</h1>
    <p>{{ en ? 'Tools registered in the repository and their integration methods. AI-callable is a registry attribute; installed dependencies and readiness must be checked on your machine.' : '查看仓库登记的工具和接入方式。AI 可调用是注册表属性，安装情况和可用性需要在本机检查。' }}</p>
    <p><a href="https://github.com/LING71671/open-reverselab/blob/main/tools/ai-tool-registry.json">{{ en ? 'Registry source' : '注册表源码' }}</a> · <a href="https://github.com/LING71671/open-reverselab/blob/main/tools/skills/mcp/ReverseLabToolsMCP/README.md">{{ en ? 'MCP service setup' : 'MCP 服务配置' }}</a></p>
    <div class="rl-tool-filters"><label>{{ en ? 'Search tools' : '搜索工具' }}<input type="search" v-model="query" :placeholder="en ? 'Name, ID or description' : '名称、ID 或说明'" /></label><SelectField id="tool-domain" v-model="board" :label="en ? 'Domain' : '领域'" :options="domains" /></div>
    <p v-if="!groups.length" role="status">{{ en ? 'No tools match this search.' : '没有匹配的工具。' }} <button class="rl-text-link" @click="query = ''; board = ''">{{ en ? 'Clear filters' : '清除筛选' }}</button></p>
    <section v-for="g in groups" :key="g.board"><h2>{{ g.board }} <small>{{ g.tools.length }}</small></h2><details v-for="tool in g.tools" :key="tool.id"><summary><span><strong>{{ tool.name }}</strong><code>{{ tool.id }}</code></span><span class="rl-tool-method">{{ tool.ai_callable ? (en ? 'AI-callable' : 'AI 可调用') : (en ? 'Manual' : '手动') }}</span></summary><div><p>{{ tool.notes }}</p><p>{{ en ? 'Integration' : '接入方式' }}: <code>{{ tool.launch_mode }}</code></p></div></details></section>
  </div>
</template>
<style scoped>
.rl-tools { max-width: 1000px; margin: auto; padding: 48px 24px 80px; }
h1 { font-size: 36px; line-height: 1.2; font-weight: 750; letter-spacing: -.025em; }
p { margin: 18px 0; line-height: 1.8; color: var(--rl-ink-soft); max-width: 75ch; }
a { text-decoration: underline; }
.rl-tool-filters { display: flex; gap: 20px; margin: 32px 0; }
label { display: grid; gap: 8px; font-size: 14px; flex: 1; }
.rl-tool-filters > * { flex: 1; min-width: 0; }
input { min-height: 44px; padding: 10px 12px; border: 1px solid var(--rl-line); border-radius: 6px; color: var(--rl-ink); background: var(--rl-bg); width: 100%; }
input::placeholder { color: var(--rl-muted); }
section { margin-top: 36px; } h2 { font-size: 22px; font-weight: 700; margin-bottom: 14px; }
h2 small { font-size: 14px; color: var(--rl-muted); margin-left: 8px; font-variant-numeric: tabular-nums; }
details { border-top: 1px solid var(--rl-line); }
summary { display: flex; justify-content: space-between; gap: 24px; align-items: center; padding: 18px 4px; cursor: pointer; }
summary strong { display: block; font-size: 16px; } summary code { font-size: 12px; color: var(--rl-muted); overflow-wrap: anywhere; }
.rl-tool-method { flex-shrink: 0; color: var(--rl-muted); font-size: 13px; }
details[open] summary { background: var(--rl-surface); padding-inline: 12px; } details > div { padding: 0 12px 10px; }
@media(max-width: 600px) { .rl-tool-filters { flex-direction: column; } h1 { font-size: 30px; } }
</style>
