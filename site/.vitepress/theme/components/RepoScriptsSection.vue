<script setup lang="ts">
import { ref, computed } from 'vue'
import { useData } from 'vitepress'
import { repoScripts } from '../data/repo-scripts'

const { lang } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const activeScriptFilter = ref<'all' | 'audit' | 'gen' | 'agent'>('all')
const copiedCommand = ref<string | null>(null)

const filteredRepoScripts = computed(() => {
  if (activeScriptFilter.value === 'all') return repoScripts
  return repoScripts.filter(s => s.category === activeScriptFilter.value)
})

const copyToClipboard = async (text: string, id: string) => {
  try {
    await navigator.clipboard.writeText(text)
    copiedCommand.value = id
    setTimeout(() => {
      if (copiedCommand.value === id) copiedCommand.value = null
    }, 2000)
  } catch (e) {
    // fallback
  }
}

const t = computed(() => ({
  scriptsTitle: isEn.value ? 'Repository Maintainer & Automation Tooling' : '仓库内置运维与自动化脚本',
  scriptsDesc: isEn.value
    ? 'Internal utility scripts that everyday users rarely run directly, but guarantee continuous auditing, documentation builds, and autonomous agent loops.'
    : '那些普通用户通常不直接运行、但支撑整个实验环境严谨运转的工程工具（审计校验、站点构建与 Agent 协议自检）。',
  scriptsFilterAll: isEn.value ? 'All Scripts' : '全部脚本',
  scriptsFilterAudit: isEn.value ? 'Audit & Safety' : '审计与安全合规',
  scriptsFilterGen: isEn.value ? 'KB & Site Gen' : '知识库与建站',
  scriptsFilterAgent: isEn.value ? 'Agent & Runner' : 'Agent 协议与自检',
  copyText: isEn.value ? 'Copy Snippet' : '复制命令',
  copiedText: isEn.value ? 'Copied!' : '已复制!',
}))
</script>

<template>
  <section id="repo-tooling" class="rl-section" aria-labelledby="scripts-title">
    <div class="rl-section-header">
      <div>
        <h2 id="scripts-title" class="rl-section-title">{{ t.scriptsTitle }}</h2>
        <p class="rl-section-desc">{{ t.scriptsDesc }}</p>
      </div>
    </div>

    <div class="rl-script-controls">
      <div class="rl-tabs">
        <button
          class="rl-tab-btn"
          :class="{ active: activeScriptFilter === 'all' }"
          @click="activeScriptFilter = 'all'"
        >
          {{ t.scriptsFilterAll }}
        </button>
        <button
          class="rl-tab-btn"
          :class="{ active: activeScriptFilter === 'audit' }"
          @click="activeScriptFilter = 'audit'"
        >
          {{ t.scriptsFilterAudit }}
        </button>
        <button
          class="rl-tab-btn"
          :class="{ active: activeScriptFilter === 'gen' }"
          @click="activeScriptFilter = 'gen'"
        >
          {{ t.scriptsFilterGen }}
        </button>
        <button
          class="rl-tab-btn"
          :class="{ active: activeScriptFilter === 'agent' }"
          @click="activeScriptFilter = 'agent'"
        >
          {{ t.scriptsFilterAgent }}
        </button>
      </div>
    </div>

    <div class="rl-scripts-grid">
      <div v-for="sc in filteredRepoScripts" :key="sc.name" class="rl-script-card">
        <div class="rl-script-top">
          <span
            class="rl-script-badge"
            :class="{
              'badge-audit': sc.category === 'audit',
              'badge-gen': sc.category === 'gen',
              'badge-agent': sc.category === 'agent'
            }"
          >
            {{ isEn ? sc.categoryLabel.en : sc.categoryLabel.zh }}
          </span>
          <span class="rl-script-filename">{{ sc.name }}</span>
        </div>

        <p class="rl-script-desc">{{ isEn ? sc.enDesc : sc.zhDesc }}</p>

        <div class="rl-script-cmd-box">
          <code class="rl-script-cmd-text">{{ sc.cmd }}</code>
          <button class="rl-script-copy-btn" @click="copyToClipboard(sc.cmd, sc.name)" :title="t.copyText">
            <span v-if="copiedCommand === sc.name">{{ t.copiedText }}</span>
            <svg v-else class="rl-copy-icon" viewBox="0 0 16 16" width="12" height="12" fill="currentColor">
              <path d="M0 6.75C0 5.784.784 5 1.75 5h1.5a.75.75 0 0 1 0 1.5h-1.5a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-1.5a.75.75 0 0 1 1.5 0v1.5A1.75 1.75 0 0 1 9.25 16h-7.5A1.75 1.75 0 0 1 0 14.25v-7.5z"/>
              <path d="M5 1.75C5 .784 5.784 0 6.75 0h7.5C15.216 0 16 .784 16 1.75v7.5A1.75 1.75 0 0 1 14.25 11h-7.5A1.75 1.75 0 0 1 5 9.25v-7.5zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h7.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25h-7.5z"/>
            </svg>
          </button>
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
.rl-script-controls {
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
.rl-scripts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 16px;
}
.rl-script-card {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  border-radius: 8px;
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  transition: all 140ms ease;
}
.rl-script-card:hover {
  border-color: var(--rl-primary);
  transform: translateY(-1px);
}
.rl-script-top {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.rl-script-badge {
  font-family: var(--rl-font-mono);
  font-size: 10px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 4px;
  text-transform: uppercase;
}
.badge-audit {
  background: oklch(0.580 0.150 65 / 0.15);
  color: var(--rl-accent);
}
.badge-gen {
  background: oklch(0.420 0.140 278 / 0.15);
  color: var(--rl-primary);
}
.badge-agent {
  background: oklch(0.520 0.140 150 / 0.15);
  color: var(--rl-ok);
}
.rl-script-filename {
  font-family: var(--rl-font-mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--rl-ink);
}
.rl-script-desc {
  font-size: 12.5px;
  line-height: 1.55;
  color: var(--rl-ink-soft);
  margin: 0 0 12px;
  flex-grow: 1;
}
.rl-script-cmd-box {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--rl-surface-2);
  border: 1px solid var(--rl-line);
  padding: 6px 10px;
  border-radius: 5px;
  gap: 8px;
}
.rl-script-cmd-text {
  font-family: var(--rl-font-mono);
  font-size: 11.5px;
  color: var(--rl-ink);
  overflow-x: auto;
  white-space: nowrap;
}
.rl-script-copy-btn {
  background: transparent;
  border: none;
  color: var(--rl-muted);
  cursor: pointer;
  padding: 2px;
  display: flex;
  align-items: center;
  flex-shrink: 0;
  font-size: 11px;
  font-family: var(--rl-font-mono);
}
.rl-script-copy-btn:hover {
  color: var(--rl-primary);
}
</style>
