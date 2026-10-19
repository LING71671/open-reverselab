<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'

const { lang } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const sysStatus = computed(() => (isEn.value ? 'SYS_STAT: OPERATIONAL' : '系统状态: 运转就绪'))
const agentEngine = computed(() => (isEn.value ? 'AGENT-NATIVE PROTOCOL' : 'AGENT 原生协议'))
const specVerified = computed(() => (isEn.value ? '100% SPEC VERIFIED' : '100% 规则验证'))
</script>

<template>
  <div class="rl-telemetry-bar">
    <div class="rl-telemetry-left">
      <span class="rl-telemetry-dot"></span>
      <span class="rl-telemetry-mono">{{ sysStatus }}</span>
      <span class="rl-telemetry-sep">/</span>
      <span class="rl-telemetry-mono">{{ agentEngine }}</span>
      <span class="rl-telemetry-sep">/</span>
      <span class="rl-telemetry-mono">{{ specVerified }}</span>
    </div>
    <div class="rl-telemetry-right">
      <a class="rl-star-pill" href="https://github.com/LING71671/open-reverselab" target="_blank" rel="noopener">
        <svg class="rl-star-pill-icon" viewBox="0 0 16 16" width="12" height="12" fill="currentColor">
          <path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.75.75 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25z"/>
        </svg>
        <span>Star on GitHub</span>
      </a>
      <span class="rl-telemetry-tag">v1.2.1-PROD</span>
    </div>
  </div>
</template>

<style scoped>
.rl-telemetry-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 16px;
  margin: 16px 0 32px;
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  border-radius: 8px;
  font-family: var(--rl-font-mono);
  font-size: 12px;
  gap: 12px;
  flex-wrap: wrap;
}
.rl-telemetry-left {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.rl-telemetry-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--rl-ok);
  box-shadow: 0 0 6px var(--rl-ok);
  flex-shrink: 0;
}
.rl-telemetry-mono {
  color: var(--rl-ink-soft);
  font-weight: 500;
}
.rl-telemetry-sep {
  color: var(--rl-muted);
}
.rl-telemetry-right {
  display: flex;
  align-items: center;
  gap: 10px;
}
.rl-star-pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  background: var(--rl-bg);
  border: 1px solid var(--rl-line);
  padding: 2px 8px;
  border-radius: 4px;
  font-weight: 600;
  color: var(--rl-ink) !important;
  text-decoration: none !important;
  transition: all 140ms ease;
}
.rl-star-pill:hover {
  border-color: var(--rl-accent);
  color: var(--rl-accent) !important;
}
.rl-star-pill-icon {
  color: var(--rl-accent);
}
.rl-telemetry-tag {
  background: var(--rl-surface-2);
  color: var(--rl-primary);
  padding: 2px 8px;
  border-radius: 4px;
  font-weight: 600;
  border: 1px solid var(--rl-line);
}
</style>
