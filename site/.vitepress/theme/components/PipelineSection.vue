<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'
import { pipelineStages } from '../data/pipeline'

const { lang } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const t = computed(() => ({
  title: isEn.value ? 'End-to-End Autonomous Reversing Loop' : '5 阶闭环逆向工程流水线',
  desc: isEn.value
    ? 'From an unknown binary or challenge URL to a validated proof-of-concept: 5 standardized stages designed for autonomous AI agents and human analysts.'
    : '从未知二进制样本或攻防 URL 到可复现的验证套件：5 个专为 AI Agent 与逆向研究员设计的标准化分析阶段。',
}))
</script>

<template>
  <section class="rl-section" aria-labelledby="pipeline-title">
    <div class="rl-section-header">
      <div>
        <h2 id="pipeline-title" class="rl-section-title">{{ t.title }}</h2>
        <p class="rl-section-desc">{{ t.desc }}</p>
      </div>
    </div>

    <div class="rl-pipeline-grid">
      <div v-for="stage in pipelineStages" :key="stage.num" class="rl-pipeline-card">
        <div class="rl-pipeline-top">
          <span class="rl-pipeline-num">{{ stage.num }}</span>
          <span class="rl-pipeline-tools">{{ stage.tools }}</span>
        </div>
        <h3 class="rl-pipeline-name">{{ isEn ? stage.titleEn : stage.titleZh }}</h3>
        <p class="rl-pipeline-desc">{{ isEn ? stage.descEn : stage.descZh }}</p>
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
.rl-pipeline-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}
.rl-pipeline-card {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  border-radius: 8px;
  padding: 18px;
  display: flex;
  flex-direction: column;
  transition: all 140ms ease;
}
.rl-pipeline-card:hover {
  border-color: var(--rl-primary);
  transform: translateY(-2px);
}
.rl-pipeline-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.rl-pipeline-num {
  font-family: var(--rl-font-mono);
  font-size: 12px;
  font-weight: 700;
  color: var(--rl-accent);
  background: var(--rl-accent-soft);
  padding: 2px 6px;
  border-radius: 4px;
}
.rl-pipeline-tools {
  font-family: var(--rl-font-mono);
  font-size: 11px;
  color: var(--rl-muted);
}
.rl-pipeline-name {
  font-family: var(--rl-font-display);
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--rl-ink);
  margin: 0 0 8px;
}
.rl-pipeline-desc {
  font-size: 12.5px;
  line-height: 1.6;
  color: var(--rl-ink-soft);
  margin: 0;
}
</style>
