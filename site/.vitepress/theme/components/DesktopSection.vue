<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'
import { desktopFeatures, desktopConfig } from '../data/desktop'

const { lang } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const t = computed(() => ({
  title: isEn.value ? 'ReverseLab Desktop — Visual Canvas IDE' : 'ReverseLab Desktop 可视化逆向分析台',
  desc: isEn.value
    ? 'Next-generation desktop workbench powered by Tauri v2, React 19, and LangGraph: visual canvas orchestration, live execution telemetry, and local toolchain bridges.'
    : '基于 Tauri v2、React 19 与 LangGraph 的新一代桌面逆向工作台：可视化拓扑编排、实时状态遥测与本地工具链无缝桥接。',
  branchNotice: isEn.value ? 'BRANCH: dev' : '开发分支: dev',
  branchTip: isEn.value
    ? 'Active development branch: dev. Follow instructions below to test locally.'
    : '桌面版图形工作台当前在 dev 分支活跃开发中，本地测试请检出 dev 分支。',
  cta: isEn.value ? 'View Desktop on dev branch' : '前往 dev 分支查看 Desktop 源码',
}))
</script>

<template>
  <section id="desktop-workbench" class="rl-section" aria-labelledby="desktop-title">
    <div class="rl-section-header">
      <div>
        <div class="rl-header-badge-row">
          <h2 id="desktop-title" class="rl-section-title">{{ t.title }}</h2>
          <span class="rl-branch-badge">{{ t.branchNotice }}</span>
        </div>
        <p class="rl-section-desc">{{ t.desc }} {{ t.branchTip }}</p>
      </div>
    </div>

    <div class="rl-desktop-card">
      <div class="rl-desktop-preview">
        <div class="rl-desktop-mockup-header">
          <div class="rl-term-dots">
            <span></span><span></span><span></span>
          </div>
          <div class="rl-desktop-mockup-title">ReverseLab Desktop — Canvas Graph (branch: dev · Tauri v2 · React 19)</div>
          <span class="rl-mockup-badge">● DEV BRANCH</span>
        </div>

        <!-- Stylized Flow Graph Representation -->
        <div class="rl-canvas-mockup">
          <div class="rl-node rl-node-input">
            <span class="rl-node-badge">INPUT</span>
            <div class="rl-node-title">sample_target.bin</div>
            <div class="rl-node-sub">Hash: 8f3c...b219</div>
          </div>
          <div class="rl-canvas-arrow">──▶</div>

          <div class="rl-node rl-node-stage">
            <span class="rl-node-badge">STAGE 01</span>
            <div class="rl-node-title">Static Triage</div>
            <div class="rl-node-sub">DiE / Entropy / Headers</div>
          </div>
          <div class="rl-canvas-arrow">──▶</div>

          <div class="rl-node rl-node-stage">
            <span class="rl-node-badge">STAGE 02</span>
            <div class="rl-node-title">KB Route</div>
            <div class="rl-node-sub">185 Playbooks Match</div>
          </div>
          <div class="rl-canvas-arrow">──▶</div>

          <div class="rl-node rl-node-agent">
            <span class="rl-node-badge">AI AGENT</span>
            <div class="rl-node-title">LangGraph Loop</div>
            <div class="rl-node-sub">Frida Hook & Memory</div>
          </div>
          <div class="rl-canvas-arrow">──▶</div>

          <div class="rl-node rl-node-output">
            <span class="rl-node-badge">EVIDENCE</span>
            <div class="rl-node-title">Closure & Diff</div>
            <div class="rl-node-sub">Python Scaffolds</div>
          </div>
        </div>
      </div>

      <div class="rl-desktop-features">
        <div v-for="feat in desktopFeatures" :key="feat.titleEn" class="rl-desktop-feat-item">
          <h4 class="rl-feat-title">{{ isEn ? feat.titleEn : feat.titleZh }}</h4>
          <p class="rl-feat-desc">{{ isEn ? feat.descEn : feat.descZh }}</p>
        </div>
      </div>

      <div class="rl-desktop-footer">
        <div class="rl-desktop-cmd-wrap">
          <span class="rl-cmd-label">Dev Checkout & Run:</span>
          <code class="rl-desktop-cmd">{{ desktopConfig.runCommand }}</code>
        </div>
        <a class="rl-btn rl-btn-primary" :href="desktopConfig.githubUrl" target="_blank" rel="noopener">
          <span>{{ t.cta }}</span>
        </a>
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
.rl-header-badge-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.rl-branch-badge {
  font-family: var(--rl-font-mono);
  font-size: 11px;
  font-weight: 700;
  color: var(--rl-accent);
  background: var(--rl-accent-soft);
  border: 1px solid oklch(0.580 0.150 65 / 0.3);
  padding: 2px 8px;
  border-radius: 4px;
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
.rl-desktop-card {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  border-radius: 10px;
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}
.rl-desktop-preview {
  background: var(--rl-code-bg);
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid var(--rl-line);
}
.rl-desktop-mockup-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: oklch(0.200 0.020 280);
  padding: 10px 16px;
  border-bottom: 1px solid oklch(0.260 0.020 280);
}
.rl-term-dots {
  display: flex;
  gap: 6px;
}
.rl-term-dots span {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: #64748b;
}
.rl-term-dots span:nth-child(1) { background: #ef4444; }
.rl-term-dots span:nth-child(2) { background: #f59e0b; }
.rl-term-dots span:nth-child(3) { background: #10b981; }

.rl-desktop-mockup-title {
  font-family: var(--rl-font-mono);
  font-size: 12px;
  color: #94a3b8;
}
.rl-mockup-badge {
  font-family: var(--rl-font-mono);
  font-size: 11px;
  color: var(--rl-accent);
  font-weight: 700;
}
.rl-canvas-mockup {
  padding: 24px 20px;
  display: flex;
  align-items: center;
  gap: 12px;
  overflow-x: auto;
}
.rl-node {
  background: oklch(0.220 0.020 280);
  border: 1px solid oklch(0.320 0.030 280);
  border-radius: 6px;
  padding: 10px 14px;
  min-width: 150px;
  flex-shrink: 0;
}
.rl-node-badge {
  font-family: var(--rl-font-mono);
  font-size: 10px;
  font-weight: 700;
  color: #38bdf8;
  display: block;
  margin-bottom: 4px;
}
.rl-node-title {
  color: #f1f5f9;
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 2px;
}
.rl-node-sub {
  color: #94a3b8;
  font-size: 11px;
  font-family: var(--rl-font-mono);
}
.rl-node-agent {
  border-color: var(--rl-primary);
  box-shadow: 0 0 12px oklch(0.420 0.140 278 / 0.4);
}
.rl-node-agent .rl-node-badge {
  color: #c084fc;
}
.rl-canvas-arrow {
  color: #64748b;
  font-family: var(--rl-font-mono);
  font-size: 12px;
  flex-shrink: 0;
}
.rl-desktop-features {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 20px;
}
.rl-desktop-feat-item {
  border-left: 2px solid var(--rl-line);
  padding-left: 14px;
}
.rl-desktop-feat-item:hover {
  border-left-color: var(--rl-primary);
}
.rl-feat-title {
  font-family: var(--rl-font-display);
  font-size: 1rem;
  font-weight: 700;
  color: var(--rl-ink);
  margin: 0 0 6px;
}
.rl-feat-desc {
  font-size: 13px;
  line-height: 1.6;
  color: var(--rl-ink-soft);
  margin: 0;
}
.rl-desktop-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--rl-line);
}
.rl-desktop-cmd-wrap {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.rl-cmd-label {
  font-family: var(--rl-font-mono);
  font-size: 12px;
  color: var(--rl-muted);
}
.rl-desktop-cmd {
  font-family: var(--rl-font-mono);
  font-size: 13px;
  color: var(--rl-ink);
  background: var(--rl-surface-2);
  padding: 6px 12px;
  border-radius: 4px;
  border: 1px solid var(--rl-line);
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
</style>
