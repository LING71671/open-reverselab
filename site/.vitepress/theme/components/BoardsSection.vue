<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'
import boards from '../../boards.json'

interface Board {
  name: string
  zh: string
  hue: string
  blurb: string
  articles: number
  categories: number
}

const { lang } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const boardList = boards as Record<string, Board>
const boardKeys = Object.keys(boardList)

const enBlurbs: Record<string, string> = {
  'ctf-website': 'JWT / SQLi / SSRF / XSS / CORS / OAuth / CVE / payment exploits — verified closed-loop attack graph.',
  'apk-reverse': 'DEX / Native / IL2CPP / Frida hooks / unpacking / crypto cracking — memory to disassembled code.',
  'pe-reverse': 'Ghidra / x64dbg / triage / IOC / YARA / patching / evasion — full binary reverse lifecycle.',
  general: 'Cryptography / protocol reversing / kernel exploitation / game cheats / firmware / SDR / AI security.',
  windows: 'Windows internals: config injection / privilege escalation / thread & process injection bypasses.',
}

const boardSignals: Record<string, { zh: string; en: string }> = {
  'ctf-website': { zh: '入口信号: JWT / SQLi / SSRF / CVE → 脚本打点 → 闭环验证', en: 'Signals: JWT / SQLi / SSRF / CVE → Payloads → Evidence Loop' },
  'apk-reverse': { zh: '入口信号: 加密壳 / Native / JNI → Frida Hook → 内存脱壳', en: 'Signals: Packers / Native / JNI → Frida Hook → Memory Unpack' },
  'pe-reverse': { zh: '入口信号: 异常熵值 / 反调试 → Ghidra静态 → x64dbg验证', en: 'Signals: High Entropy / Anti-Debug → Ghidra → Dynamic Breakpoints' },
  general: { zh: '入口信号: 未知协议 / 自定义PRNG → 逆向测试桩 → 重放破解', en: 'Signals: Custom Protocols / PRNG → Test Scaffold → Crypto Replay' },
  windows: { zh: '入口信号: 权限令牌 / 敏感注册表 → 注入利用 → 防御规避', en: 'Signals: Security Tokens / Registry Keys → Injection → AV Evasion' },
}

const t = computed(() => ({
  boardsTitle: isEn.value ? 'Attack Networks & Analysis Boards' : '5 大闭环攻击网与实战板块',
  boardsDesc: isEn.value
    ? 'Each board forms an end-to-end attack graph: entry signals → payload execution → branch analysis → evidence validation.'
    : '每个板块构成一条完整的闭环攻击网：入口信号识别 → 自动化脚本打点 → 路径分支研判 → 证据链闭环。',
  articleUnit: isEn.value ? 'Articles' : '篇手册',
  categoryUnit: isEn.value ? 'Categories' : '类技术',
  enterBoard: isEn.value ? 'Enter Board →' : '进入板块 →',
}))

const kbPath = (b: string) => `${isEn.value ? '/en' : ''}/kb/${b}/README`
const blurbOf = (b: Board) => (isEn.value ? enBlurbs[b.name] ?? b.blurb : b.blurb)
const signalOf = (b: string) => (isEn.value ? boardSignals[b]?.en ?? '' : boardSignals[b]?.zh ?? '')
</script>

<template>
  <section class="rl-section" aria-labelledby="boards-title">
    <div class="rl-section-header">
      <div>
        <h2 id="boards-title" class="rl-section-title">{{ t.boardsTitle }}</h2>
        <p class="rl-section-desc">{{ t.boardsDesc }}</p>
      </div>
    </div>

    <div class="rl-board-matrix">
      <a
        v-for="(b, idx) in boardKeys"
        :key="b"
        class="rl-board-cell"
        :href="kbPath(b)"
        :style="{ '--bd-hue': boardList[b].hue }"
      >
        <div class="rl-cell-top">
          <span class="rl-board-id">#0{{ idx + 1 }}</span>
          <span class="rl-board-chip">
            {{ boardList[b].name }}
          </span>
          <span class="rl-cell-enter">{{ t.enterBoard }}</span>
        </div>

        <h3 class="rl-cell-title">
          {{ boardList[b].name }}
          <span v-if="!isEn" class="rl-cell-zh">{{ boardList[b].zh }}</span>
        </h3>

        <p class="rl-cell-blurb">{{ blurbOf(boardList[b]) }}</p>

        <div class="rl-cell-signal">
          <svg class="rl-signal-icon" viewBox="0 0 16 16" width="12" height="12" fill="currentColor">
            <path d="M1 8a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 .4.2l1.6 2.133 3.2-6.4a.5.5 0 0 1 .867-.04l2.4 4 1.533-1.84a.5.5 0 0 1 .767.64l-2 2.4a.5.5 0 0 1-.787.027L9.2 5.253 6.333 11a.5.5 0 0 1-.887.027L3.6 8.5H1.5A.5.5 0 0 1 1 8z"/>
          </svg>
          <span>{{ signalOf(b) }}</span>
        </div>

        <div class="rl-cell-footer">
          <div class="rl-cell-metric">
            <strong>{{ boardList[b].articles }}</strong> {{ t.articleUnit }}
          </div>
          <div class="rl-cell-metric">
            <strong>{{ boardList[b].categories }}</strong> {{ t.categoryUnit }}
          </div>
        </div>
      </a>
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
.rl-board-matrix {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 20px;
}
.rl-board-cell {
  display: flex;
  flex-direction: column;
  background: var(--rl-bg);
  border: 1px solid var(--rl-line);
  border-radius: 10px;
  padding: 24px;
  text-decoration: none !important;
  transition: all 180ms ease-out;
  position: relative;
}
.rl-board-cell:hover {
  border-color: hsl(var(--bd-hue, 278) 45% 55%);
  box-shadow: 0 6px 20px -8px hsl(var(--bd-hue, 278) 60% 70% / 0.25);
  transform: translateY(-2px);
}
.rl-cell-top {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 16px;
}
.rl-board-id {
  font-family: var(--rl-font-mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--rl-muted);
}
.rl-board-chip {
  font-family: var(--rl-font-mono);
  font-size: 12px;
  font-weight: 600;
  color: hsl(var(--bd-hue) 45% 30%);
  background: hsl(var(--bd-hue) 60% 96%);
  border: 1px solid hsl(var(--bd-hue) 50% 88%);
  padding: 2px 8px;
  border-radius: 4px;
}
.rl-cell-enter {
  margin-left: auto;
  font-size: 13px;
  font-weight: 600;
  color: var(--rl-primary);
  opacity: 0.8;
}
.rl-board-cell:hover .rl-cell-enter {
  opacity: 1;
  transform: translateX(2px);
}
.rl-cell-title {
  font-family: var(--rl-font-display);
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--rl-ink);
  margin: 0 0 10px;
}
.rl-cell-zh {
  font-size: 0.95rem;
  font-weight: 500;
  color: var(--rl-muted);
  margin-left: 6px;
}
.rl-cell-blurb {
  font-size: 14px;
  line-height: 1.6;
  color: var(--rl-ink-soft);
  margin: 0 0 16px;
  flex-grow: 1;
}
.rl-cell-signal {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  background: var(--rl-surface-2);
  border: 1px solid var(--rl-line);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 12px;
  font-family: var(--rl-font-mono);
  color: var(--rl-ink-soft);
  margin-bottom: 16px;
  line-height: 1.4;
}
.rl-signal-icon {
  margin-top: 2px;
  flex-shrink: 0;
  color: hsl(var(--bd-hue) 60% 45%);
}
.rl-cell-footer {
  display: flex;
  gap: 16px;
  padding-top: 12px;
  border-top: 1px solid var(--rl-line);
  font-size: 13px;
  color: var(--rl-muted);
}
.rl-cell-metric strong {
  color: var(--rl-ink);
  font-family: var(--rl-font-mono);
}
</style>
