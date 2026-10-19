<script setup lang="ts">
import { ref, computed } from 'vue'
import { useData } from 'vitepress'

const { lang } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const activeTerminalTab = ref<'win' | 'unix' | 'agent'>('win')
const copiedCommand = ref<string | null>(null)

const winCommands = `git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
.\\scripts\\misc\\bootstrap.ps1
.\\scripts\\misc\\install_tools.ps1 -CTF      # 安装 Web CTF 工具链
.\\scripts\\misc\\install_tools.ps1 -Android  # 安装 APK 逆向工具链
.\\scripts\\misc\\install_tools.ps1 -Windows  # 安装 PE 分析工具链`

const unixCommands = `git clone https://github.com/LING71671/open-reverselab.git
cd open-reverselab
bash ./scripts/misc/bootstrap.sh
python3 ./scripts/misc/lab_healthcheck.py`

const agentCommands = `python ./scripts/misc/setup_unattended_ctf_runner.py --overwrite
# Claude Code / Codex:
/loop /ctf-24h <target_url> [case_name]`

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
  startTitle: isEn.value ? 'Quickstart & Environment Setup' : '环境初始化与快速上手',
  startDesc: isEn.value
    ? 'Bootstrap your local workbench in seconds. All dependencies follow strictly audited offline recipes.'
    : '数秒完成本地实验环境初始化。工具链支持离线解包与自动化检测。',
  copyText: isEn.value ? 'Copy Snippet' : '复制命令',
  copiedText: isEn.value ? 'Copied!' : '已复制!',
}))
</script>

<template>
  <section class="rl-section" aria-labelledby="start-title">
    <div class="rl-section-header">
      <div>
        <h2 id="start-title" class="rl-section-title">{{ t.startTitle }}</h2>
        <p class="rl-section-desc">{{ t.startDesc }}</p>
      </div>
    </div>

    <div class="rl-terminal-card">
      <div class="rl-terminal-header">
        <div class="rl-terminal-buttons">
          <button
            class="rl-term-tab"
            :class="{ active: activeTerminalTab === 'win' }"
            @click="activeTerminalTab = 'win'"
          >
            PowerShell (Windows)
          </button>
          <button
            class="rl-term-tab"
            :class="{ active: activeTerminalTab === 'unix' }"
            @click="activeTerminalTab = 'unix'"
          >
            Bash (macOS / Linux)
          </button>
          <button
            class="rl-term-tab"
            :class="{ active: activeTerminalTab === 'agent' }"
            @click="activeTerminalTab = 'agent'"
          >
            AI Agent (Codex / Claude)
          </button>
        </div>

        <button
          class="rl-copy-btn"
          @click="copyToClipboard(
            activeTerminalTab === 'win' ? winCommands : activeTerminalTab === 'unix' ? unixCommands : agentCommands,
            activeTerminalTab
          )"
        >
          {{ copiedCommand === activeTerminalTab ? t.copiedText : t.copyText }}
        </button>
      </div>

      <div class="rl-terminal-body">
        <pre v-if="activeTerminalTab === 'win'"><code>{{ winCommands }}</code></pre>
        <pre v-else-if="activeTerminalTab === 'unix'"><code>{{ unixCommands }}</code></pre>
        <pre v-else><code>{{ agentCommands }}</code></pre>
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
.rl-terminal-card {
  background: var(--rl-code-bg);
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.12);
}
.rl-terminal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: oklch(0.200 0.020 280);
  padding: 8px 16px;
  border-bottom: 1px solid oklch(0.260 0.020 280);
  gap: 12px;
  flex-wrap: wrap;
}
.rl-terminal-buttons {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.rl-term-tab {
  background: transparent;
  border: none;
  color: #94a3b8;
  font-family: var(--rl-font-mono);
  font-size: 12px;
  padding: 6px 12px;
  border-radius: 4px;
  cursor: pointer;
  transition: all 140ms ease;
}
.rl-term-tab:hover {
  color: #f8fafc;
}
.rl-term-tab.active {
  background: oklch(0.300 0.030 280);
  color: #f8fafc;
  font-weight: 600;
}
.rl-copy-btn {
  background: oklch(0.280 0.030 280);
  border: 1px solid oklch(0.380 0.040 280);
  color: #e2e8f0;
  font-family: var(--rl-font-mono);
  font-size: 12px;
  padding: 4px 10px;
  border-radius: 4px;
  cursor: pointer;
  transition: all 140ms ease;
}
.rl-copy-btn:hover {
  background: var(--rl-primary);
  color: #fff;
}
.rl-terminal-body {
  padding: 20px;
}
.rl-terminal-body pre {
  margin: 0;
  color: #e2e8f0;
  font-family: var(--rl-font-mono);
  font-size: 13.5px;
  line-height: 1.6;
  overflow-x: auto;
}
</style>
