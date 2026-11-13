<script setup lang="ts">
import { computed, ref } from 'vue'
import { useData, withBase } from 'vitepress'
import SelectField from './SelectField.vue'
const { lang } = useData()
const en = computed(() => lang.value.startsWith('en'))
const local = (path: string) => withBase(`${en.value ? '/en' : ''}${path}.html`)
const repo = 'https://github.com/LING71671/open-reverselab'
const track = ref<'red' | 'blue' | 'both'>('both')
const modes = ['red', 'blue', 'both'] as const
const platform = ref('windows')
const platforms = [{ value: 'windows', label: 'PowerShell' }, { value: 'unix', label: 'Bash · macOS / Linux' }]
const copyStatus = ref('')
const knowledgeTracks = [
  { id: 'red', name: 'Red', zh: '攻击网、分析路径与复现方法', en: 'Attack networks, analysis paths and reproduction' },
  { id: 'blue', name: 'Blue', zh: '防御网、检测、控制措施与验证', en: 'Defense networks, detection, controls and validation' },
  { id: 'shared', name: 'Shared', zh: '识别、调试、算法与协议方法', en: 'Identification, debugging, algorithms and protocols' },
]
const tracks = computed(() => ({
  red: en.value ? 'Investigate attack paths and validate hypotheses against an authorized target. Keep evidence from each attempt.' : '围绕授权目标寻找分析路径，验证假设，保留每次尝试的证据。',
  blue: en.value ? 'Follow defense guidance to examine behavior, assess controls and produce detection or remediation evidence.' : '结合防御知识检查行为与控制措施，形成检测、加固和修复验证证据。',
  both: en.value ? 'Let red and blue plan concurrent actions, exchange evidence, and verify the combined result.' : 'red 与 blue 分别规划并行动作，交换证据，核验完整目标。',
}))
const command = computed(() => `git clone ${repo}.git\ncd open-reverselab\n${platform.value === 'windows' ? '.\\scripts\\misc\\bootstrap.ps1' : 'bash ./scripts/misc/bootstrap.sh'}\n${platform.value === 'windows' ? 'python' : 'python3'} scripts/misc/lab_healthcheck.py`)
async function copyCommand() {
  try { await navigator.clipboard.writeText(command.value); copyStatus.value = en.value ? 'Copied' : '已复制' }
  catch { copyStatus.value = en.value ? 'Select the commands to copy them.' : '复制失败，请选中命令手动复制。' }
}
</script>
<template>
  <div class="rl-home">
    <section id="desktop" class="rl-intro">
      <div><h1>{{ en ? 'An AI workbench for reverse engineering.' : 'AI 逆向分析工作台' }}</h1><p>{{ en ? 'Give Open ReverseLab a target and a Goal. Follow parallel analysis, inspect the evidence and keep the results in your workspace.' : '给出目标和 Goal，查看并行分析过程，在工作区中收纳样本、证据与报告。' }}</p></div>
      <div class="rl-download"><a class="rl-button" :href="`${repo}/releases/tag/v2.0.0-beta.1`">{{ en ? 'Download Windows beta' : '下载 Windows 测试版' }}<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6" /></svg></a><span>v2.0.0-beta.1 · Windows x64</span><a class="rl-text-link" :href="local('/desktop')">{{ en ? 'Installation guide' : '安装说明' }}</a></div>
    </section>
    <figure class="rl-product">
      <a :href="withBase('/assets/desktop/knowledge-light.png')" :aria-label="en ? 'View full desktop screenshot' : '查看桌面端完整截图'"><img :src="withBase('/assets/desktop/knowledge-light.png')" :alt="en ? 'Open ReverseLab desktop, showing paired red and blue JWT knowledge articles' : 'Open ReverseLab 桌面端，展示配对的 red 与 blue JWT 知识文档'" width="2560" height="1440" fetchpriority="high" /></a>
      <figcaption>{{ en ? 'Desktop knowledge base · both' : '桌面端知识库 · both' }}<a :href="local('/kb/blue/ctf-website/techniques/02-auth/jwt/00-overview-defense')">{{ en ? 'Read this article' : '阅读这篇文档' }}<span aria-hidden="true"> ↗</span></a></figcaption>
    </figure>
    <section class="rl-split rl-section" aria-labelledby="goal-title">
      <div><h2 id="goal-title">{{ en ? 'Start with a target.' : '从目标开始' }}</h2><p>{{ en ? 'Use a file, directory or URL. Time and token limits are optional. Follow each branch in the live flow canvas.' : '目标可以是文件、目录或 URL。时间与 Token 上限可选，实时流程画板保留每条分支的进度。' }}</p><a class="rl-text-link" :href="`${repo}/blob/main/desktop/AGENT_SYSTEM.md`">{{ en ? 'How Goals run' : '了解 Goal 如何执行' }} ↗</a></div>
      <div class="rl-track-demo"><div class="rl-segments" role="group" :aria-label="en ? 'Analysis mode' : '分析模式'"><button v-for="mode in modes" :key="mode" :aria-pressed="track === mode" @click="track = mode">{{ mode }}</button></div><p class="rl-track-description" aria-live="polite">{{ tracks[track] }}</p><div class="rl-track-path" aria-hidden="true"><span>Target</span><span class="rl-path-line"></span><span>{{ track === 'both' ? 'red + blue' : track }}</span><span class="rl-path-line"></span><span>{{ en ? 'Evidence' : '证据' }}</span></div></div>
    </section>
    <section id="knowledge" class="rl-split rl-section" aria-labelledby="knowledge-title">
      <div><h2 id="knowledge-title">{{ en ? 'Browse the knowledge base.' : '查阅知识库' }}</h2><p>{{ en ? 'Choose Red, Blue or Shared, then a domain. Search by signal and follow the procedures and tool mappings.' : '先选择 Red、Blue 或共享方法，再进入领域。按信号检索，继续阅读对应规程和工具映射。' }}</p><a class="rl-text-link" :href="local('/mcp-tools')">{{ en ? 'Browse the tool registry' : '查看工具目录' }} ↗</a></div>
      <div class="rl-board-list"><a v-for="item in knowledgeTracks" :key="item.id" :href="local(`/kb/${item.id}/README`)"><span><strong>{{ item.name }}</strong><small>{{ en ? item.en : item.zh }}</small></span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6" /></svg></a></div>
    </section>
    <section class="rl-split rl-section" aria-labelledby="cli-title">
      <div><h2 id="cli-title">{{ en ? 'Prefer the terminal?' : '也可以从命令行使用' }}</h2><p>{{ en ? 'The repository includes scripts, an MCP server and client workflows. Install only the external tools your analysis needs.' : '仓库包含脚本、MCP 服务和客户端工作流。外部工具按分析任务单独安装。' }}</p><a class="rl-text-link" :href="`${repo}/blob/main/START.md`">{{ en ? 'Read the quick start' : '阅读快速开始' }} ↗</a></div>
      <div class="rl-commands"><div class="rl-command-bar"><SelectField id="command-platform" v-model="platform" :label="en ? 'Shell' : '命令行环境'" :hide-label="true" :options="platforms" @update:model-value="copyStatus = ''" /><button @click="copyCommand">{{ en ? 'Copy' : '复制' }}</button></div><pre tabindex="0"><code>{{ command }}</code></pre><p v-if="copyStatus" role="status">{{ copyStatus }}</p></div>
    </section>
    <section class="rl-sponsors rl-section" aria-labelledby="sponsors-title">
      <div class="rl-sponsor-heading"><h2 id="sponsors-title">{{ en ? 'Sponsors' : '赞助支持' }}</h2><a class="rl-text-link" :href="`${repo}/blob/main/${en ? 'SPONSORS.md' : 'SPONSORS_zh.md'}`">{{ en ? 'Support the project' : '支持项目' }} ↗</a></div>
      <div class="rl-sponsor-list">
        <a href="https://infistar.cc/register?aff=OPENREVERSELAB&amp;ref_source=link"><strong>Infistar.cc <span aria-hidden="true">↗</span></strong><p>{{ en ? 'Multi-model API access for AI and MCP workflows. Project referrals receive CNY 5 in sign-up credit.' : '为 AI 与 MCP 工作流提供多模型 API 接入。通过专属链接注册赠 ¥5 体验额度。' }}</p></a>
        <a href="https://sentry.io"><strong>Sentry <span aria-hidden="true">↗</span></strong><p>{{ en ? 'Sponsored account for error monitoring and performance tracing across the project toolchain.' : '提供赞助账户，支持项目工具链的错误监控与性能追踪。' }}</p></a>
      </div>
    </section>
    <section class="rl-community rl-section" :aria-label="en ? 'Open source community' : '开源社区'"><p>{{ en ? 'Open source under Apache-2.0.' : '以 Apache-2.0 开源。' }}</p><div><a :href="repo">GitHub</a><a href="https://deepwiki.com/LING71671/open-reverselab">DeepWiki</a><a :href="`${repo}/blob/main/.github/CONTRIBUTING.md`">{{ en ? 'Contribute' : '参与贡献' }}</a><a href="https://star-history.com/#LING71671/open-reverselab&Date">Star History</a></div></section>
  </div>
</template>
