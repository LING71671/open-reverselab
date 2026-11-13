<script setup lang="ts">
import { computed, ref } from 'vue'
import { useData, withBase } from 'vitepress'
const { lang } = useData()
const en = computed(() => lang.value.startsWith('en'))
const local = (path: string) => withBase(`${en.value ? '/en' : ''}${path}.html`)
const repo = 'https://github.com/LING71671/open-reverselab'
const track = ref<'red' | 'blue' | 'both'>('both')
const modes = ['red', 'blue', 'both'] as const
const platform = ref('windows')
const copyStatus = ref('')
const boards = [
  { id: 'ctf-website', name: 'Web / CTF', zh: '认证、注入、服务端漏洞与防御验证', en: 'Authentication, injection, server-side flaws and defense checks' },
  { id: 'apk-reverse', name: 'Android / APK', zh: 'Java、Native、加密与运行时观测', en: 'Java, native code, cryptography and runtime observation' },
  { id: 'pe-reverse', name: 'Windows / PE', zh: '静态分析、调试、行为研判与检测', en: 'Static analysis, debugging, behavior and detection' },
  { id: 'general', name: 'General', zh: '算法、协议、固件与跨领域分析', en: 'Algorithms, protocols, firmware and cross-domain analysis' },
]
const tracks = computed(() => ({
  red: en.value ? 'Investigate attack paths and validate hypotheses against an authorized target. Keep evidence from each attempt.' : '围绕授权目标寻找分析路径，验证假设，保留每次尝试的证据。',
  blue: en.value ? 'Follow defense guidance to examine behavior, assess controls and produce detection or remediation evidence.' : '结合防御知识检查行为与控制措施，形成检测、加固和修复验证证据。',
  both: en.value ? 'Run red and blue branches independently, then bring their evidence into a shared result.' : 'red 与 blue 分支独立推进，完成后汇入同一份结果。',
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
      <div class="rl-download"><a class="rl-button" :href="local('/desktop')">{{ en ? 'Build the desktop preview' : '构建桌面预览版' }}<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6" /></svg></a><span>{{ en ? 'Source preview · Windows x64' : '源码预览 · Windows x64' }}</span><a class="rl-text-link" :href="`${repo}/releases`">{{ en ? 'Published releases' : '已发布版本' }}</a></div>
    </section>
    <figure class="rl-product">
      <a :href="withBase('/assets/desktop/knowledge-light.png')" :aria-label="en ? 'View full desktop screenshot' : '查看桌面端完整截图'"><img :src="withBase('/assets/desktop/knowledge-light.png')" :alt="en ? 'Open ReverseLab desktop, showing paired red and blue JWT knowledge articles' : 'Open ReverseLab 桌面端，展示配对的 red 与 blue JWT 知识文档'" width="2560" height="1440" fetchpriority="high" /></a>
      <figcaption>{{ en ? 'Desktop knowledge base · both' : '桌面端知识库 · both' }}<a :href="local('/kb/ctf-website/techniques/02-auth/jwt/00-overview-defense')">{{ en ? 'Read this article' : '阅读这篇文档' }}<span aria-hidden="true"> ↗</span></a></figcaption>
    </figure>
    <section class="rl-split rl-section" aria-labelledby="goal-title">
      <div><h2 id="goal-title">{{ en ? 'Start with a target.' : '从目标开始' }}</h2><p>{{ en ? 'Use a file, directory or URL. Time and token limits are optional. Follow each branch in the live flow canvas.' : '目标可以是文件、目录或 URL。时间与 Token 上限可选，实时流程画板保留每条分支的进度。' }}</p><a class="rl-text-link" :href="`${repo}/blob/main/desktop/AGENT_SYSTEM.md`">{{ en ? 'How Goals run' : '了解 Goal 如何执行' }} ↗</a></div>
      <div class="rl-track-demo"><div class="rl-segments" role="group" :aria-label="en ? 'Analysis mode' : '分析模式'"><button v-for="mode in modes" :key="mode" :aria-pressed="track === mode" @click="track = mode">{{ mode }}</button></div><p class="rl-track-description" aria-live="polite">{{ tracks[track] }}</p><div class="rl-track-path" aria-hidden="true"><span>Target</span><span class="rl-path-line"></span><span>{{ track === 'both' ? 'red + blue' : track }}</span><span class="rl-path-line"></span><span>{{ en ? 'Evidence' : '证据' }}</span></div></div>
    </section>
    <section id="knowledge" class="rl-split rl-section" aria-labelledby="knowledge-title">
      <div><h2 id="knowledge-title">{{ en ? 'Knowledge for the next step.' : '按领域查知识' }}</h2><p>{{ en ? 'Analysis techniques and defense guidance live together. Search by signal, then follow the linked procedures and tool mappings.' : '分析技术与 defense 文档按领域组织。按信号检索，继续阅读对应规程和工具映射。' }}</p><a class="rl-text-link" :href="local('/mcp-tools')">{{ en ? 'Browse the tool registry' : '查看工具目录' }} ↗</a></div>
      <div class="rl-board-list"><a v-for="board in boards" :key="board.id" :href="local(`/kb/${board.id}/README`)"><span><strong>{{ board.name }}</strong><small>{{ en ? board.en : board.zh }}</small></span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6" /></svg></a></div>
    </section>
    <section class="rl-split rl-section" aria-labelledby="cli-title">
      <div><h2 id="cli-title">{{ en ? 'Prefer the terminal?' : '也可以从命令行使用' }}</h2><p>{{ en ? 'The repository includes scripts, an MCP server and client workflows. Install only the external tools your analysis needs.' : '仓库包含脚本、MCP 服务和客户端工作流。外部工具按分析任务单独安装。' }}</p><a class="rl-text-link" :href="`${repo}/blob/main/START.md`">{{ en ? 'Read the quick start' : '阅读快速开始' }} ↗</a></div>
      <div class="rl-commands"><div class="rl-command-bar"><label><span class="rl-sr-only">{{ en ? 'Shell' : '命令行环境' }}</span><select v-model="platform" @change="copyStatus = ''"><option value="windows">PowerShell</option><option value="unix">Bash · macOS / Linux</option></select></label><button @click="copyCommand">{{ en ? 'Copy' : '复制' }}</button></div><pre tabindex="0"><code>{{ command }}</code></pre><p v-if="copyStatus" role="status">{{ copyStatus }}</p></div>
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
