<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'

const { lang, isDark } = useData()
const isEn = computed(() => lang.value.startsWith('en'))

const starHistoryUrl = computed(() => {
  return isDark.value
    ? 'https://api.star-history.com/svg?repos=LING71671/open-reverselab&type=Date&theme=dark'
    : 'https://api.star-history.com/svg?repos=LING71671/open-reverselab&type=Date'
})

const t = computed(() => ({
  starHistoryTitle: isEn.value ? 'Star History & Community Growth' : 'GitHub Star 趋势与开源社区',
  starHistoryDesc: isEn.value
    ? 'Open-ReverseLab is completely open-source, maintained by defensive researchers and community contributors worldwide.'
    : 'Open-ReverseLab 保持永久开源与防御性研究定位，感谢全球安全研究员、CTF 战队与社区贡献者的支持。',
  starButton: isEn.value ? 'Star on GitHub' : '在 GitHub 点亮 Star',
  sentryTitle: isEn.value ? 'Sponsored by Sentry' : 'Sentry 官方赞助支持',
  sentryDesc: isEn.value
    ? 'Sentry supports openreverselab with sponsored error monitoring and performance tracing for our automated toolchains.'
    : 'Sentry 为 Open-ReverseLab 逆向实验环境提供赞助账户，保障自动化分析工具链的错误监控与性能追踪。',
  deepwikiTitle: isEn.value ? 'DeepWiki Semantic Q&A' : 'DeepWiki 知识库问答',
  deepwikiDesc: isEn.value
    ? 'Query the entire 185-article knowledge base semantically via DeepWiki AI.'
    : '基于 DeepWiki 对全库 185 篇实战手册与工具映射表进行语义检索与即时解答。',
  licenseTitle: isEn.value ? 'GPL-3.0 Copyleft' : 'GPL-3.0 开源保障',
  licenseDesc: isEn.value
    ? 'Strictly copyleft, guaranteeing community freedom for authorized security research and learning.'
    : '严格强传染开源许可，确保研究成果公开共享，严守安全合规与防御性研究原则。',
}))
</script>

<template>
  <section id="community" class="rl-section" aria-labelledby="star-title">
    <div class="rl-section-header">
      <div>
        <h2 id="star-title" class="rl-section-title">{{ t.starHistoryTitle }}</h2>
        <p class="rl-section-desc">{{ t.starHistoryDesc }}</p>
      </div>
    </div>

    <!-- Star History Visual Card -->
    <div class="rl-star-history-card">
      <div class="rl-star-header">
        <div class="rl-term-dots">
          <span></span><span></span><span></span>
        </div>
        <div class="rl-star-title-wrap">
          <svg class="rl-star-icon" viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
            <path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.75.75 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25z"/>
          </svg>
          <span class="rl-star-repo">LING71671/open-reverselab</span>
        </div>
        <a class="rl-star-cta" href="https://github.com/LING71671/open-reverselab" target="_blank" rel="noopener">
          <span>★ {{ t.starButton }}</span>
        </a>
      </div>

      <div class="rl-star-body">
        <a href="https://star-history.com/#LING71671/open-reverselab&Date" target="_blank" rel="noopener" title="Star History on star-history.com">
          <img
            :src="starHistoryUrl"
            alt="Star History Chart"
            loading="lazy"
            class="rl-star-chart-img"
          />
        </a>
      </div>
    </div>

    <!-- Community & Sponsor Grid -->
    <div class="rl-community-grid">
      <div class="rl-community-card">
        <div class="rl-community-top">
          <span class="rl-community-badge rl-badge-sentry">SPONSOR</span>
          <span class="rl-community-label">Sentry.io</span>
        </div>
        <h4 class="rl-community-name">{{ t.sentryTitle }}</h4>
        <p class="rl-community-desc">{{ t.sentryDesc }}</p>
        <a class="rl-community-link" href="https://sentry.io" target="_blank" rel="noopener">sentry.io →</a>
      </div>

      <div class="rl-community-card">
        <div class="rl-community-top">
          <span class="rl-community-badge rl-badge-deepwiki">DEEPWIKI</span>
          <span class="rl-community-label">AI Search</span>
        </div>
        <h4 class="rl-community-name">{{ t.deepwikiTitle }}</h4>
        <p class="rl-community-desc">{{ t.deepwikiDesc }}</p>
        <a class="rl-community-link" href="https://deepwiki.com/LING71671/open-reverselab" target="_blank" rel="noopener">deepwiki.com →</a>
      </div>

      <div class="rl-community-card">
        <div class="rl-community-top">
          <span class="rl-community-badge rl-badge-gpl">GPL-3.0</span>
          <span class="rl-community-label">License</span>
        </div>
        <h4 class="rl-community-name">{{ t.licenseTitle }}</h4>
        <p class="rl-community-desc">{{ t.licenseDesc }}</p>
        <a class="rl-community-link" href="https://github.com/LING71671/open-reverselab/blob/main/LICENSE" target="_blank" rel="noopener">LICENSE (GPL-3.0) →</a>
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
.rl-star-history-card {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  border-radius: 10px;
  overflow: hidden;
  margin-bottom: 24px;
}
.rl-star-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 18px;
  border-bottom: 1px solid var(--rl-line);
  background: var(--rl-surface-2);
  gap: 12px;
  flex-wrap: wrap;
}
.rl-star-title-wrap {
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: var(--rl-font-mono);
  font-size: 13px;
  font-weight: 600;
  color: var(--rl-ink);
}
.rl-star-icon {
  color: var(--rl-accent);
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

.rl-star-cta {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--rl-primary);
  color: #fff !important;
  font-size: 12px;
  font-weight: 600;
  padding: 4px 12px;
  border-radius: 4px;
  text-decoration: none !important;
  transition: all 140ms ease;
}
.rl-star-cta:hover {
  background: var(--rl-primary-2);
}
.rl-star-body {
  padding: 16px;
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 320px;
}
.rl-star-chart-img {
  width: 100%;
  max-width: 960px;
  height: auto;
  display: block;
  border-radius: 6px;
}
.rl-community-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
}
.rl-community-card {
  background: var(--rl-surface);
  border: 1px solid var(--rl-line);
  border-radius: 8px;
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
}
.rl-community-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}
.rl-community-badge {
  font-family: var(--rl-font-mono);
  font-size: 11px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 4px;
}
.rl-badge-sentry {
  background: oklch(0.350 0.120 295 / 0.15);
  color: oklch(0.480 0.180 295);
}
.rl-badge-deepwiki {
  background: oklch(0.520 0.140 150 / 0.15);
  color: var(--rl-ok);
}
.rl-badge-gpl {
  background: var(--rl-accent-soft);
  color: var(--rl-accent);
}
.rl-community-label {
  font-family: var(--rl-font-mono);
  font-size: 11px;
  color: var(--rl-muted);
}
.rl-community-name {
  font-family: var(--rl-font-display);
  font-size: 1.05rem;
  font-weight: 700;
  color: var(--rl-ink);
  margin: 0 0 8px;
}
.rl-community-desc {
  font-size: 13px;
  line-height: 1.6;
  color: var(--rl-ink-soft);
  margin: 0 0 16px;
  flex-grow: 1;
}
.rl-community-link {
  font-family: var(--rl-font-mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--rl-primary);
  text-decoration: none !important;
}
.rl-community-link:hover {
  text-decoration: underline !important;
}
</style>
