import { defineConfig } from 'vitepress'
import { sidebar } from './sidebar'
import { stableDocumentLinks } from '../scripts/links.mjs'
import { fileURLToPath } from 'node:url'

/**
 * English sidebar derived from the auto-generated Chinese sidebar.
 * Only site-level UI text is translated; KB article titles/content stay as-is
 * (per "site pages only, main repo untouched" decision). KB links are
 * re-prefixed with /en/ so they resolve to the site/en/kb/** stubs, which
 * @include the original Chinese KB files.
 */
function toEnSidebar(zh: Record<string, unknown>): Record<string, unknown> {
  const translateText = (text: string): string => {
    const fixed: Record<string, string> = {
      '板块总览': 'Overview',
      '攻击网': 'Attack Network',
      '板块文章': 'Articles',
      '技术索引': 'Technique index',
    }
    return (fixed[text] ?? text).replace(/（/g, '(').replace(/）/g, ')')
  }

  const fix = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(fix)
    if (node && typeof node === 'object') {
      const out: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(node)) {
        if (k === 'text') out[k] = translateText(String(v))
        else if (k === 'link' && typeof v === 'string' && v.startsWith('/kb/')) out[k] = '/en' + v
        else out[k.startsWith('/kb/') ? '/en' + k : k] = fix(v)
      }
      return out
    }
    return node
  }
  return fix(zh) as Record<string, unknown>
}

const enSidebar = toEnSidebar(sidebar)

// Deployment is GitHub Pages (project pages), so every absolute asset URL and
// canonical link must be prefixed with the repository base path.
const base = process.env.VITEPRESS_BASE || '/'
const siteUrl = (process.env.VITEPRESS_SITE_URL || 'https://ling71671.github.io/open-reverselab').replace(/\/$/, '')
const socialPreview = `${siteUrl}/assets/social-preview-v2.png`

const zhThemeConfig = {
  nav: [
    { text: '桌面端', link: '/desktop' },
    { text: '知识库', items: [
      { text: 'Web / CTF', link: '/kb/ctf-website/README' },
      { text: 'Android / APK', link: '/kb/apk-reverse/README' },
      { text: 'Windows / PE', link: '/kb/pe-reverse/README' },
      { text: 'General', link: '/kb/general/README' },
      { text: 'Windows', link: '/kb/windows/README' },
    ] },
    { text: '工具', link: '/mcp-tools' },
    { text: 'FAQ', link: '/faq' },
  ],
  sidebar,
  outline: { level: [2, 3], label: '本页目录' },
  search: {
    options: {
      translations: {
        button: { buttonText: '搜索', buttonAriaLabel: '搜索' },
        modal: {
          noResultsText: '未找到相关内容',
          resetButtonTitle: '清除查询',
          footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' },
        },
      },
    },
  },
  docFooter: { prev: '上一篇', next: '下一篇' },
  lastUpdated: { text: '更新于', formatOptions: { dateStyle: 'short', timeStyle: 'medium' } },
  returnToTopLabel: '返回顶部',
  sidebarMenuLabel: '目录',
  darkModeSwitchLabel: '外观',
  lightModeSwitchTitle: '切换到浅色模式',
  darkModeSwitchTitle: '切换到深色模式',
  footer: {
    message: `Apache-2.0 · 仅供授权环境下的学习与防御性研究使用 · <a href="${base}disclaimer">免责声明</a>`,
    copyright: '© 2026 Open ReverseLab',
  },
}

const enThemeConfig = {
  nav: [
    { text: 'Desktop', link: '/en/desktop' },
    { text: 'Knowledge', items: [
      { text: 'Web / CTF', link: '/en/kb/ctf-website/README' },
      { text: 'Android / APK', link: '/en/kb/apk-reverse/README' },
      { text: 'Windows / PE', link: '/en/kb/pe-reverse/README' },
      { text: 'General', link: '/en/kb/general/README' },
      { text: 'Windows', link: '/en/kb/windows/README' },
    ] },
    { text: 'Tools', link: '/en/mcp-tools' },
    { text: 'FAQ', link: '/en/faq' },
  ],
  sidebar: enSidebar,
  outline: { level: [2, 3], label: 'On this page' },
  search: {
    options: {
      translations: {
        button: { buttonText: 'Search', buttonAriaLabel: 'Search' },
        modal: {
          noResultsText: 'No results for',
          resetButtonTitle: 'Clear query',
          footer: { selectText: 'Select', navigateText: 'Switch', closeText: 'Close' },
        },
      },
    },
  },
  docFooter: { prev: 'Previous', next: 'Next' },
  lastUpdated: { text: 'Updated at', formatOptions: { dateStyle: 'short', timeStyle: 'medium' } },
  returnToTopLabel: 'Back to top',
  sidebarMenuLabel: 'Menu',
  darkModeSwitchLabel: 'Appearance',
  lightModeSwitchTitle: 'Switch to light theme',
  darkModeSwitchTitle: 'Switch to dark theme',
  footer: {
    message: `Apache-2.0 · For authorized learning and defensive research only · <a href="${base}en/disclaimer">Disclaimer</a>`,
    copyright: '© 2026 Open ReverseLab',
  },
}

/**
 * Language auto-detection script injected into every page's <head>.
 * - First visit (no stored preference): redirect to /en/ when the browser
 *   language is English; otherwise stay on the Chinese site.
 * - Once the user picks a language (recorded in localStorage on route change
 *   by theme/index.ts), the preference wins and no auto-redirect happens.
 */
const languageDetectScript = `(function () {
  try {
    var pref = localStorage.getItem('rl-lang');
    if (pref) return;
    var base = ${JSON.stringify(base)};
    var path = '/' + location.pathname.slice(base.length);
    if (path === '/en' || path.indexOf('/en/') === 0) return;
    var lang = (navigator.language || 'zh').toLowerCase();
    if (lang.indexOf('en') === 0) {
      location.replace(base + 'en' + (path === '/' ? '/' : path) + location.search + location.hash);
    }
  } catch (e) {}
})();`

export default defineConfig({
  base,
  srcExclude: ['README.md'],
  lang: 'zh-CN',
  title: 'Open ReverseLab',
  description: 'Open ReverseLab AI 逆向分析工作台，支持 red / blue / both、并行 Goal、工作区与分析知识库。',

  head: [
    ['meta', { name: 'keywords', content: 'reverse engineering, 逆向工程, CTF, APK reverse, PE analysis, MCP tools, Frida, Ghidra, x64dbg, web security, knowledge base' }],
    ['meta', { name: 'author', content: 'Open ReverseLab' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'Open ReverseLab' }],
    ['meta', { property: 'og:image', content: socialPreview }],
    ['meta', { property: 'og:image:width', content: '1280' }],
    ['meta', { property: 'og:image:height', content: '640' }],
    ['meta', { property: 'og:image:alt', content: 'Open ReverseLab — AI reverse engineering workspace' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:image', content: socialPreview }],
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}assets/favicon.svg` }],
  ],

  locales: {
    root: {
      label: '简体中文',
      lang: 'zh-CN',
      title: 'Open ReverseLab',
      description: 'Open ReverseLab AI 逆向分析工作台，支持 red / blue / both、并行 Goal、工作区与分析知识库。',
      themeConfig: zhThemeConfig,
    },
    en: {
      label: 'English',
      lang: 'en-US',
      link: '/en/',
      title: 'Open ReverseLab',
      description: 'Open ReverseLab AI reverse engineering workbench with red / blue / both, parallel Goals, workspaces and a knowledge base.',
      themeConfig: enThemeConfig,
    },
  },

  themeConfig: {
    // Shared across locales: logo, site title, and the local search provider
    // must live at the top level — VitePress' build-time local search plugin
    // reads site.themeConfig.search, not the per-locale themeConfig.
    logo: '/assets/favicon.svg',
    siteTitle: 'Open ReverseLab',
    socialLinks: [{ icon: 'github', link: 'https://github.com/LING71671/open-reverselab' }],
    search: {
      provider: 'local',
      options: {},
    },
  },

  markdown: {
    lineNumbers: false,
    languageAlias: {
      smali: 'java',
      yara: 'c',
      freemarker: 'html',
      smarty: 'html',
      pebble: 'html',
    },
    config(md) {
      stableDocumentLinks(md, fileURLToPath(new URL('..', import.meta.url)))
      // kb/ 文章含大量 Jinja2/Twig/Velocity 示例（{{ ... }}），与 Vue 插值冲突。
      // 在 markdown-it 渲染完成后，把整段 HTML 中的裸 {{ / }} 转义为 HTML 实体：
      // Vue 编译器不再识别为插值，浏览器渲染时实体还原为原文。
      // （fence 代码块在 v-pre 中，实体同样会被浏览器解码，显示不受影响。）
      // 仅对 kb/（及 en/kb/ stub）应用——站点自身页面（404.md 等）的
      // Vue 插值必须保留。
      const render = md.renderer.render.bind(md.renderer)
      md.renderer.render = (tokens, options, env) => {
        let html = render(tokens, options, env)
        const rel = String(env?.relativePath || env?.path || '')
        if (rel.startsWith('kb/') || rel.startsWith('en/kb/')) {
          html = html
            .replace(/\{\{/g, '&#123;&#123;')
            .replace(/\}\}/g, '&#125;&#125;')
        }
        return html
      }
    },
  },

  transformHead({ pageData }) {
    const english = pageData.relativePath.startsWith('en/')
    const path = pageData.relativePath.replace(/(^|\/)index\.md$/, '$1').replace(/\.md$/, '.html')
    const canonical = `${siteUrl}/${path}`
    const title = pageData.title.includes('Open ReverseLab') ? pageData.title : `${pageData.title} | Open ReverseLab`
    const description = pageData.description || (english
      ? 'An AI reverse engineering workspace with target-bound Goals, text and canvas views, a knowledge base and MCP tools.'
      : '围绕目标运行 Goal，通过正文与画板查看分析过程，使用知识库与 MCP 工具。')
    return [
      ['script', {}, languageDetectScript],
      ['link', { rel: 'canonical', href: canonical }],
      ['meta', { property: 'og:url', content: canonical }],
      ['meta', { property: 'og:title', content: title }],
      ['meta', { property: 'og:description', content: description }],
      ['meta', { property: 'og:locale', content: english ? 'en_US' : 'zh_CN' }],
      ['meta', { name: 'twitter:title', content: title }],
      ['meta', { name: 'twitter:description', content: description }],
    ]
  },

  ignoreDeadLinks: false,

  sitemap: {
    // Relative page and language URLs must retain the GitHub Pages project path.
    hostname: `${siteUrl}/`,
    transformItems: items => items.filter(item => item.url !== '404.html'),
  },

  vite: {
    // site/kb is a junction to ../kb; keep module paths inside site/ so
    // Vite does not treat them as external files.
    resolve: {
      symlinks: false,
    },
  },
})
