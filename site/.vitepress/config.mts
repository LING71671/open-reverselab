import { defineConfig } from 'vitepress'
import { sidebar } from './sidebar'

export default defineConfig({
  lang: 'zh-CN',
  title: 'ReverseLab',
  description: '开源逆向工程实验环境：173 篇可执行知识库 + 100+ MCP 自动化工具。Agent 原生，目录即约定。',

  head: [
    ['meta', { name: 'keywords', content: 'reverse engineering, 逆向工程, CTF, APK reverse, PE analysis, MCP tools, Frida, Ghidra, x64dbg, web security, knowledge base' }],
    ['meta', { name: 'author', content: 'ReverseLab' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'ReverseLab — 开源逆向工程实验环境' }],
    ['meta', { property: 'og:description', content: '173 篇可执行知识库文章 + 100+ MCP 自动化工具，覆盖 CTF/APK/PE/加密/游戏作弊全领域。' }],
    ['meta', { property: 'og:site_name', content: 'ReverseLab' }],
    ['meta', { property: 'og:locale', content: 'zh_CN' }],
    ['meta', { property: 'og:image', content: 'https://reverselab.int0.cc/assets/social-preview.png' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:image', content: 'https://reverselab.int0.cc/assets/social-preview.png' }],
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/assets/favicon.svg' }],
  ],

  themeConfig: {
    logo: '/assets/favicon.svg',
    siteTitle: 'ReverseLab',
    nav: [
      { text: '知识库', link: '/kb/ctf-website/README', activeMatch: '/kb/' },
      { text: 'CTF Website', link: '/kb/ctf-website/README' },
      { text: 'APK Reverse', link: '/kb/apk-reverse/README' },
      { text: 'PE Reverse', link: '/kb/pe-reverse/README' },
      { text: 'General', link: '/kb/general/README' },
      { text: 'MCP 工具', link: '/mcp-tools', activeMatch: '/mcp-tools' },
      { text: 'FAQ', link: '/faq', activeMatch: '/faq' },
      { text: 'GitHub', link: 'https://github.com/LING71671/open-reverselab' },
    ],
    sidebar,
    outline: { level: [2, 3], label: '本页目录' },
    search: {
      provider: 'local',
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
      message: 'GPL-3.0 · 仅供授权环境下的学习与防御性研究使用',
      copyright: '© 2026 ReverseLab',
    },
  },

  markdown: {
    lineNumbers: false,
    config(md) {
      // kb/ 文章含大量 Jinja2/Twig/Velocity 示例（{{ ... }}），与 Vue 插值冲突。
      // 在 markdown-it 渲染完成后，把整段 HTML 中的裸 {{ / }} 转义为 HTML 实体：
      // Vue 编译器不再识别为插值，浏览器渲染时实体还原为原文。
      // （fence 代码块在 v-pre 中，实体同样会被浏览器解码，显示不受影响。）
      const render = md.renderer.render.bind(md.renderer)
      md.renderer.render = (tokens, options, env) =>
        render(tokens, options, env)
          .replace(/\{\{/g, '&#123;&#123;')
          .replace(/\}\}/g, '&#125;&#125;')
    },
  },

  // kb/ 文章里的相对链接可能指向仓库内站点范围之外的文件
  // （scripts/、tools/、cases/ 等），GitHub 上有效，站点构建时忽略。
  ignoreDeadLinks: [
    // ignore external / non-kb relative targets
    (href) => !/^(\/kb\/|\.?\/?kb\/)/.test(href) && !/^https?:/.test(href) && !/^mailto:/.test(href),
  ],

  sitemap: {
    hostname: 'https://reverselab.int0.cc',
  },

  vite: {
    // site/kb is a junction to ../kb; keep module paths inside site/ so
    // Vite does not treat them as external files.
    resolve: {
      symlinks: false,
    },
  },
})
