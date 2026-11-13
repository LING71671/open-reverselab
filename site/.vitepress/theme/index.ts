import { type Theme, inBrowser } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import './custom.css'
import '@fontsource/nunito-sans/400.css'
import '@fontsource/nunito-sans/500.css'
import '@fontsource/nunito-sans/600.css'
import '@fontsource/nunito-sans/700.css'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/500.css'
import HomePage from './HomePage.vue'
import McpToolsPage from './McpToolsPage.vue'

export default {
  extends: DefaultTheme,
  enhanceApp({ app, router, siteData }) {
    app.component('HomePage', HomePage)
    app.component('McpToolsPage', McpToolsPage)

    // Remember the user's language choice (e.g. the nav language switch).
    // First-visit auto-detection is handled by the inline script in
    // config.mts (transformHead); this persists manual switches so the
    // auto-redirect does not override them.
    router.onAfterRouteChange = (to) => {
      try {
        if (!inBrowser) return
        const path = '/' + to.slice(siteData.value.base.length)
        const isEn = path === '/en' || path.startsWith('/en/')
        localStorage.setItem('rl-lang', isEn ? 'en' : 'zh')
      } catch {
        /* storage unavailable — ignore */
      }
    }
  },
} satisfies Theme
