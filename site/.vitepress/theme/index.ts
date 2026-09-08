import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import './custom.css'
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-sans/700.css'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/500.css'
import HomePage from './HomePage.vue'
import McpToolsPage from './McpToolsPage.vue'

export default {
  extends: DefaultTheme,
  enhanceApp({ app, router }) {
    app.component('HomePage', HomePage)
    app.component('McpToolsPage', McpToolsPage)

    // Remember the user's language choice (e.g. the nav language switch).
    // First-visit auto-detection is handled by the inline script in
    // config.mts (transformHead); this persists manual switches so the
    // auto-redirect does not override them.
    router.onAfterRouteChange = (to) => {
      try {
        const isEn = to === '/en' || to.startsWith('/en/')
        localStorage.setItem('rl-lang', isEn ? 'en' : 'zh')
      } catch {
        /* storage unavailable — ignore */
      }
    }
  },
} satisfies Theme
