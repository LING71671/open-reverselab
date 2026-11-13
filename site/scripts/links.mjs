import path from 'node:path'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const repository = fileURLToPath(new URL('../..', import.meta.url))
const migrations = JSON.parse(readFileSync(path.join(repository, 'kb/path-aliases.json'), 'utf8'))

// One route table is shared by Markdown rendering, the dev server and static redirects.
export function loadLegacyRoutes() {
  const routes = {}
  const add = (old, target) => {
    for (const value of [old, target]) {
      if (!/^kb\/[^?#]+\.(md|html)$/.test(value) || path.posix.normalize(value) !== value) {
        throw new Error(`Invalid knowledge route: ${value}`)
      }
    }
    const source = old.replace(/\.md$/, '.html')
    const destination = target.replace(/\.md$/, '.html')
    if (source !== destination) routes[source] = destination
  }
  for (const [old, target] of Object.entries(migrations)) add(old, target)
  const historic = JSON.parse(readFileSync(new URL('./legacy-routes.json', import.meta.url), 'utf8'))
  for (const [old, target] of Object.entries(historic)) add(old, target)
  // Earlier document-relative links sometimes repeated the techniques segment.
  for (const [old, target] of Object.entries(routes)) {
    if (old.includes('/techniques/') && !old.includes('/techniques/techniques/')) {
      add(old.replace('/techniques/', '/techniques/techniques/'), target)
    }
  }
  return routes
}

const legacyRoutes = loadLegacyRoutes()

export function legacyRedirect(href, base = '/') {
  const url = new URL(href, 'https://site.invalid')
  const basePath = base.split('/').filter(Boolean).join('/')
  const prefix = basePath ? `/${basePath}/` : '/'
  let pathname
  try { pathname = decodeURIComponent(url.pathname) } catch { return null }
  if (!pathname.startsWith(prefix)) return null
  let route = pathname.slice(prefix.length)
  const locale = route.startsWith('en/') ? 'en/' : ''
  route = route.slice(locale.length)
  if (route.endsWith('/')) route += 'README.html'
  else if (route.endsWith('.md')) route = route.slice(0, -3) + '.html'
  else if (!route.endsWith('.html')) route += '.html'
  const target = legacyRoutes[route] || legacyRoutes[route.replace(/\/(?:techniques\/){2,}/g, '/techniques/')]
  return target ? `${prefix}${locale}${target}${url.search}${url.hash}` : null
}

function canonicalKnowledgePath(source, siteRoot) {
  const extension = source.endsWith('.md') ? '.md' : source.endsWith('.html') ? '.html' : ''
  const markdown = /\.(md|html)$/.test(source) ? source.replace(/\.(md|html)$/, '.md') : source + '.md'
  const route = markdown.slice(1).replace(/\.md$/, '.html')
  let target = legacyRoutes[route]
  if (!target && !existsSync(path.resolve(siteRoot, '..', markdown.slice(1)))) {
    const old = route.replace(/^kb\/(?:red|blue|shared)\//, 'kb/').replace(/\/(?:techniques\/){2,}/g, '/techniques/')
    target = legacyRoutes[old]
  }
  if (target) return '/' + target.replace(/\.html$/, extension)
  return source
}

// Resolve against the document, even while the address bar is changing routes.
export function documentLink(href, page, siteRoot) {
  if (!href || /^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) return href
  const match = href.match(/^([^?#]*)(.*)$/s)
  const [, body, suffix] = match
  let target = path.posix.normalize(body.startsWith('/') ? body : `/${path.posix.dirname(page)}/${body}`)
  const english = target.startsWith('/en/kb/') || (page.startsWith('en/') && target.startsWith('/kb/'))
  let source = target.replace(/^\/en\/kb\//, '/kb/')
  if (page.startsWith('en/kb/') && source.startsWith('/en/') && !existsSync(path.join(siteRoot, target))) {
    source = source.slice(3)
  }
  if (source.startsWith('/kb/')) {
    source = canonicalKnowledgePath(source, siteRoot)
    target = (english ? '/en' : '') + source
  }
  const repositoryFile = path.resolve(siteRoot, '..', source.slice(1))
  if (!source.startsWith('/kb/') && !existsSync(path.join(siteRoot, source)) && existsSync(repositoryFile)) {
    return `https://github.com/LING71671/open-reverselab/blob/main${source}${suffix}`
  }
  if (source.startsWith('/kb/') && !/\.(md|html)$/.test(source) && existsSync(repositoryFile) && !existsSync(`${repositoryFile}.md`)) {
    return `https://github.com/LING71671/open-reverselab/blob/main${source}${suffix}`
  }
  return target + suffix
}

export function stableDocumentLinks(md, siteRoot) {
  md.core.ruler.push('stable-document-links', state => {
    const page = String(state.env.relativePath || '')
    const knowledgePage = /^(en\/)?kb\//.test(page)
    const visit = tokens => {
      for (const token of tokens) {
        if (token.type === 'link_open') {
          const href = token.attrGet('href')
          if (knowledgePage || /^\/(en\/)?kb\//.test(href || '')) token.attrSet('href', documentLink(href, page, siteRoot))
        }
        if (token.children) visit(token.children)
      }
    }
    visit(state.tokens)
  })
}
