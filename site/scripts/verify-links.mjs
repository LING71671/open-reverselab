import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { loadLegacyRoutes } from './links.mjs'

const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const root = path.join(site, '.vitepress/dist')
const basePath = (process.env.VITEPRESS_BASE || '').split('/').filter(Boolean).join('/')
const base = basePath ? `/${basePath}/` : '/'
const aliases = loadLegacyRoutes()
const file = name => { try { return statSync(name).isFile() } catch { return false } }
for (const locale of ['', 'en/']) for (const [old, target] of Object.entries(aliases)) {
  if (!file(path.join(root, locale, target))) throw new Error(`Missing redirect destination: ${locale}${target}`)
  const destination = `${base}${locale}${target}`
  const output = path.join(root, locale, old)
  mkdirSync(path.dirname(output), { recursive: true })
  writeFileSync(output, `<!doctype html><html lang="${locale ? 'en' : 'zh-CN'}"><meta charset="utf-8"><meta name="robots" content="noindex"><link rel="canonical" href="${destination}"><title>Open ReverseLab</title><script>location.replace(${JSON.stringify(destination)}+location.search+location.hash)</script><a href="${destination}">${locale ? 'Open document' : '打开文档'}</a></html>`)
}

function files(dir) { return readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(path.join(dir, entry.name)) : entry.name.endsWith('.html') ? [path.join(dir, entry.name)] : []) }
const errors = new Set()
let checked = 0
const pages = files(root)
for (const page of pages) {
  const html = readFileSync(page, 'utf8')
  for (const match of html.matchAll(/<(?:a|img|script|link)\b[^>]*?\s(?:href|src)="([^"]+)"/g)) {
    const href = match[1].replaceAll('&amp;', '&')
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) continue
    const url = new URL(href, `https://site.invalid${base}${path.relative(root, page).split(path.sep).join('/')}`)
    const relative = decodeURIComponent(url.pathname)
    if (!relative.startsWith(base)) { errors.add(`${path.relative(root, page)} → ${href} (outside site base)`); continue }
    const target = path.join(root, relative.slice(base.length))
    checked++
    if (!file(target) && !file(`${target}.html`) && !file(path.join(target, 'index.html'))) errors.add(`${path.relative(root, page)} → ${href}`)
  }
}
if (errors.size) { console.error([...errors].join('\n')); throw new Error(`${errors.size} broken internal links`) }
console.log(`Checked ${checked} internal links across ${pages.length} pages; no missing targets.`)

// Includes can silently resolve to an empty body while navigation still builds.
// Every canonical KB page must render its article heading in both locales.
const kbPages = files(path.join(root, 'kb')).filter(page => !aliases[path.relative(root, page).split(path.sep).join('/')])
for (const page of kbPages) {
  const relative = path.relative(root, page)
  const heading = readFileSync(page, 'utf8').match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/)?.[1]
  assert.ok(heading, `Missing KB article heading: ${relative}`)
  const translated = path.join(root, 'en', relative)
  assert.ok(file(translated), `Missing English KB page: ${relative}`)
  const englishHeading = readFileSync(translated, 'utf8').match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/)?.[1]
  assert.equal(englishHeading, heading, `Missing or different English KB article heading: ${relative}`)
}
console.log(`Checked article content in both locales for ${kbPages.length} KB pages.`)

const publicRoot = `${(process.env.VITEPRESS_SITE_URL || 'https://ling71671.github.io/open-reverselab').replace(/\/$/, '')}/`
const sitemap = readFileSync(path.join(root, 'sitemap.xml'), 'utf8')
const sitemapUrls = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>|<xhtml:link\b[^>]*\bhref="([^"]+)"/g)].map(match => match[1] || match[2])
assert.ok(sitemapUrls.length > 0, 'The sitemap must contain published pages')
for (const url of sitemapUrls) {
  assert.ok(url.startsWith(publicRoot), `Sitemap URL outside project path: ${url}`)
  const relative = decodeURIComponent(url.slice(publicRoot.length))
  assert.notEqual(relative, '404.html', 'Do not submit the error page for indexing')
  assert.ok(!aliases[relative.replace(/^en\//, '')], `Legacy redirect in sitemap: ${url}`)
  assert.ok(file(path.join(root, relative || 'index.html')) || file(path.join(root, relative, 'index.html')), `Missing sitemap destination: ${url}`)
}
console.log(`Checked ${sitemapUrls.length} sitemap page and language URLs; all retain the public project path.`)
