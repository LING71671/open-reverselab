import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const root = path.join(site, '.vitepress/dist')
const base = process.env.VITEPRESS_BASE || '/'
const aliases = JSON.parse(readFileSync(new URL('./legacy-routes.json', import.meta.url), 'utf8'))
const file = name => { try { return statSync(name).isFile() } catch { return false } }
for (const locale of ['', 'en/']) for (const [old, target] of Object.entries(aliases)) {
  if (!file(path.join(root, locale, target))) throw new Error(`Missing redirect destination: ${locale}${target}`)
  const destination = `${base}${locale}${target}`
  const output = path.join(root, locale, old)
  mkdirSync(path.dirname(output), { recursive: true })
  writeFileSync(output, `<!doctype html><html lang="${locale ? 'en' : 'zh-CN'}"><meta charset="utf-8"><meta name="robots" content="noindex"><link rel="canonical" href="${destination}"><title>Open ReverseLab</title><script>location.replace(${JSON.stringify(destination)}+location.search+location.hash)</script><a href="${destination}">${locale ? 'Open technique index' : '打开技术索引'}</a></html>`)
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
