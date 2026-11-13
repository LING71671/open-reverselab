import path from 'node:path'
import { existsSync } from 'node:fs'

// Resolve against the document, even while the address bar is changing routes.
export function documentLink(href, page, siteRoot) {
  if (!href || /^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) return href
  const match = href.match(/^([^?#]*)(.*)$/s)
  const [, body, suffix] = match
  const target = path.posix.normalize(body.startsWith('/') ? body : `/${path.posix.dirname(page)}/${body}`)
  const source = target.replace(/^\/en\/kb\//, '/kb/')
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
    if (!/^(en\/)?kb\//.test(page)) return
    const visit = tokens => {
      for (const token of tokens) {
        if (token.type === 'link_open') token.attrSet('href', documentLink(token.attrGet('href'), page, siteRoot))
        if (token.children) visit(token.children)
      }
    }
    visit(state.tokens)
  })
}
