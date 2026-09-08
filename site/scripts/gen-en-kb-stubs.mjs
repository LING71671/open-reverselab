// Generate English-locale stubs for the knowledge base: site/en/kb/**.
//
// The KB content stays Chinese (site pages only — the main repo is untouched),
// but the /en/ locale needs real pages so the English site chrome (nav,
// sidebar, search) wraps the KB. Each stub is a VitePress markdown include that
// pulls the original file's body, so there is no content duplication:
//
//   site/en/kb/ctf-website/README.md  ->  <!-- @include: /kb/ctf-website/README.md -->
//
// Run AFTER scripts/ensure-kb.mjs (site/kb must exist). Files in site/en/kb
// that no longer exist under site/kb are removed, keeping the copy in sync.
import { existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const siteRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const kbDir = path.join(siteRoot, 'kb')
const enKbDir = path.join(siteRoot, 'en', 'kb')

function collectMdFiles(dir, base = dir) {
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...collectMdFiles(full, base))
    } else if (entry.name.endsWith('.md')) {
      out.push(path.relative(base, full).split(path.sep).join('/'))
    }
  }
  return out
}

if (!existsSync(kbDir)) {
  console.error('site/kb not found — run scripts/ensure-kb.mjs first')
  process.exit(1)
}

const sourceFiles = collectMdFiles(kbDir)
let written = 0

for (const rel of sourceFiles) {
  const stubPath = path.join(enKbDir, rel)
  mkdirSync(path.dirname(stubPath), { recursive: true })
  const include = `<!-- @include: /kb/${rel.split(path.sep).join('/')} -->\n`
  let needsWrite = true
  if (existsSync(stubPath)) {
    try {
      needsWrite = statSync(stubPath).mtimeMs < statSync(path.join(kbDir, rel)).mtimeMs
    } catch {
      needsWrite = true
    }
  }
  if (needsWrite) {
    writeFileSync(stubPath, include, 'utf-8')
    written++
  }
}

// Remove stubs whose source KB file is gone.
let removed = 0
const walk = (dir) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full)
    else {
      const rel = path.relative(enKbDir, full).split(path.sep).join('/')
      if (!sourceFiles.includes(rel)) {
        rmSync(full, { force: true })
        removed++
      }
    }
  }
}
if (existsSync(enKbDir)) walk(enKbDir)

console.log(`en/kb stubs: ${sourceFiles.length} files (${written} written, ${removed} removed)`)
