// Sync ../kb into site/kb before dev/build.
// Windows junctions break Vite's module resolution for VitePress pages,
// so we copy instead. Replace the generated tree to also reflect moves/deletions.
import { existsSync, rmSync, cpSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const siteRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const kbLink = path.join(siteRoot, 'kb')
const kbSource = path.resolve(siteRoot, '..', 'kb')

if (!existsSync(kbSource)) throw new Error(`Knowledge source not found: ${kbSource}`)
if (path.relative(siteRoot, kbLink) !== 'kb' || kbLink === kbSource) throw new Error('Invalid generated KB directory')
// rmSync unlinks a junction itself; it does not traverse its source directory.
rmSync(kbLink, { recursive: true, force: true })
cpSync(kbSource, kbLink, { recursive: true, force: true })
console.log(`synced kb/ -> ${kbLink}`)
