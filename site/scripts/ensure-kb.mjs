// Sync ../kb into site/kb before dev/build.
// Windows junctions break Vite's module resolution for VitePress pages,
// so we copy instead. Copies only when the source tree is newer.
import { existsSync, rmSync, cpSync, statSync, lstatSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const siteRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const kbLink = path.join(siteRoot, 'kb')
const kbSource = path.resolve(siteRoot, '..', 'kb')

function newestMtime(dir) {
  let newest = 0
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      newest = Math.max(newest, newestMtime(full))
    } else {
      newest = Math.max(newest, statSync(full).mtimeMs)
    }
  }
  return newest
}

// Windows junctions break Vite's module resolution for VitePress pages:
// treat any symlink/junction as stale and rebuild as a real directory.
const isLink = () => {
  try {
    return lstatSync(kbLink).isSymbolicLink()
  } catch {
    return false
  }
}

const needsCopy = () => {
  if (!existsSync(kbLink) || isLink()) return true
  try {
    const st = statSync(kbLink)
    if (!st.isDirectory()) return true
  } catch {
    return true
  }
  return newestMtime(kbSource) > newestMtime(kbLink)
}

if (needsCopy()) {
  rmSync(kbLink, { recursive: true, force: true })
  cpSync(kbSource, kbLink, { recursive: true, force: true })
  console.log(`synced kb/ -> ${kbLink}`)
} else {
  console.log('kb/ is up to date')
}
