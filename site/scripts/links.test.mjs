import assert from 'node:assert/strict'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { documentLink } from './links.mjs'
const site = fileURLToPath(new URL('..', import.meta.url))
test('document-relative links stay stable during a route transition', () => {
  assert.equal(documentLink('techniques/README.md', 'kb/windows/README.md', site), '/kb/windows/techniques/README.md')
  assert.equal(documentLink('notepadpp-config-injection.md#details', 'en/kb/windows/techniques/README.md', site), '/en/kb/windows/techniques/notepadpp-config-injection.md#details')
  assert.equal(documentLink('#details', 'kb/windows/README.md', site), '#details')
})
test('repository-only files link to source, not nonexistent HTML pages', () => {
  assert.equal(documentLink('../.github/CONTRIBUTING.md', 'kb/README.md', site), 'https://github.com/LING71671/open-reverselab/blob/main/.github/CONTRIBUTING.md')
  assert.equal(documentLink('crypto/04-rsa-attack-family.selftest.py', 'kb/general/techniques/README.md', site), 'https://github.com/LING71671/open-reverselab/blob/main/kb/general/techniques/crypto/04-rsa-attack-family.selftest.py')
})
