import assert from 'node:assert/strict'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { documentLink, legacyRedirect, loadLegacyRoutes } from './links.mjs'
const site = fileURLToPath(new URL('..', import.meta.url))
test('document-relative links stay stable during a route transition', () => {
  assert.equal(documentLink('techniques/README.md', 'kb/shared/windows/README.md', site), '/kb/shared/windows/techniques/README.md')
  assert.equal(documentLink('notepadpp-config-injection.md#details', 'en/kb/shared/windows/techniques/README.md', site), '/en/kb/red/windows/techniques/notepadpp-config-injection.md#details')
  assert.equal(documentLink('#details', 'kb/shared/windows/README.md', site), '#details')
})
test('repository-only files link to source, not nonexistent HTML pages', () => {
  assert.equal(documentLink('../.github/CONTRIBUTING.md', 'kb/README.md', site), 'https://github.com/LING71671/open-reverselab/blob/main/.github/CONTRIBUTING.md')
  assert.equal(documentLink('../.github/CONTRIBUTING.md', 'en/kb/README.md', site), 'https://github.com/LING71671/open-reverselab/blob/main/.github/CONTRIBUTING.md')
  assert.equal(documentLink('crypto/04-rsa-attack-family.selftest.py', 'kb/shared/general/techniques/README.md', site), 'https://github.com/LING71671/open-reverselab/blob/main/kb/shared/general/techniques/crypto/04-rsa-attack-family.selftest.py')
})
test('legacy knowledge links retain the locale, query and fragment after migration', () => {
  assert.equal(documentLink('/kb/general/techniques/attack-network.md?view=graph#ai-security', 'en/index.md', site), '/en/kb/red/general/techniques/attack-network.md?view=graph#ai-security')
  assert.equal(documentLink('/kb/general/techniques/defense-network.html#ai-security', 'index.md', site), '/kb/blue/general/techniques/defense-network.html#ai-security')
  assert.equal(documentLink('/kb/ctf-website/README', 'index.md', site), '/kb/shared/ctf-website/README')
  assert.equal(documentLink('/kb/red/general/README.md', 'kb/README.md', site), '/kb/red/general/README.md')
})
test('dev redirects handle old routes, duplicate techniques paths and deployment bases', () => {
  assert.equal(legacyRedirect('/kb/general/techniques/techniques/attack-network.html?view=graph#ai-security'), '/kb/red/general/techniques/attack-network.html?view=graph#ai-security')
  assert.equal(legacyRedirect('/open-reverselab/en/kb/general/techniques/defense-network', '/open-reverselab/'), '/open-reverselab/en/kb/blue/general/techniques/defense-network.html')
  assert.equal(legacyRedirect('/kb/windows/techniques/techniques/README.md'), '/kb/shared/windows/techniques/README.html')
  assert.equal(legacyRedirect('/kb/general/'), '/kb/shared/general/README.html')
  assert.equal(legacyRedirect('/kb/red/general/README.html'), null)
  assert.equal(legacyRedirect('/kb/general/README.html', '/open-reverselab/'), null)
})
test('static redirects cover the same attack and defense destinations as dev', () => {
  const routes = loadLegacyRoutes()
  assert.equal(routes['kb/general/techniques/attack-network.html'], 'kb/red/general/techniques/attack-network.html')
  assert.equal(routes['kb/general/techniques/defense-network.html'], 'kb/blue/general/techniques/defense-network.html')
  for (const [old, target] of Object.entries(routes)) {
    assert.equal(legacyRedirect('/' + old), '/' + target)
    assert.equal(legacyRedirect('/en/' + old), '/en/' + target)
  }
})
