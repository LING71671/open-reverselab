export const meta = {
  name: 'ctf-dos-assessment',
  description: 'DoS attack surface assessment — map all 13 DoS techniques to discovered targets, run safe probes, rate exploitability',
  phases: [
    { title: '技术-目标映射' },
    { title: '应用层 & 协议栈探测' },
    { title: 'TLS & HTTP/2 探测' },
    { title: 'ReDoS & 算法复杂度' },
    { title: 'DNS & 邮件安全探测' },
    { title: 'API & 端点枚举' },
    { title: '综合研判' },
  ]
}

// args: { domain, targets: [...], fingerprints: {...}, caseDir?: string }
const domain = typeof args === 'string' ? args : args?.domain || 'example.edu.cn'
const targets = (typeof args === 'object' && args?.targets) ? args.targets : [
  { host: domain, ip: null, stack: 'unknown', cdn: null, waf: null, h2: null },
  { host: `www.${domain}`, ip: null, stack: 'unknown', cdn: null, waf: null, h2: null },
  { host: `api.${domain}`, ip: null, stack: 'unknown', cdn: null, waf: null, h2: null },
  { host: `admin.${domain}`, ip: null, stack: 'unknown', cdn: null, waf: null, h2: null },
  { host: `auth.${domain}`, ip: null, stack: 'unknown', cdn: null, waf: null, h2: null },
]
const DNS_NS = (typeof args === 'object' && args?.dnsNs) ? args.dnsNs : []
const geofenced = (typeof args === 'object' && args?.geofenced) ? args.geofenced : [`cas.${domain}`, `idp.${domain}`, `vpn.${domain}`, `webvpn.${domain}`]
const unprobed = (typeof args === 'object' && args?.unprobed) ? args.unprobed : [`dev.${domain}`, `test.${domain}`, `staging.${domain}`, `internal.${domain}`]

const targetsList = targets.map(t => `https://${t.host}`).join('\n')
const targetDetails = JSON.stringify(targets, null, 2)
const dosCaseDir = (typeof args === 'object' && args?.caseDir) ? args.caseDir : null

// ============================================================
// Phase 1: Map techniques to targets
// ============================================================
phase('技术-目标映射')

const MAPPING_PROMPT = [
  `Map all 13 DoS technique categories below to the ${domain} target list.`,
  'For each technique, determine applicability per target and output a priority-ordered execution plan.',
  '',
  '## Targets',
  targetDetails,
  '',
  `Also: DNS infrastructure: ${DNS_NS.length ? DNS_NS.join(', ') : 'unknown; enumerate from NS records first'}`,
  `Geofenced (China-IP only): ${geofenced.join(', ')}`,
  `Discovered but unprobed: ${unprobed.join(', ')}`,
  '',
  '## 13 DoS Techniques (from knowledge base)',
  '',
  '01. **Application-Layer DoS** — Slowloris, RUDY, HTTP/2 Rapid Reset (CVE-2023-44487), WebSocket fragment flood, GraphQL alias amplification. Targets connection pools, worker processes.',
  '02. **Resource Exhaustion** — HashDoS, XML Bomb, Zip Bomb, fd exhaustion, DB connection pool saturation, thread pool starvation, JSON depth attacks.',
  '03. **Amplification/DRDoS** — DNS/NTP/Memcached/CLDAP reflection with IP spoofing. Requires raw sockets + reflector list.',
  '04. **ReDoS** — Regex backtracking bombs via nested quantifiers on string input endpoints (email, phone, path, URL validation). O(2^n) CPU per request.',
  '05. **HTTP/2 CONTINUATION & H2 Advanced** — CONTINUATION Flood CVE-2024-27316 (OOM via missing END_HEADERS), HPACK bomb, Stream priority starvation, QUIC CID exhaustion.',
  '06. **TCP State Exhaustion** — SYN flood, Sockstress (zero-window persistence), TIME_WAIT exhaustion, netfilter conntrack overflow, socket buffer pressure.',
  '07. **DNS DoS** — Water Torture (random subdomains), NXDOMAIN flood, Phantom Domain attack, cache poisoning. Targets authoritative & recursive DNS.',
  '08. **TLS Exhaustion** — Incomplete handshake flood, renegotiation loop, oversized ClientHello, certificate chain bomb, session ticket churn.',
  '09. **Cache/CDN DoS** — Cache busting (random params), origin IP discovery, Range header abuse, cache poison DoS, CDN edge exhaustion.',
  '10. **API Abuse** — Deep pagination, batch amplification, rate limit bypass, search API abuse, webhook slow callback, file upload abuse.',
  '11. **Cloud/Container DoS** — K8s ResourceQuota exhaustion, HPA infinite scaling, serverless billing bomb, IMDS quota DoS, container resource escape.',
  '12. **SSRF-Driven DoS** — Internal service flooding, SSRF-to-Redis via Gopher, recursive SSRF, cloud metadata SSRF, file:// protocol blocking.',
  '13. **Database DoS** — Slow query injection, deadlock construction, connection pool saturation, WAL/binlog explosion, index degradation.',
  '',
  '## Task',
  'For EACH target, list which techniques are applicable (including rationale) and which are NOT applicable (with reason).',
  'Then produce a prioritized execution plan: SAFE probes first, LIGHT RISKY probes second, FULL ATTACK last (for CTF authorized only).',
  '',
  'Return a structured mapping table and execution plan.',
].join('\n')

const mappingResult = await agent(MAPPING_PROMPT, { label: '技术映射', phase: '技术-目标映射' })

// ============================================================
// Phase 2: SAFE Probes — 4 parallel groups
// ============================================================

const APP_LAYER_PROBE = [
  `Application-layer DoS vulnerability assessment for ${domain} targets. NON-DESTRUCTIVE probing only.`,
  '',
  '## Targets',
  targetsList,
  '',
  '## Target details',
  targetDetails,
  '',
  '## Tasks (SAFE probing only — measure, don\'t flood)',
  '',
  '### 1. Connection limit estimation',
  'For each target, use curl with keepalive to measure:',
  '- Max concurrent connections before server stops accepting (send 5, 10, 20 parallel requests)',
  '- Keep-Alive timeout (time between requests before connection dropped)',
  '- Connection header response: keep-alive enabled? timeout? max?',
  '',
  '### 2. Protocol behavior',
  '- HTTP/1.1 keep-alive: send multiple requests on same connection, measure',
  '- HTTP/2 support: curl --http2, check ALPN negotiation',
  '- WebSocket: check for Upgrade: websocket in responses or 101 switching',
  '- GraphQL: probe /graphql, /graphiql, /api/graphql endpoints',
  '',
  '### 3. Worker process inference',
  '- Send concurrent requests, measure response time degradation',
  '- Try sending incomplete headers (curl with custom header, no CRLF) — does connection timeout?',
  '- Check for X-Runtime or Server-Timing headers that leak processing time',
  '',
  '### 4. Request size / body limits',
  '- Send POST with increasing body sizes (1KB, 10KB, 100KB, 1MB) to find limits',
  '- Check Content-Length max (413? 500? connection reset?)',
  '',
  '### 5. Rate limit detection',
  '- Send 5 rapid requests to same endpoint, check for 429 or Retry-After header',
  '- Check if there\'s any rate limit header (X-RateLimit-*)',
  '',
  'Return per-target: connection behavior, protocol support, limits, rate-limiting status.',
].join('\n')

const TLS_H2_PROBE = [
  `TLS and HTTP/2 vulnerability assessment for ${domain} targets. NON-DESTRUCTIVE.`,
  '',
  '## Targets',
  targetsList,
  '',
  '## Tasks',
  '',
  '### 1. TLS version & cipher enumeration',
  'For each target use openssl s_client or curl to check:',
  '- Supported TLS versions (1.0, 1.1, 1.2, 1.3)',
  '- Cipher suite strength (weak ciphers? export-grade?)',
  '- Certificate chain depth',
  '- Session ticket support (check for session ticket TLS extension)',
  '- Session ID reuse (connect twice, check if same session ID offered)',
  '',
  '### 2. H2 ALPN negotiation',
  '- Check if h2 is advertised in ALPN',
  '- If yes, try HTTP/2 connection and check:',
  '  - Max concurrent streams (SETTINGS_MAX_CONCURRENT_STREAMS)',
  '  - Initial window size (SETTINGS_INITIAL_WINDOW_SIZE)',
  '  - Max frame size (SETTINGS_MAX_FRAME_SIZE)',
  '  - Max header list size (SETTINGS_MAX_HEADER_LIST_SIZE)',
  '',
  '### 3. H2 vulnerability surface',
  '- Check server version for known H2 CVEs:',
  '  - CVE-2023-44487 (Rapid Reset)',
  '  - CVE-2024-27316 (CONTINUATION Flood) — server header + version detection',
  '- Estimate server\'s stream concurrency tolerance',
  '',
  '### 4. Renegotiation check',
  '- Test if TLS renegotiation is allowed:',
  '  openssl s_client -connect <host>:443 (then send R command)',
  '- If allowed, test renegotiation rate (CVE-2011-1473 style)',
  '',
  '### 5. Certificate chain analysis',
  '- Chain length (how many intermediates)',
  '- Each cert\'s key size and signature algorithm',
  '- Any wildcard characteristics relevant to DoS (SAN count, etc.)',
  '',
  'Return per-target: TLS posture, H2 config, vulnerability surface.',
].join('\n')

const REDOS_API_PROBE = [
  `ReDoS and API abuse vulnerability assessment for ${domain} targets. SAFE probing only.`,
  '',
  '## Targets',
  targetsList,
  '',
  '## Target details',
  targetDetails,
  '',
  '## Tasks',
  '',
  '### 1. ReDoS — String input endpoint discovery',
  'For each target, extract from homepage HTML/JS:',
  '- All <form> inputs with text/email/search/url type',
  '- All query parameters in <a href> links',
  '- Any search functionality (search box, search form action)',
  '- URL path parameters (slugs, IDs, names)',
  '',
  'For each string input found, test ReDoS susceptibility:',
  '- Send normal input, measure response time (baseline)',
  '- Send input ending with repeated char + special: "aaaaaaaaaaaaaaaaaaaaaa!" (30 a\'s + !)',
  '- Send input with nested pattern: "aaaaaaaaaaaaaaaaaaaaaa@" (30 a\'s + @)',
  '- Compare response times: ratio > 3x = potential ReDoS',
  '- Report any endpoint where crafted input causes significant delay',
  '',
  '### 2. API endpoint enumeration',
  'For each target, probe common API paths:',
  '- /api, /api/v1, /api/v2',
  '- /v1, /v2',
  '- /graphql, /graphiql',
  '- /swagger-ui.html, /swagger-resources, /api-docs',
  '- Check response bodies for JSON error messages (indicates API)',
  '',
  '### 3. Pagination / batch detection',
  '- Look for common pagination parameters: ?page=, ?offset=, ?limit=, ?size=, ?cursor=',
  '- Test extreme values: ?page=999999, ?offset=99999999',
  '- Measure response time for extreme pagination (potential DB full scan)',
  '',
  '### 4. Search API detection',
  '- If search functionality found, test:',
  '  - Empty search vs broad search vs narrow search (response time comparison)',
  '  - Special chars in search: *, ?, %, _, regex metacharacters',
  '  - Very long search string (1000+ chars)',
  '- Check for elasticsearch/lucene error messages',
  '',
  '### 5. File upload detection',
  '- Look for file upload forms (input type=file)',
  '- Check for upload endpoints: /upload, /file/upload, /api/upload',
  '- If found, note the path but DO NOT actually upload',
  '',
  'Return per-target: ReDoS candidate endpoints, API surface, pagination/search/upload vectors.',
].join('\n')

const DNS_EMAIL_PROBE = [
  `DNS and email infrastructure DoS assessment for ${domain}.`,
  '',
  '## Context',
  `- Authoritative NS: ${DNS_NS.length ? DNS_NS.join(', ') : 'unknown; enumerate with dig +short NS first'}`,
  '- MX/SPF/DKIM/DMARC/DNSSEC: enumerate live from DNS before assessing',
  '',
  '## Tasks',
  '',
  '### 1. DNS resilience probing',
  `- Test authoritative NS response times (dig @<ns> ${domain}, measure RTT)`,
  '- Test NS for ANY query support (amplification vector)',
  '- Test recursive resolver behavior: query random non-existent subdomains, check if NS is hit each time (Water Torture susceptibility)',
  '- Check SOA negative TTL (how long NXDOMAIN cached)',
  '- Check NS response size for standard queries (amplification factor)',
  '- Test both NS servers independently for availability (single point of failure?)',
  '',
  '### 2. Email infrastructure assessment',
  '- Check MX server response times',
  '- Test if MX servers accept oversized messages (EHLO banner analysis)',
  '- Check if MX has rate limiting (connect 3 times rapidly)',
  '- Test if STARTTLS is enforced or opportunistic',
  '- Check SPF include chain depth (DNS lookup amplification for SPF)',
  '- spf.mail.qq.com include chain: 7 sub-includes — each requires DNS lookup',
  '',
  '### 3. DNS cache behavior',
  `- Query www.${domain} with +norecurse to check TTL`,
  '- Measure TTL values: are they short (cache miss DoS potential) or long (stable)?',
  '- Check if DNS uses anycast (multiple IPs for same NS hostname)',
  '',
  '### 4. Phantom domain potential',
  '- Test if NS servers timeout or respond quickly to non-existent authoritative queries',
  '- Measure NS retry behavior on timeout',
  '',
  'Return: DNS DoS surface, email infrastructure weaknesses, amplification potential.',
].join('\n')

// ============================================================
// Phase 2-5: Execute all probes in parallel
// ============================================================
const [appLayerResult, tlsH2Result, redosApiResult, dnsEmailResult] = await parallel([
  () => agent(APP_LAYER_PROBE, { label: '应用层探测', phase: '应用层 & 协议栈探测' }),
  () => agent(TLS_H2_PROBE, { label: 'TLS/H2探测', phase: 'TLS & HTTP/2 探测' }),
  () => agent(REDOS_API_PROBE, { label: 'ReDoS/API', phase: 'ReDoS & 算法复杂度' }),
  () => agent(DNS_EMAIL_PROBE, { label: 'DNS/邮件', phase: 'DNS & 邮件安全探测' }),
])

// ============================================================
// Phase 6: Targeted deep probes based on initial results
// ============================================================
phase('API & 端点枚举')

const DEEP_PROBE_PROMPT = [
  `Deep API and endpoint enumeration for ${domain} targets, guided by initial probe results.`,
  '',
  '## Targets',
  targetDetails,
  targetsList,
  '',
  '## Phase 2 results',
  '=== App Layer ===',
  appLayerResult || '(none)',
  '',
  '### Tasks',
  '',
  '### 1. CMS / framework specific endpoints',
  'Based on fingerprintResult, adapt paths for Java/PHP/.NET/Node/Python stacks:',
  '- /admin, /admin/login, /system, /manage, /console',
  '- /api, /api/v1, /api/v2, /graphql, /graphiql',
  '- /swagger-ui.html, /api-docs, /v2/api-docs, /v3/api-docs',
  '- /actuator, /actuator/health, /actuator/env, /actuator/mappings',
  '- /search, /search.jsp, /search.php, /query',
  '- /upload, /uploads, /file/upload, /api/upload',
  '',
  '### 2. JS/API bundle analysis',
  '- Extract JS bundles from reachable pages',
  '- Grep for API base URLs, fetch/XHR/WebSocket endpoints, GraphQL queries',
  '- Identify pagination/search/filter endpoints and test extreme but safe values',
  '',
  '### 3. Auth / SSO / mail portals',
  '- Probe login page behavior and rate-limit headers',
  '- Record cookie/security headers and topology-leaking custom headers',
  '',
  '### 4. Search/code exposure driven endpoints',
  '- Use earlier GitHub/search exposure evidence to probe discovered hosts and APIs',
  '- Avoid hard-coded org-specific paths; only test paths supported by evidence',
  '',
  '### 5. SSRF endpoint discovery',
  '- On each target, search for redirect/fetch/proxy URL parameters',
  '- Test any found URL-accepting parameters with timing-based detection',
  '',
  'Return: deep endpoint map, SSRF vectors, CMS/framework-specific attack surface.',
].join('\n')

const deepProbeResult = await agent(DEEP_PROBE_PROMPT, { label: '深度端点', phase: 'API & 端点枚举' })

// ============================================================
// Phase 7: Synthesis
// ============================================================
phase('综合研判')

const synthesisInput = [
  '=== Technique-Target Mapping ===',
  mappingResult || '(none)',
  '',
  '=== 1. Application Layer Probe ===',
  appLayerResult || '(none)',
  '',
  '=== 2. TLS & HTTP/2 Probe ===',
  tlsH2Result || '(none)',
  '',
  '=== 3. ReDoS & API Probe ===',
  redosApiResult || '(none)',
  '',
  '=== 4. DNS & Email Probe ===',
  dnsEmailResult || '(none)',
  '',
  '=== 5. Deep Endpoint Probe ===',
  deepProbeResult || '(none)',
].join('\n')

const SYNTHESIS_PROMPT = [
  `You are the DoS attack surface synthesis analyst for ${domain}.`,
  'Synthesize all probe results into a comprehensive DoS vulnerability assessment.',
  '',
  '## Tasks',
  '',
  '### 1. Per-technique exploitability rating (for ALL 13 techniques)',
  'Rate each technique for EACH reachable target:',
  '- ✅ Exploitable: attack vector confirmed, conditions met',
  '- ⚠️ Potentially Exploitable: likely works but needs specific conditions or further verification',
  '- ❓ Unknown: insufficient data (needs more probing or internal access)',
  '- ❌ Not Applicable: target stack doesn\'t support this attack',
  '',
  '### 2. Attack chain synthesis',
  'Combine vectors where possible:',
  '- Example: ReDoS on search + no rate limiting = single attacker can pin CPU',
  '- Example: Cache busting + origin IP known + no CDN = direct origin attack trivial',
  '- Example: H2 Rapid Reset + no WAF = instant connection pool exhaustion',
  '',
  '### 3. Risk prioritization',
  'For each confirmed exploitable technique:',
  '- Likelihood of successful DoS (1-5)',
  '- Impact severity (1-5)',
  '- Ease of execution (1-5)',
  '- Prioritize by Risk = Likelihood × Impact',
  '',
  '### 4. Write the report',
  dosCaseDir
    ? `Use the Write tool to save the full DoS assessment to: ${dosCaseDir}\\dos-assessment.md`
    : 'Output the full DoS assessment below in markdown format',
  '',
  'Report structure:',
  '  1. 评估总览 — all 13 techniques × all targets matrix',
  '  2. 已确认利用向量 — detailed per confirmed exploitable',
  '  3. 潜在利用向量 — detailed per potentially exploitable',
  '  4. 攻击链分析 — combined attack scenarios',
  '  5. 防御差距 — what protections are missing',
  '  6. PoC 优先级排序 — which to verify first in next phase',
  '',
  'Return complete DoS assessment with exploitability matrix.',
].join('\n')

const synthesis = await agent(SYNTHESIS_PROMPT + '\n\n' + synthesisInput, {
  label: '综合研判',
  phase: '综合研判',
})

return {
  domain,
  mapping: mappingResult,
  appLayer: appLayerResult,
  tlsH2: tlsH2Result,
  redosApi: redosApiResult,
  dnsEmail: dnsEmailResult,
  deepProbe: deepProbeResult,
  synthesis,
}
