export const meta = {
  name: 'ctf-asset-discovery',
  description: 'CTF digital asset discovery — crt.sh, DNS, WHOIS, HTTP probe, email security, search exposure, synthesis',
  phases: [
    { title: '证书透明发现' },
    { title: 'DNS 全量记录' },
    { title: 'WHOIS / ASN' },
    { title: '主站 HTTP 指纹' },
    { title: '邮件安全配置' },
    { title: '搜索引擎 & 代码暴露' },
    { title: '综合研判' },
  ]
}

// ============================================================
// args 规范：
//   string               → 直接当 domain
//   object.domain        → 目标域名
//   object.caseDir       → 案例目录（可选，不传则不写文件）
// ============================================================
const _domain = typeof args === 'string' ? args : args?.domain || 'example.edu.cn'
const _caseDir = typeof args === 'object' && args?.caseDir ? args.caseDir : null
const domain = _domain
const caseDir = _caseDir

const CRTSH_PROMPT = [
  `Query crt.sh for all subdomain certificate transparency records of ${domain}.`,
  '',
  'Steps:',
  `1. Use WebFetch to access: https://crt.sh/?q=%25.${domain}&output=json`,
  `   If JSON is too large, try: https://crt.sh/?q=%25.${domain}&output=json&limit=500`,
  '2. Parse the JSON, extract all "name_value" fields',
  '3. Deduplicate, sort, remove wildcard prefix from *. entries',
  `4. Also query: https://crt.sh/?q=%25.${domain}&output=json&deduplicate=Y`,
  '5. Statistics to report:',
  '   - Total unique subdomain count',
  `   - Wildcard certificate list (*.${domain}, *.xxx.${domain})`,
  '   - Subdomains newly appeared in last 90 days (check entry_timestamp)',
  '   - Categorize by function: mail.*, www.*, idp.*, sso.*, cas.*, vpn.*, lib.*, *.lib.*, etc.',
  '',
  'Return format:',
  '- unique_subdomains: full list (one per line)',
  '- total_count: number',
  '- wildcard_certs: list',
  '- recent_90d: list of recently seen subdomains',
  '- categorized: grouped by function/category',
].join('\n')

const DNS_PROMPT = [
  `Perform comprehensive DNS enumeration for ${domain}.`,
  '',
  'Use Bash to run the following commands. If dig is unavailable, use nslookup.',
  '',
  `1. A records: dig +short A ${domain}, dig +short A www.${domain}`,
  `2. AAAA records: dig +short AAAA ${domain}`,
  `3. MX records: dig +short MX ${domain}, then PTR reverse lookup on each MX IP`,
  `4. NS records: dig +short NS ${domain}, then get IP of each NS`,
  `5. TXT records: dig +short TXT ${domain}, especially check for SPF (v=spf1)`,
  `6. SOA record: dig +short SOA ${domain}`,
  `7. CNAME check for these subdomains (dig +short CNAME <sub>.${domain}):`,
  '   www, mail, webmail, idp, sso, login, portal, vpn, cas, lib, library,',
  '   admin, api, cdn, static, assets, media, news, blog, wiki, git,',
  '   oa, jw, yjs, cwc, xsc, yb, zs, jwc, sky, ele, met,',
  '   passport, auth, oauth, openid, saml, ldap,',
  '   mail2, smtp, imap, pop3, webvpn, sslvpn',
  '8. Zone transfer attempt: dig AXFR <domain> @<each NS server>',
  `9. SRV records: dig +short SRV _ldap._tcp.${domain}, dig +short SRV _sip._tcp.${domain}`,
  '',
  'Report status for each record type (found / not found / timeout).',
].join('\n')

const WHOIS_PROMPT = [
  `Look up WHOIS info and IP ownership for ${domain}.`,
  '',
  '1. WHOIS lookup via WebFetch:',
  `   - https://whois.aliyun.com/domain/${domain}`,
  `   - or https://whois.chinaz.com/${domain}`,
  '2. Extract: Registrant Organization, Registration/Expiry dates, DNS servers, Contact info, IP ranges',
  '3. ASN lookup via Bash:',
  `   - Get A record IPs of ${domain} first`,
  '   - whois <IP> | grep -i "origin|AS|netname|descr|country"',
  '   - Or: curl https://api.bgpview.io/ip/<IP>',
  '4. IP range expansion:',
  '   - Use WebFetch to search bgpview for the organization name found in WHOIS',
  '5. Geolocation: city/province of IPs, CDN frontend detection (Cloudflare/Aliyun CDN)',
  '',
  'Return complete WHOIS + ASN + IP range intelligence.',
].join('\n')

const HTTP_PROBE_PROMPT = [
  `Perform comprehensive HTTP/HTTPS fingerprinting on ${domain} and key subdomains.`,
  '',
  'Use MCP tool http_probe (load via ToolSearch if needed), or fallback to WebFetch/curl.',
  '',
  'Primary targets:',
  `1. https://${domain} (and http:// redirect check)`,
  `2. https://www.${domain}`,
  `3. https://mail.${domain}`,
  `4. https://cas.${domain}`,
  `5. https://idp.${domain}`,
  `6. https://vpn.${domain}`,
  `7. https://lib.${domain}`,
  `8. https://jw.${domain}`,
  `9. https://yjs.${domain}`,
  `10. https://zs.${domain}`,
  '',
  'For each target, collect:',
  '- HTTP status code and redirect chain',
  '- Server header (nginx/Apache/IIS/...)',
  '- X-Powered-By header',
  '- Set-Cookie headers (session mechanism, cookie flags)',
  '- Security headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS, X-XSS-Protection',
  '- All custom X-* headers',
  '- Response body CMS fingerprints (meta generator, powered-by comments)',
  '- SSL certificate details (issuer, expiry, SAN list)',
  '',
  'WAF/CDN detection:',
  '- Cloudflare: cf-ray header, __cfduid cookie, Server: cloudflare',
  '- Aliyun WAF: X-Client-Ip, ali-cdn headers',
  '- Custom school WAF',
  '- CDN provider identification',
  '',
  'Tech stack detection:',
  '- Frontend framework (React/Vue/jQuery — check HTML/JS patterns)',
  '- CMS identification',
  '- Backend language inference (PHP session/Java JSESSIONID/.NET ASP.NET/Python)',
  '',
  'Return complete HTTP fingerprint and tech stack analysis per target.',
].join('\n')

const EMAIL_SECURITY_PROMPT = [
  `Analyze email security configuration for ${domain}.`,
  '',
  'Run DNS queries via Bash:',
  '',
  `1. SPF: dig +short TXT ${domain} | grep "v=spf1"`,
  '   Analyze: is the policy too permissive (+all / ?all)? What IPs/services are included?',
  '2. DKIM:',
  `   dig +short TXT default._domainkey.${domain}`,
  `   dig +short TXT google._domainkey.${domain}`,
  `   dig +short TXT selector1._domainkey.${domain}`,
  `   dig +short TXT selector2._domainkey.${domain}`,
  `3. DMARC: dig +short TXT _dmarc.${domain}`,
  '   Analyze policy: p=none / p=quarantine / p=reject / not found',
  '4. MX security: for each MX server, check STARTTLS support, PTR record, blacklist status',
  `5. BIMI: dig +short TXT default._bimi.${domain}`,
  `6. MTA-STS: try https://mta-sts.${domain}/.well-known/mta-sts.txt`,
  '7. DNS security:',
  `   - DNSSEC: dig +dnssec DNSKEY ${domain}`,
  `   - CAA: dig +short CAA ${domain}`,
  '',
  'Return email security posture assessment with spoofing risk levels.',
].join('\n')

const SEARCH_EXPOSURE_PROMPT = [
  `Search for ${domain} exposure in search engines and code repositories.`,
  '',
  '1. GitHub search (WebFetch):',
  `   - https://github.com/search?q=${domain}&type=code`,
  `   - https://github.com/search?q=%22${domain}%22+password&type=code`,
  `   - https://github.com/search?q=%22${domain}%22+key&type=code`,
  `   - https://github.com/search?q=%22${domain}%22+token&type=code`,
  `   - https://github.com/search?q=%22${domain}%22+secret&type=code`,
  `   - https://github.com/search?q=${domain}&type=repositories`,
  '   Look for leaked API keys, passwords, config files, database URIs.',
  '',
  '2. Google Dork via WebSearch:',
  `   - site:${domain} filetype:pdf (sensitive PDFs)`,
  `   - site:${domain} filetype:xls OR filetype:xlsx (spreadsheets)`,
  `   - site:${domain} filetype:sql (database backups)`,
  `   - site:${domain} inurl:admin`,
  `   - site:${domain} inurl:login`,
  `   - site:${domain} intitle:"index of"`,
  `   - site:${domain} ext:env OR ext:yml OR ext:json (config files)`,
  `   - site:${domain} ext:bak OR ext:backup OR ext:old`,
  '',
  `3. Wayback Machine: https://web.archive.org/web/*/${domain}`,
  `4. Paste sites: site:pastebin.com ${domain}, site:codepad.org ${domain}`,
  '',
  'Return all exposure findings with risk ratings.',
].join('\n')

const SYNTHESIS_PROMPT = [
  `You are the synthesis analyst for digital asset reconnaissance. Below are multi-dimensional`,
  `collection results for ${domain}. Synthesize everything and produce the following deliverables.`,
  '',
  '## Tasks',
  '',
  '1. MERGE & DEDUP subdomain list — combine crt.sh and DNS results, deduplicate, categorize by function',
  '',
  '2. ATTACK SURFACE ASSESSMENT — based on all results, list:',
  '   - Internet-facing services (what services/ports are exposed)',
  '   - Authentication portals (SSO/IDP/CAS/VPN/email login pages)',
  '   - Infrastructure exposure (DNS servers, mail servers)',
  '   - Third-party dependencies (CDN, cloud services, external components)',
  '   - Information leaks (GitHub, search engines, config files)',
  '',
  '3. RISK RATING per finding:',
  '   - Critical: remote code execution, authentication bypass',
  '   - High: sensitive info disclosure, configuration weakness',
  '   - Medium: tech stack exposure, fingerprintable',
  '   - Low: info gathering, harmless exposure',
  '   - Info: notes',
  '',
  '4. Write 01-recon.md reconnaissance notes in Chinese (full content, do not abbreviate subdomain lists):',
  caseDir ? `   Use the Write tool to save to: ${caseDir}\\notes\\01-recon.md` : '   Output the full content below',
  '   Sections:',
  '   1. 资产范围',
  '   2. 子域名清单 (full list + categorized stats)',
  '   3. DNS 情报',
  '   4. IP 段 & ASN',
  '   5. Web 指纹',
  '   6. 邮件安全',
  '   7. 暴露面',
  '   8. 攻击面总结',
  '   9. 下一步行动建议',
  caseDir ? `10. Also write fingerprints.json to: ${caseDir}\\fingerprints.json (structured subdomain→tech mapping)` : '',
  '',
  'Output everything in full — do not abbreviate subdomain lists.',
].join('\n')

// ============================================================
// Parallel collection — all 6 agents launch simultaneously
// ============================================================
const [crtshResult, dnsResult, whoisResult, httpResult, emailResult, searchResult] = await parallel([
  () => agent(CRTSH_PROMPT, { label: 'crt.sh', phase: '证书透明发现' }),
  () => agent(DNS_PROMPT, { label: 'DNS', phase: 'DNS 全量记录' }),
  () => agent(WHOIS_PROMPT, { label: 'WHOIS', phase: 'WHOIS / ASN' }),
  () => agent(HTTP_PROBE_PROMPT, { label: 'HTTP probe', phase: '主站 HTTP 指纹' }),
  () => agent(EMAIL_SECURITY_PROMPT, { label: 'Email security', phase: '邮件安全配置' }),
  () => agent(SEARCH_EXPOSURE_PROMPT, { label: 'Search exposure', phase: '搜索引擎 & 代码暴露' }),
])

// ============================================================
// Synthesize
// ============================================================
phase('综合研判')
const synthesisInput = [
  '=== crt.sh Certificate Transparency ===',
  crtshResult || '(no result)',
  '',
  '=== DNS Full Records ===',
  dnsResult || '(no result)',
  '',
  '=== WHOIS / ASN ===',
  whoisResult || '(no result)',
  '',
  '=== HTTP Fingerprints ===',
  httpResult || '(no result)',
  '',
  '=== Email Security ===',
  emailResult || '(no result)',
  '',
  '=== Search Engine & Code Exposure ===',
  searchResult || '(no result)',
].join('\n')

const synthesisResult = await agent(SYNTHESIS_PROMPT + '\n\n' + synthesisInput, {
  label: 'Synthesis',
  phase: '综合研判',
})

return {
  domain,
  crtsh: crtshResult,
  dns: dnsResult,
  whois: whoisResult,
  http: httpResult,
  email: emailResult,
  search: searchResult,
  synthesis: synthesisResult,
}
