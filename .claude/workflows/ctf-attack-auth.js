export const meta = {
  name: 'ctf-attack-auth',
  description: 'Auth worker: JWT, OAuth/OIDC, SAML, Host Header, LDAP, session/cookie trust boundaries',
  phases: [
    { title: 'KB 路由' },
    { title: '认证攻击验证' },
    { title: '证据写回' },
  ],
}

const target = typeof args === 'string' ? args : args?.target || ''
if (!target) throw new Error('ctf-attack-auth requires args.target or string target')
const caseName = typeof args === 'object' && args?.caseName ? args.caseName : ''
const manifest = typeof args === 'object' && args?.manifest ? args.manifest : ''
if (!caseName || !manifest) throw new Error('ctf-attack-auth requires args.caseName and args.manifest')
const reportRoot = typeof args === 'object' && args?.reportRoot ? args.reportRoot : 'reports/ctf-website'
const innerIterations = typeof args === 'object' && args?.innerIterations ? Number(args.innerIterations) : 0

phase('KB 路由')
const kb = await agent(
  `为 auth 攻击读取 KB。必须运行：
\`\`\`bash
python3 scripts/ctf-website/kb_router.py "jwt oauth saml host header ldap session cookie"
\`\`\`
读取 JWT 子库、OAuth/OIDC、SAML、Host Header、LDAP、session/cookie 技术文件。`,
  { label: 'auth-kb', phase: 'KB 路由' },
)

phase('认证攻击验证')
const result = await agent(
  `对 ${target} 做一轮认证攻击 worker。

Manifest: ${manifest}
Inner iterations: ${innerIterations || 'until convergence/status change'}
KB:
${kb}

任务：
0. 内部循环协议：plan → execute auth/session variant → observe response/cookie/token → mutate claim/header/redirect/session → retry。不要只试一次；未设置 innerIterations 时迭代到证据确认、路径证伪或状态变化。
1. 登录/SSO/OAuth/OIDC/SAML 端点枚举：/.well-known/openid-configuration、/oauth/authorize、/cas/login、/saml。
2. JWT：alg none/confusion、kid/jku/x5u、弱密钥、claim 缺失、过长 exp、replay。
3. OAuth/OIDC：redirect_uri、state/nonce、PKCE、client_secret 泄露、open redirect chain。
4. SAML：XML wrapping、签名验证、NameID/attribute 注入。
5. Host Header：password reset poisoning、X-Forwarded-Host、vhost confusion。
6. Session/cookie：HttpOnly/Secure/SameSite、Domain/Path、session fixation、logout replay。

不等待人工；需要凭据的路径记录到 next_round_focus 或 dead_ends，然后切换到可自动验证路径。
输出 JSON: evidence_added, dead_ends_added, next_round_focus, signals_seen。`,
  { label: 'auth-run', phase: '认证攻击验证' },
)

phase('证据写回')
const summary = await agent(
  `合并 auth 结果到 ${manifest}，写 ${reportRoot}/${caseName}/attack-auth.md。

Auth result:
${result}

只输出 JSON: {"status":"CONTINUE|DONE|EXHAUSTED","report":"<path>","next_round_focus":[]}`,
  { label: 'auth-writeback', phase: '证据写回' },
)

return { target, caseName, manifest, kb, result, summary }
