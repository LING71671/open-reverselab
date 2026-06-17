# Web CTF Attack Matrix

Use this after the first 30-minute baseline to avoid tunnel vision.

| Surface | If You See | Try |
|---|---|---|
| Login | username/password JSON | SQLi/NoSQLi, timing, default creds, password reset |
| JWT | bearer or cookie JWT | alg/kid/jku, weak secret, claim trust |
| Upload | image/pdf/archive | extension confusion, MIME, polyglot, zip slip, parser SSRF |
| URL import | image/webhook/link preview | SSRF, redirect, DNS, IPv6, internal names |
| Template preview | email/report/theme | SSTI, include/import, sandbox escape |
| Search/filter | q/sort/order | SQLi/NoSQLi, regex DoS, prototype pollution |
| GraphQL | `/graphql` | introspection, batching, field auth |
| WebSocket | realtime app | replay, IDOR, sequencing, race |
| Admin bot | URL submission | XSS, CSP bypass, cookie exfil via allowed channel |
| Cache/proxy | `X-Cache` | unkeyed header, host poison, request smuggling |
| Export/report | PDF/HTML render | SSRF, local file, XSS in renderer |
| Source maps | `.map` files | API endpoints, secrets, route names, old code |

Rule: if a path has no developer-plausible route to the secret, pivot.
