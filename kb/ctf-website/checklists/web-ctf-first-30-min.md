# Web CTF First 30 Minutes

## 0-5 min: Baseline

- Record URL, host, port, scheme, and challenge text.
- `curl -i -k <url>`: status, redirects, cookies, server headers.
- Check robots, sitemap, common static paths, source maps.
- Save JS bundle list and API route hints.
- Identify auth model: cookie, JWT, session id, localStorage, CSRF.

## 5-15 min: Surface Map

- Enumerate obvious routes manually before brute force.
- Inspect forms, hidden fields, JSON APIs, upload endpoints.
- Try method changes: `GET/POST/PUT/PATCH/DELETE/OPTIONS`.
- Try content types: form, JSON, XML, multipart.
- Check state transitions: register -> login -> profile -> admin -> export.

## 15-25 min: Bug-Class Probes

- Reflected/stored sinks: XSS/HTML injection/CRLF.
- Backend errors: SQLi, NoSQLi, SSTI, template parse errors.
- URL fetchers: SSRF, redirect handling, DNS-only callbacks.
- File paths: traversal, upload extraction, include/import.
- Token logic: JWT alg/kid/jku, weak secret, unsigned tokens.
- Race/cache: duplicate coupon, reset token reuse, cache key mismatch.

## 25-30 min: Decide Path

- Pick the strongest signal, not the most familiar exploit class.
- Record dead ends with evidence.
- If frontend looks rich/obfuscated, switch to JSHook/browser runtime.
- If no signal, enumerate parameters and hidden routes with targeted wordlists.
