---
name: cors-misconfiguration
category: configuration
description: CORS misconfiguration detection
attack_types:
  - cors
  - misconfiguration
severity_range: [medium, high]
---

# CORS Misconfiguration Testing

## Phase 1: Baseline CORS Headers
Send request with `Origin: https://evil.com`:
- Check `Access-Control-Allow-Origin` response header
- Check `Access-Control-Allow-Credentials: true`
- Check `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers`

## Phase 2: Origin Reflection Tests
```
Origin: https://evil.com           → reflected? → exploitable
Origin: https://target.com.evil.com → reflected? → subdomain trick
Origin: https://eviltarget.com     → reflected? → prefix/suffix match
Origin: null                       → reflected? → sandboxed iframe exploit
Origin: https://TARGET.COM         → reflected? → case sensitivity
```

## Phase 3: Wildcard + Credentials
- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` → browsers block, but verify
- `Access-Control-Allow-Origin: <reflected>` with credentials → full exploit

## Phase 4: Preflight Bypass
- Simple requests (GET/POST with standard headers) skip preflight
- Test if non-standard methods/headers are allowed without preflight check
- Check `Access-Control-Max-Age` for cached preflight abuse

## Phase 5: Exploitation
- Steal authenticated data via cross-origin XHR
- CSRF via CORS: POST with JSON body from attacker page
- Internal network scanning via CORS from victim's browser
