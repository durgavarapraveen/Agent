---
name: csrf-testing
category: session
description: Cross-Site Request Forgery testing methodology
attack_types:
  - csrf
  - session
severity_range: [medium, high]
---

# CSRF Testing

## Phase 1: Identify State-Changing Actions
- Password change, email update, profile modification
- Fund transfer, purchase, subscription
- Admin actions: user creation, permission changes
- API key generation/revocation

## Phase 2: Token Analysis
- Missing CSRF token entirely → exploitable
- Token in cookie only (no double-submit) → exploitable
- Predictable token (timestamp, sequential) → exploitable
- Token not validated on server → exploitable
- Token tied to session but reusable across requests → partial protection

## Phase 3: Bypass Techniques
- Remove token parameter entirely
- Change request method: POST → GET (some frameworks skip CSRF on GET)
- Empty token value: `csrf_token=`
- Use another user's valid token (not session-bound)
- Change Content-Type: `application/json` → `application/x-www-form-urlencoded`
- Subdomain token reuse if cookie scope is too broad

## Phase 4: SameSite Cookie Bypass
- `SameSite=None` → fully exploitable cross-site
- `SameSite=Lax` → GET requests still sent cross-site, test state-change via GET
- `SameSite=Strict` → window.open or top-level navigation bypass
- Missing SameSite attribute → browser default (Lax in modern browsers)

## Phase 5: Proof of Concept
- Auto-submitting form via JavaScript
- Image tag for GET-based CSRF
- XHR/fetch for JSON API CSRF (if CORS allows)
