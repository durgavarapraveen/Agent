---
name: jwt-attacks
category: authentication
description: JWT token attack methodology
attack_types:
  - jwt
  - authentication
  - authorization
severity_range: [high, critical]
---

# JWT Attack Methodology

## Phase 1: Token Analysis
- Decode header, payload, signature (base64url)
- Identify algorithm: HS256, RS256, ES256, none
- Check expiration (exp), issued-at (iat), not-before (nbf)
- Identify issuer (iss), audience (aud), subject (sub)

## Phase 2: Algorithm Confusion
### None Algorithm
```json
{"alg": "none", "typ": "JWT"}
```
- Set alg to "none", "None", "NONE", "nOnE"
- Remove signature, keep trailing dot

### RS256 → HS256 Confusion
- If server uses RS256, try HS256 with the public key as HMAC secret
- Server verifies HMAC(public_key, payload) instead of RSA

## Phase 3: Key Attacks
- Weak HMAC secrets: brute-force with common wordlists (jwt-cracker, hashcat -m 16500)
- JWK header injection: embed attacker's public key in the `jwk` header
- JKU/X5U header: point to attacker-controlled key URL
- Kid injection: `"kid": "../../dev/null"` or SQL injection in kid

## Phase 4: Claim Manipulation
- Change `sub` (subject) to another user ID
- Elevate `role` from "user" to "admin"
- Extend `exp` to far future
- Change `iss` to accepted issuer
- Add missing claims that grant access

## Phase 5: Implementation Flaws
- Token not invalidated on logout → replay
- No token refresh rotation → stolen refresh token reuse
- Signature not verified → modify payload freely
- Token in URL parameter → leaks via Referer header
- Long-lived tokens without rotation
