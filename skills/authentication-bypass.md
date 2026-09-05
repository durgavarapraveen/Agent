---
name: authentication-bypass
category: vulnerabilities
description: Authentication mechanism testing and bypass techniques
attack_types: [authentication, auth_bypass, credential_stuffing, session_management]
severity_range: [critical, high]
---

# Authentication Bypass Testing

## Phase 1: Login Mechanism Analysis

1. Identify all login endpoints (POST /login, POST /api/auth, etc.)
2. Check for rate limiting on login attempts
3. Identify password reset flows
4. Check for MFA/2FA implementation
5. Look for alternative auth methods (OAuth, SSO, API keys)

## Phase 2: Credential Testing

### Default Credentials
Test common defaults: admin/admin, admin/password, root/root, test/test

### SQL Injection in Login
1. Username: `admin' OR '1'='1'-- -` Password: anything
2. Username: `admin'--` Password: anything
3. Username: `' OR 1=1-- -` Password: anything

### NoSQL Injection in Login
1. `{"username": {"$gt": ""}, "password": {"$gt": ""}}`
2. `{"username": {"$ne": ""}, "password": {"$ne": ""}}`

## Phase 3: Session Management

1. Check session token entropy (should be >128 bits)
2. Test session fixation: Can you set session ID before auth?
3. Test session after logout: Does server invalidate?
4. Check cookie flags: HttpOnly, Secure, SameSite
5. Test concurrent sessions: Can same user have multiple?

## Phase 4: JWT Testing

1. Check for algorithm confusion (change RS256 to HS256)
2. Test none algorithm: `{"alg": "none"}`
3. Check token expiry (long-lived tokens are risky)
4. Test signature removal
5. Check for key disclosure in /jwks.json or /.well-known/

## Phase 5: Password Reset

1. Test for predictable reset tokens
2. Check if reset link works multiple times
3. Test host header injection in reset emails
4. Check if old password is validated

## False Positive Prevention

- Authentication bypass must result in access to protected resources
- Session issues must be demonstrable with actual session tokens
- JWT issues must allow forging valid tokens
- Rate limiting bypass must be tested from single IP

## Success Indicators

- **Confirmed**: Access to authenticated endpoint without valid credentials
- **Evidence**: HTTP request/response showing authenticated access with forged/bypassed auth
