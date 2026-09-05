---
name: authorization-testing
category: vulnerabilities
description: Authorization and access control verification across roles
attack_types: [authorization, access_control, privilege_escalation, rbac]
severity_range: [critical, high, medium]
---

# Authorization Testing Methodology

## Phase 1: Role Mapping

1. Identify all user roles (anonymous, user, moderator, admin, superadmin)
2. Map which endpoints each role should access
3. Identify role assignment mechanisms

## Phase 2: Vertical Privilege Escalation

For each admin endpoint:
1. Request as anonymous → expect 401
2. Request as regular user → expect 403
3. If either returns 200, it's a finding

### Common Admin Endpoints
- `/admin`, `/dashboard`, `/api/admin/*`
- `/api/users` (list all users)
- `/api/settings`, `/api/config`
- GraphQL introspection with admin mutations

## Phase 3: Horizontal Access Control

1. User A creates resource → note ID
2. User B tries to read/modify/delete that resource
3. Check both REST and GraphQL interfaces

## Phase 4: Function-Level Access

Test if lower-privilege users can call restricted functions:
- User creation/deletion
- Role modification
- Configuration changes
- Data export/import
- Audit log access

## False Positive Prevention

- Verify the endpoint is supposed to be restricted
- Check if API returns different data per role (not same public data)
- Ensure auth token is valid and not expired during test

## Success Indicators

- **Confirmed**: Lower-privilege user accesses higher-privilege function
- **Evidence**: Request with low-privilege token returning restricted data/action
