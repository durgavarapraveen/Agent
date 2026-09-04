---
name: api-security-testing
category: api
description: REST API security testing methodology
attack_types:
  - api
  - injection
  - authentication
severity_range: [medium, critical]
---

# API Security Testing

## Phase 1: API Discovery
- Swagger/OpenAPI: `/swagger.json`, `/api-docs`, `/openapi.json`, `/v2/api-docs`
- GraphQL: `/graphql`, `/graphiql`, `/playground`
- Common paths: `/api/v1/`, `/api/v2/`, `/rest/`, `/services/`
- WADL: `/application.wadl`
- Hidden endpoints: increment version numbers, change HTTP methods

## Phase 2: Authentication & Authorization
- Test endpoints without auth token
- Use expired/revoked tokens
- Horizontal access: change user ID in JWT or request
- Vertical access: access admin endpoints with user token
- API key in URL vs header (key in URL leaks via logs/referer)

## Phase 3: Input Validation
- Mass assignment: send extra fields in POST/PUT (`isAdmin: true`, `role: admin`)
- Type juggling: send string where int expected, array where string expected
- Boundary testing: max-length strings, negative numbers, zero values
- Special characters in all parameters

## Phase 4: Rate Limiting & Resource
- No rate limiting: enumerate users, brute-force credentials
- Pagination abuse: `?limit=999999` or negative offset
- Field selection DoS: `?fields=*` or deeply nested includes
- Batch endpoint abuse: process thousands of items per request

## Phase 5: Data Exposure
- Verbose errors exposing stack traces, SQL queries
- Debug endpoints: `/debug`, `/trace`, `/actuator`, `/metrics`
- Excessive data in responses (return full user object instead of needed fields)
- Predictable resource IDs enabling enumeration
