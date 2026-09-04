---
name: graphql-testing
category: api
description: GraphQL API security testing
attack_types:
  - graphql
  - api
  - injection
severity_range: [medium, critical]
---

# GraphQL Security Testing

## Phase 1: Introspection
```graphql
{ __schema { types { name fields { name type { name } } } } }
{ __schema { queryType { name } mutationType { name } } }
```
- If introspection disabled, try: field suggestion errors, __type queries
- Clairvoyance tool for schema reconstruction from suggestions

## Phase 2: Authorization Testing
- Query other users' data by changing ID arguments
- Access admin-only mutations as regular user
- Nested object access: `user { orders { paymentDetails } }`
- Batch queries to enumerate: `{ u1: user(id:1){email} u2: user(id:2){email} }`

## Phase 3: Injection
- SQL injection in arguments: `user(name: "' OR 1=1--")`
- NoSQL injection: `user(filter: {email: {$regex: ".*"}})`
- SSRF via URL arguments in mutations

## Phase 4: Denial of Service
- Deeply nested queries: `{ user { friends { friends { friends ... } } } }`
- Circular fragments: fragment A references B, B references A
- Batch queries: send 1000 queries in single request
- Large field selection: request all fields on large objects
- Alias-based attacks: `{ a1:expensiveQuery a2:expensiveQuery ... a100:expensiveQuery }`

## Phase 5: Information Disclosure
- Verbose error messages exposing stack traces
- Debug mode: `__debug` field, error extensions
- Field suggestions revealing private fields
- Type names revealing internal architecture
