---
name: file-upload-attacks
category: file_access
description: File upload vulnerability testing
attack_types:
  - file_upload
  - file_access
severity_range: [medium, critical]
---

# File Upload Attack Methodology

## Phase 1: Understand Upload Mechanism
- Accepted file types (whitelist vs blacklist)
- File size limits
- Storage location (same origin vs CDN vs cloud)
- Filename handling (preserved vs randomized)
- Content-Type validation (client vs server)

## Phase 2: Extension Bypass
```
shell.php → shell.php5, shell.phtml, shell.phar, shell.phps
shell.jsp → shell.jspx, shell.jsw, shell.jsv
shell.asp → shell.aspx, shell.cer, shell.asa
shell.php → shell.php.jpg (double extension)
shell.php → shell.php%00.jpg (null byte - legacy)
shell.php → shell.PhP (case variation)
shell.php → shell.php. (trailing dot - Windows)
shell.php → shell.php::$DATA (NTFS ADS - Windows)
```

## Phase 3: Content-Type Bypass
- Change Content-Type header: `application/x-php` → `image/jpeg`
- Magic bytes: prepend `GIF89a` to PHP file
- Polyglot: valid JPEG that is also valid PHP
- SVG with embedded JavaScript

## Phase 4: Path Traversal in Filename
```
../../../etc/cron.d/shell
..%2f..%2f..%2fvar/www/html/shell.php
```

## Phase 5: Exploitation
- Web shell upload → RCE
- HTML/SVG upload → stored XSS
- .htaccess upload → reconfigure handler to execute uploads
- Overwrite existing files: config files, templates
- ZIP slip: `../../shell.php` entry in archive
- ImageMagick exploits via crafted images
