---
name: race-condition-testing
category: logic
description: Race condition and TOCTOU vulnerability testing
attack_types:
  - race_condition
  - business_logic
severity_range: [medium, critical]
---

# Race Condition Testing

## Phase 1: Identify Race-Prone Operations
- Financial: balance checks before debit, coupon/voucher redemption
- Inventory: stock check before purchase
- Rate limiting: check-then-increment counters
- Account: email verification, password reset token validation
- File operations: check-then-write, read-then-delete

## Phase 2: Single-Endpoint Race (Limit Overrun)
- Send N identical requests simultaneously (N=10-50)
- Use HTTP/2 single-packet attack or HTTP/1.1 last-byte sync
- Tools: Turbo Intruder, custom async scripts
- Example: Redeem coupon 20x by sending 20 simultaneous requests

## Phase 3: Multi-Endpoint Race (TOCTOU)
- Identify check-then-act sequences across different endpoints
- Example: Verify email → change email → complete action with old verification
- Example: Add item to cart → change price → checkout

## Phase 4: Exploitation Techniques
### HTTP/2 Single-Packet Attack
- Queue all requests, release simultaneously over single TCP connection
- Server processes all before any response returns

### Last-Byte Synchronization (HTTP/1.1)
- Send all requests minus last byte
- Send all final bytes simultaneously

## Phase 5: Detection Signals
- Successful double-spend or double-redeem
- Counter exceeded expected limit
- Inconsistent database state after concurrent operations
- Different response for identical simultaneous requests
