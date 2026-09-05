---
name: business-logic-abuse
category: vulnerabilities
description: Business logic flaw detection in application workflows
attack_types: [business_logic, race_condition, parameter_tampering, workflow_bypass]
severity_range: [high, medium]
---

# Business Logic Testing

## Phase 1: Workflow Mapping

1. Identify multi-step processes (checkout, registration, password reset)
2. Map the expected order of API calls
3. Note which steps validate previous steps

## Phase 2: Step Skipping

1. Try to skip steps in a workflow (e.g., go from cart to confirmation, skip payment)
2. Try to repeat steps (e.g., apply discount code twice)
3. Try to go backwards (e.g., modify order after payment)

## Phase 3: Parameter Tampering

1. Price manipulation: Change price in client-side request
2. Quantity manipulation: Negative quantities, zero quantities
3. Discount stacking: Apply multiple discount codes
4. Currency confusion: Change currency parameter

## Phase 4: Race Conditions

1. Send same request concurrently (e.g., withdraw funds twice)
2. Use threading to hit endpoint simultaneously
3. Check for TOCTOU (time-of-check-time-of-use) issues

## False Positive Prevention

- Business logic findings MUST demonstrate actual impact
- Price changes must result in actual different charges (not just displayed)
- Race conditions must produce inconsistent state

## Success Indicators

- **Confirmed**: Workflow produces unintended state (free item, double credit, skipped validation)
- **Evidence**: Sequence of requests showing the logic bypass
