"""
Operator CLI to resolve pending escalation approvals.

Usage:
    python -m core.escalation.resolve list
    python -m core.escalation.resolve approve <request_id> [--by NAME] [--reason TEXT]
    python -m core.escalation.resolve deny    <request_id> [--by NAME] [--reason TEXT]
"""

import argparse
import json
import sys

from core.escalation.escalation_gate import EscalationGate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="core.escalation.resolve")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list pending approval requests")

    for verb in ("approve", "deny"):
        p = sub.add_parser(verb, help=f"{verb} a pending request")
        p.add_argument("request_id")
        p.add_argument("--by", default="cli")
        p.add_argument("--reason", default="")

    args = parser.parse_args(argv)
    gate = EscalationGate()

    if args.cmd == "list":
        pending = gate.list_pending()
        if not pending:
            print("No pending approvals.")
            return 0
        for r in pending:
            print(f"[{r['request_id']}] risk={r.get('risk')} action={r.get('action')} "
                  f"target={r.get('target')}")
            if r.get("details"):
                print(f"    details: {json.dumps(r['details'], default=str)[:300]}")
        return 0

    approved = args.cmd == "approve"
    ok = gate.decide(args.request_id, approved, decided_by=args.by, reason=args.reason)
    if ok:
        print(f"Request {args.request_id} -> {'APPROVED' if approved else 'DENIED'}")
        return 0
    print(f"Request {args.request_id} not found or already resolved.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
