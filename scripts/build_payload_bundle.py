#!/usr/bin/env python3
"""Build the single-file payload bundle from PayloadsAllTheThings (+ optional
nuclei templates / custom YAML), so the catalog is fully populated offline.

Usage:
    python scripts/build_payload_bundle.py --patt /path/to/PayloadsAllTheThings
    python scripts/build_payload_bundle.py --clone            # git-clone PATT to a tmp dir
    python scripts/build_payload_bundle.py --patt DIR --out data/payloads/patt_bundle.jsonl

Writes JSONL (one normalized Payload per line) to --out (default
data/payloads/patt_bundle.jsonl). The running catalog auto-loads this bundle
on first use (see core/payloads/catalog.py _BUNDLE_PATH).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile

from core.database.pg_store import _init_schema
from core.payloads.catalog import PayloadCatalog


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--patt", help="Path to a PayloadsAllTheThings checkout")
    ap.add_argument("--clone", action="store_true",
                    help="git clone PayloadsAllTheThings into a temp dir first")
    ap.add_argument("--nuclei", help="Path to nuclei-templates checkout (optional)")
    ap.add_argument("--custom", help="Dir of custom *.yaml payload files (optional)")
    ap.add_argument("--out", default="data/payloads/patt_bundle.jsonl")
    args = ap.parse_args()

    patt = args.patt
    if args.clone and not patt:
        patt = tempfile.mkdtemp(prefix="patt_")
        subprocess.run(["git", "clone", "--depth", "1",
                        "https://github.com/swisskyrepo/PayloadsAllTheThings.git", patt],
                       check=True)
    if not patt and not args.nuclei and not args.custom:
        ap.error("provide --patt, --clone, --nuclei, or --custom")

    _init_schema()
    cat = PayloadCatalog(auto_seed=False)
    total = 0
    if patt:
        total += cat.ingest_payloads_all_the_things(patt)
    if args.nuclei:
        total += cat.ingest_nuclei_templates(args.nuclei)
    if args.custom:
        import os
        for fn in os.listdir(args.custom):
            if fn.endswith((".yaml", ".yml")):
                total += cat.ingest_custom_yaml(os.path.join(args.custom, fn))

    written = cat.export_bundle(args.out)
    print(f"Ingested ~{total} payloads; wrote {written} to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
