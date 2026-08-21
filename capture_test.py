"""
Standalone tester for the HTTP request-capture module.

Usage:
    python capture_test.py <url> [max_pages] [max_depth]

Examples:
    python capture_test.py http://localhost:3000 12 2
    python capture_test.py https://example.com 3 1
"""

import json
import logging
import sys
import time

logging.basicConfig(level=logging.INFO,
                    format="[%(levelname)s] %(name)s: %(message)s")

from core.request_capture import RequestCapturer
from core.shared_context import SharedContext


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    url = sys.argv[1]
    max_pages = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    max_depth = int(sys.argv[3]) if len(sys.argv) > 3 else 2

    print("=" * 70)
    print(f"Capturing requests on: {url}")
    print(f"max_pages={max_pages}  max_depth={max_depth}")
    print("=" * 70)

    rc = RequestCapturer(max_pages=max_pages, max_depth=max_depth)
    t0 = time.time()
    result = rc.capture(url)
    elapsed = time.time() - t0

    print(f"\nElapsed: {elapsed:.1f}s")
    if result.error and not result.requests:
        print(f"ERROR: {result.error}")
        print("\nIf this says 'playwright not available', install it in the "
              "container first (see the README / instructions).")
        sys.exit(2)

    api = result.api_requests()
    preflight = [r for r in result.requests if r.is_preflight]

    print(f"Pages crawled     : {len(result.pages)}")
    print(f"Total requests    : {len(result.requests)}")
    print(f"API/XHR requests  : {len(api)}")
    print(f"CORS preflight    : {len(preflight)}")

    print("\n--- Pages ---")
    for p in result.pages:
        print(f"  {p}")

    print("\n--- API / XHR / non-GET requests (replayable) ---")
    for r in api[:40]:
        body = f"  body={r.post_data[:80]}" if r.post_data else ""
        print(f"  [{r.status}] {r.method:7} {r.url}{body}")

    if preflight:
        print("\n--- CORS pre-flight (OPTIONS) ---")
        for r in preflight[:20]:
            acrm = r.headers.get("access-control-request-method", "")
            print(f"  {r.method:7} {r.url}  (requests: {acrm})")

    # Verify storage into SharedContext (what exploit agents will consume)
    ctx = SharedContext(url, {})
    rc.store(result, ctx)
    print("\n--- Stored in SharedContext ---")
    print(f"  captured_requests: {len(ctx.captured_requests)}")
    print(f"  endpoints (API)  : {len(ctx.endpoints)}")
    print(f"  crawled_pages    : {len(ctx.crawled_pages)}")

    # Show what an exploit agent would actually see
    agent_view = ctx.get_context_for_agent("exploit test", ["captured_requests"])
    print("\n--- Exploit-agent context preview (first 400 chars) ---")
    print(agent_view[:400])

    # Save full dump for inspection
    with open("capture_result.json", "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    print("\nFull result written to: capture_result.json")


if __name__ == "__main__":
    main()
