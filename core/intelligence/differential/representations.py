"""
Request representation model and equivalence-variant generators
(spec Point J — "Request Parsing Variance", Point A — differential testing).

An ``HttpRequest`` is a transport-agnostic description of one request. The
engines build a *set* of requests that a well-behaved server should treat
identically, send them through an injected ``probe`` callable, and compare the
responses. Any divergence between supposedly-equivalent representations is an
anomaly worth a hypothesis.

The injected probe matches the executor ``_probe`` signature exactly so the
same scope-checked network path is reused:

    probe(url, method="GET", headers=None, data=None) -> (status, body, headers)
"""
from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from core.intelligence.differential.comparison import ResponseSnapshot

# The executor `_probe` contract.
ProbeFn = Callable[..., Tuple[int, str, Dict[str, str]]]


@dataclass
class HttpRequest:
    """One concrete request in a differential set."""
    label: str
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None

    def with_label(self, label: str) -> "HttpRequest":
        return HttpRequest(label=label, url=self.url, method=self.method,
                           headers=dict(self.headers), body=self.body)


def send(probe: ProbeFn, request: HttpRequest) -> ResponseSnapshot:
    """Send one request through the injected probe and time it."""
    start = time.monotonic()
    try:
        status, body, headers = probe(
            request.url, method=request.method,
            headers=request.headers or None, data=request.body,
        )
    except TypeError:
        # Probe that only accepts (url) positionally — degrade gracefully.
        status, body, headers = probe(request.url)
    elapsed = (time.monotonic() - start) * 1000.0
    return ResponseSnapshot(
        label=request.label, status=int(status), body=body or "",
        headers=dict(headers or {}), elapsed_ms=elapsed,
    )


_DEFAULT_UA = {"User-Agent": "AntiGravity-Differential/1.0"}


def representation_variants(
    base_url: str,
    params: Dict[str, str],
    *,
    auth_headers: Optional[Dict[str, str]] = None,
    include_multipart: bool = False,
) -> List[HttpRequest]:
    """Build semantically-equivalent representations of the same parameters.

    A server that authorises/parses one representation differently from another
    (e.g. accepts an id in the JSON body that it would reject in the query
    string) exposes a parsing-inconsistency / access-control gap.
    """
    headers = dict(_DEFAULT_UA)
    if auth_headers:
        headers.update(auth_headers)
    variants: List[HttpRequest] = []

    query = urllib.parse.urlencode(params)
    sep = "&" if urllib.parse.urlparse(base_url).query else "?"
    variants.append(HttpRequest(
        label="GET query-string", url=f"{base_url}{sep}{query}" if params else base_url,
        method="GET", headers=dict(headers),
    ))

    form_headers = dict(headers)
    form_headers["Content-Type"] = "application/x-www-form-urlencoded"
    variants.append(HttpRequest(
        label="POST form-urlencoded", url=base_url, method="POST",
        headers=form_headers, body=query.encode(),
    ))

    json_headers = dict(headers)
    json_headers["Content-Type"] = "application/json"
    variants.append(HttpRequest(
        label="POST json", url=base_url, method="POST",
        headers=json_headers, body=json.dumps(params).encode(),
    ))

    if include_multipart:
        boundary = "----AntiGravityBoundary7MA4YWxkTrZu0gW"
        parts = []
        for k, v in params.items():
            parts.append(f"--{boundary}\r\n"
                         f'Content-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n')
        parts.append(f"--{boundary}--\r\n")
        mp_headers = dict(headers)
        mp_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        variants.append(HttpRequest(
            label="POST multipart", url=base_url, method="POST",
            headers=mp_headers, body="".join(parts).encode(),
        ))

    return variants
