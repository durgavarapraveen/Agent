"""Out-of-band (OOB) collaborator — confirms BLIND vulnerabilities.

Blind SSRF / RCE / XXE / SQLi / DNS-rebinding produce no in-response signal;
the only proof is the target reaching out to a server we control. This module:

  1. mints unique per-test tokens whose hostname/URL is embedded in payloads,
  2. lets an oracle ask "did token <t> get any DNS/HTTP interaction?",
  3. talks to a self-hosted interactsh-compatible server (OOB_COLLABORATOR_URL)
     when configured, else degrades to a NullCollaborator (never fabricates hits).

Interactsh protocol is intentionally abstracted behind ``Collaborator`` so the
backend can be interactsh, a custom AWS canary (API-GW + Route53 logs), or a
test double — the engine/oracle code is identical.

Env:
  OOB_COLLABORATOR_URL   base URL of the interactsh-compatible server
  OOB_COLLABORATOR_TOKEN optional auth token/header for that server
  OOB_DOMAIN             the interaction domain (e.g. oob.example.com)
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class OOBToken:
    token: str                 # unique correlation id (subdomain label)
    domain: str                # full interaction host: <token>.<oob_domain>
    created_at: float = field(default_factory=time.time)

    @property
    def http_url(self) -> str:
        return f"http://{self.domain}/{self.token}"

    @property
    def https_url(self) -> str:
        return f"https://{self.domain}/{self.token}"


@dataclass
class OOBInteraction:
    token: str
    protocol: str              # dns / http / smtp / ldap
    remote_addr: str = ""
    raw: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_evidence(self) -> Dict:
        return {"type": self.protocol, "remote_addr": self.remote_addr,
                "evidence_id": f"oob_{self.token}", "timestamp": self.timestamp}


class Collaborator:
    """Base interface. Real backends subclass; default is interactsh HTTP polling."""

    def is_active(self) -> bool:
        return False

    def new_token(self, tag: str = "") -> OOBToken:
        label = (tag[:8] + "-" if tag else "") + uuid.uuid4().hex[:16]
        label = "".join(c for c in label if c.isalnum() or c == "-").lower()[:40]
        return OOBToken(token=label, domain=f"{label}.{self._domain()}")

    def poll(self, token: str) -> List[OOBInteraction]:
        return []

    def had_interaction(self, token: str, wait_s: float = 0.0) -> List[OOBInteraction]:
        """Return interactions for a token, optionally waiting up to wait_s for
        delayed callbacks (blind bugs often fire seconds later)."""
        deadline = time.time() + max(0.0, wait_s)
        hits = self.poll(token)
        while not hits and time.time() < deadline:
            time.sleep(min(1.0, max(0.1, deadline - time.time())))
            hits = self.poll(token)
        return hits

    def token_marker(self, tok: "OOBToken") -> str:
        """The exact host (or host/path) to embed in a payload where a callback
        host is expected. Subdomain backends (interactsh) use the unique host;
        path-token backends (local listener) return host/<token>."""
        return tok.domain

    def _domain(self) -> str:
        return os.getenv("OOB_DOMAIN", "oob.invalid")


class NullCollaborator(Collaborator):
    """No server configured — mints tokens (so payloads still carry a unique
    marker) but reports zero interactions. NEVER fabricates a hit."""

    def is_active(self) -> bool:
        return False

    def poll(self, token: str) -> List[OOBInteraction]:
        return []


def _rand_label(n: int) -> str:
    import secrets
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


class InteractshCollaborator(Collaborator):
    """Full interactsh client: registers an RSA public key, mints subdomains under
    a shared 20-char correlation id, and polls the server for AES-encrypted
    interactions (RSA-OAEP-SHA256 key unwrap + AES-CFB payload decrypt). Works
    against a standard self-hosted `interactsh-server`. Best-effort — any error
    degrades to 'no interactions' (fail-closed on detection, never false-positive)."""

    def __init__(self, base_url: str, domain: str, auth: str = ""):
        self.base_url = base_url.rstrip("/")
        self.domain = domain
        self.auth = auth
        self._cache: Dict[str, List[OOBInteraction]] = {}
        self._lock = threading.RLock()
        self._registered = False
        self._corr_id = _rand_label(20)          # shared correlation prefix
        self._secret = str(uuid.uuid4())
        self._priv = None                        # RSA private key (lazy)

    def is_active(self) -> bool:
        return bool(self.base_url and self.domain)

    def _domain(self) -> str:
        return self.domain

    # ── interactsh registration ──────────────────────────────────────────────
    def _ensure_registered(self) -> bool:
        if self._registered:
            return True
        try:
            import base64
            import httpx
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub_pem = self._priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            payload = {
                "public-key": base64.b64encode(pub_pem).decode(),
                "secret-key": self._secret,
                "correlation-id": self._corr_id,
            }
            headers = {"Content-Type": "application/json"}
            if self.auth:
                headers["Authorization"] = self.auth
            with httpx.Client(timeout=10, verify=True) as c:
                r = c.post(f"{self.base_url}/register", json=payload, headers=headers)
            if r.status_code in (200, 201):
                self._registered = True
                logger.info("[OOB] registered with interactsh server (corr=%s)", self._corr_id)
            else:
                logger.warning("[OOB] register failed HTTP %s", r.status_code)
        except Exception as e:
            logger.warning("[OOB] register error: %s", e)
        return self._registered

    def new_token(self, tag: str = "") -> OOBToken:
        # Every subdomain must start with the registered correlation id so the
        # server routes its interactions into our poll bucket; a 13-char random
        # suffix makes each token unique (interactsh id format).
        self._ensure_registered()
        label = (self._corr_id + _rand_label(13)).lower()
        return OOBToken(token=label, domain=f"{label}.{self.domain}")

    # ── polling + decryption ─────────────────────────────────────────────────
    def poll(self, token: str) -> List[OOBInteraction]:
        if not self._ensure_registered():
            return self._cached(token)
        try:
            import httpx
            headers = {"Authorization": self.auth} if self.auth else {}
            with httpx.Client(timeout=8, verify=True) as c:
                r = c.get(f"{self.base_url}/poll",
                          params={"id": self._corr_id, "secret": self._secret},
                          headers=headers)
            if r.status_code != 200:
                return self._cached(token)
            body = r.json()
        except Exception as e:
            logger.debug("[OOB] poll failed: %s", e)
            return self._cached(token)

        aes_key = self._unwrap_aes_key(body.get("aes_key") or body.get("aes-key") or "")
        for item in (body.get("data") or []):
            dec = self._decrypt_item(item, aes_key)
            inter = self._parse(dec) if dec else None
            if inter:
                with self._lock:
                    self._cache.setdefault(inter.token, []).append(inter)
        return self._cached(token)

    def _unwrap_aes_key(self, aes_key_b64: str):
        if not aes_key_b64 or self._priv is None:
            return None
        try:
            import base64
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            return self._priv.decrypt(
                base64.b64decode(aes_key_b64),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None))
        except Exception as e:
            logger.debug("[OOB] aes-key unwrap failed: %s", e)
            return None

    def _decrypt_item(self, item_b64: str, aes_key) -> Optional[dict]:
        if not aes_key:
            return None
        try:
            import base64
            import json as _json
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            raw = base64.b64decode(item_b64)
            iv, ct = raw[:16], raw[16:]           # interactsh: AES-CFB, IV prefixed
            dec = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
            plain = dec.update(ct) + dec.finalize()
            return _json.loads(plain.decode("utf-8", "replace"))
        except Exception as e:
            logger.debug("[OOB] item decrypt failed: %s", e)
            return None

    def _parse(self, item: dict) -> Optional[OOBInteraction]:
        try:
            full = str(item.get("full-id") or item.get("unique-id") or item.get("host") or "")
            label = full.split(".")[0].lower()
            proto = str(item.get("protocol") or item.get("proto") or "dns").lower()
            return OOBInteraction(token=label, protocol=proto,
                                  remote_addr=str(item.get("remote-address") or item.get("remote_addr") or ""),
                                  raw=str(item)[:500])
        except Exception:
            return None

    def _cached(self, token: str) -> List[OOBInteraction]:
        with self._lock:
            return list(self._cache.get(token, []))


class LocalHTTPCollaborator(Collaborator):
    """Zero-infra OOB backend: runs a local HTTP listener and captures callbacks,
    correlating by a TOKEN in the request PATH (`/<token>`). Expose it publicly with
    a free tunnel (e.g. `cloudflared tunnel --url http://localhost:<port>`), set
    OOB_DOMAIN to the public tunnel host. HTTP/HTTPS interactions only (no DNS).
    Fail-closed: no listener => no interactions, never a false positive."""

    def __init__(self, port: int, domain: str):
        self.port = int(port)
        self.domain = domain.strip().rstrip("/")
        self._store: Dict[str, List[OOBInteraction]] = {}
        self._lock = threading.RLock()
        self._started = False
        self._server = None
        self._start()

    def _start(self) -> None:
        try:
            from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
            store, lock = self._store, self._lock

            class _H(BaseHTTPRequestHandler):
                def _record(self, method):
                    try:
                        tok = self.path.strip("/").split("/")[0].split("?")[0].lower()
                        if tok:
                            inter = OOBInteraction(
                                token=tok, protocol="http",
                                remote_addr=self.client_address[0] if self.client_address else "",
                                raw=f"{method} {self.path}"[:500])
                            with lock:
                                store.setdefault(tok, []).append(inter)
                    except Exception:
                        pass
                    try:
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"ok")
                    except Exception:
                        pass

                def do_GET(self):
                    self._record("GET")

                def do_POST(self):
                    self._record("POST")

                def do_HEAD(self):
                    self._record("HEAD")

                def log_message(self, *a):
                    return  # silence stdlib request logging

            self._server = ThreadingHTTPServer(("127.0.0.1", self.port), _H)
            t = threading.Thread(target=self._server.serve_forever, daemon=True)
            t.start()
            self._started = True
            logger.info("[OOB] local HTTP collaborator listening on 127.0.0.1:%d "
                        "(public host=%s)", self.port, self.domain)
        except Exception as e:
            self._started = False
            logger.warning("[OOB] local collaborator failed to start on :%d — %s", self.port, e)

    def is_active(self) -> bool:
        return bool(self._started and self.domain)

    def _domain(self) -> str:
        return self.domain

    def token_marker(self, tok: "OOBToken") -> str:
        # Token lives in the PATH, not a subdomain: <public-host>/<token>
        return f"{self.domain}/{tok.token}"

    def new_token(self, tag: str = "") -> OOBToken:
        label = ((tag[:6] + _rand_label(10)) if tag else _rand_label(16)).lower()
        label = "".join(c for c in label if c.isalnum())[:32] or _rand_label(16)
        return OOBToken(token=label, domain=self.domain)

    def poll(self, token: str) -> List[OOBInteraction]:
        with self._lock:
            return list(self._store.get(token.lower(), []))


# Literal placeholder a synthesized text payload uses for the callback host; the
# probe substitutes a freshly-minted unique token per send so a hit correlates to
# exactly that payload/endpoint.
OOB_PLACEHOLDER = "OOBHOST"

_instance: Optional[Collaborator] = None
_lock = threading.RLock()


def prepare_oob(payload: str, tag: str = ""):
    """If the collaborator is active and `payload` contains OOB_PLACEHOLDER, mint a
    unique token, substitute it in, and return (substituted_payload, token). Else
    return (payload, None). Reusable by any probe with a text OOB payload."""
    collab = get_collaborator()
    if not collab.is_active() or OOB_PLACEHOLDER not in (payload or ""):
        return payload, None
    tok = collab.new_token(tag)
    return payload.replace(OOB_PLACEHOLDER, collab.token_marker(tok)), tok


def confirm_oob(token: str, wait_s: float = 6.0) -> List[OOBInteraction]:
    """Return any out-of-band interactions for `token` (waiting up to wait_s for a
    delayed callback). A non-empty result is proof of a BLIND vulnerability."""
    try:
        return get_collaborator().had_interaction(token, wait_s=wait_s)
    except Exception:
        return []


def get_collaborator() -> Collaborator:
    global _instance
    with _lock:
        if _instance is not None:
            return _instance
        url = os.getenv("OOB_COLLABORATOR_URL", "").strip()
        domain = os.getenv("OOB_DOMAIN", "").strip()
        if url and domain:
            host = ""
            port = 8899
            try:
                from urllib.parse import urlparse
                pu = urlparse(url if "://" in url else f"http://{url}")
                host = (pu.hostname or "").lower()
                port = pu.port or (443 if pu.scheme == "https" else 80)
            except Exception:
                pass
            if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
                # Zero-infra mode: local listener + a public tunnel (cloudflared).
                _instance = LocalHTTPCollaborator(port=port, domain=domain)
                logger.info("OOB collaborator active (local+tunnel): :%d -> %s", port, domain)
            else:
                _instance = InteractshCollaborator(
                    url, domain, auth=os.getenv("OOB_COLLABORATOR_TOKEN", ""))
                logger.info("OOB collaborator active: %s (domain=%s)", url, domain)
        else:
            _instance = NullCollaborator()
            logger.info("OOB collaborator inactive (set OOB_COLLABORATOR_URL + OOB_DOMAIN to enable)")
        return _instance
