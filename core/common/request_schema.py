"""Read real request-body field names from captured traffic.

Probes previously hardcoded app-specific field names — `passwordRepeat`,
`securityAnswer`, `email`/`password`, `captchaId` — so registration / login /
recovery / captcha requests were rejected on any target that names its fields
differently, and the probe never fired.

These helpers derive the ACTUAL field names from `ctx.captured_requests` (and the
LLM/crawler-parsed forms), falling back to a broad alias set. Returns a semantic
map ({username_field, password_field, confirm_field, answer_field, ...}) so
callers build a body that matches the target instead of assuming one.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional


def _env_extra(var: str) -> tuple:
    """Operator-supplied extra field names for non-standard conventions, e.g.
    NEO_USERNAME_FIELDS=userLogin,memberEmail."""
    return tuple(t.strip().lower() for t in re.split(r'[,\s]+', os.getenv(var, "") or "")
                 if t.strip())


USERNAME_ALIASES = ("email", "username", "user", "login", "identifier", "mail",
                    "user_name", "userid", "user_id", "account", "e-mail", "uid",
                    "loginid", "login_id", "handle") + _env_extra("NEO_USERNAME_FIELDS")
PASSWORD_ALIASES = ("password", "passwd", "pwd", "pass", "secret", "user_password",
                    "userpassword", "pword") + _env_extra("NEO_PASSWORD_FIELDS")
CONFIRM_ALIASES = ("passwordrepeat", "password_repeat", "password_confirmation",
                   "confirmpassword", "confirm_password", "password2",
                   "password_confirm", "repeatpassword", "repeat_password",
                   "passwordconfirm", "confirm") + _env_extra("NEO_CONFIRM_FIELDS")
ANSWER_ALIASES = ("securityanswer", "security_answer", "answer", "secret_answer",
                  "recovery_answer", "response", "secanswer", "answer_1"
                  ) + _env_extra("NEO_ANSWER_FIELDS")

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
CAPTCHA_ANSWER_ALIASES = ("captcha", "captchaanswer", "captcha_answer",
                          "captcha_token", "captchatoken", "challenge_answer",
                          "cf-turnstile-response", "g-recaptcha-response",
                          "h-captcha-response")
CAPTCHA_ID_ALIASES = ("captchaid", "captcha_id", "challenge_id", "challengeid", "id")


def _iter_captured(ctx) -> Iterable[Dict[str, Any]]:
    for r in (getattr(ctx, "captured_requests", None) or []):
        if isinstance(r, dict):
            yield r
        else:
            d = getattr(r, "__dict__", None)
            if isinstance(d, dict):
                yield d


def _body_dict(r: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("body", "data", "json", "post_data", "payload", "params"):
        b = r.get(key)
        if isinstance(b, dict):
            return b
        if isinstance(b, str) and b.strip().startswith("{"):
            try:
                d = json.loads(b)
                if isinstance(d, dict):
                    return d
            except Exception:
                pass
    return {}


def captured_body_for(ctx, url_substrings: Iterable[str],
                      methods=("POST", "PUT", "PATCH")) -> Dict[str, Any]:
    """First captured request body whose URL matches any substring and method."""
    subs = [s.lower() for s in url_substrings]
    for r in _iter_captured(ctx):
        u = str(r.get("url") or "").lower()
        m = str(r.get("method") or "POST").upper()
        if m in methods and (not subs or any(s in u for s in subs)):
            body = _body_dict(r)
            if body:
                return body
    return {}


def _pick(keys: Iterable[str], aliases: Iterable[str]) -> Optional[str]:
    """Return the captured key whose lowercase matches an alias (alias order =
    priority)."""
    lk = {str(k).lower(): k for k in keys}
    for a in aliases:
        if a in lk:
            return lk[a]
    return None


def _looks_password_value(v: str) -> bool:
    v = str(v or "")
    return (6 <= len(v) <= 128 and not _EMAIL_RE.match(v)
            and bool(re.search(r'[A-Za-z]', v)) and bool(re.search(r'[\d\W]', v)))


def _infer_from_values(body: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Infer credential fields from VALUE shapes when the field NAMES are
    non-standard (e.g. a target using `memberId`/`secretPhrase`). Reads a real
    captured body, so values are genuine: an email-shaped value ⇒ username; two
    keys sharing an identical password-ish value ⇒ password + confirm."""
    out: Dict[str, Optional[str]] = {}
    str_items = [(k, v) for k, v in body.items() if isinstance(v, str) and v]
    for k, v in str_items:
        if _EMAIL_RE.match(v):
            out["username_field"] = k
            break
    uname_key = out.get("username_field")
    pw_candidates = [(k, v) for k, v in str_items
                     if k != uname_key and _looks_password_value(v)]
    by_val: Dict[str, List[str]] = {}
    for k, v in pw_candidates:
        by_val.setdefault(v, []).append(k)
    pair = next((ks for ks in by_val.values() if len(ks) >= 2), None)
    if pair:
        out["password_field"], out["confirm_field"] = pair[0], pair[1]
    elif pw_candidates:
        out["password_field"] = pw_candidates[0][0]
    return out


def credential_fields(ctx, url_substrings: Iterable[str] = ()) -> Dict[str, str]:
    """Best-effort {username_field, password_field, confirm_field, answer_field}.
    Order: captured body key aliases → VALUE-shape inference (for non-standard
    names) → canonical defaults."""
    body = captured_body_for(ctx, url_substrings) if ctx is not None else {}
    keys = list(body.keys())
    uname = _pick(keys, USERNAME_ALIASES)
    pw = _pick(keys, PASSWORD_ALIASES)
    confirm = _pick(keys, CONFIRM_ALIASES)
    answer = _pick(keys, ANSWER_ALIASES)
    if body and (not uname or not pw):
        inferred = _infer_from_values(body)
        uname = uname or inferred.get("username_field")
        pw = pw or inferred.get("password_field")
        confirm = confirm or inferred.get("confirm_field")
    return {
        "username_field": uname or "email",
        "password_field": pw or "password",
        "confirm_field": confirm,        # may be None
        "answer_field": answer,          # may be None
        "captured_keys": keys,           # for templating
    }


def build_login_body(ctx, username: str, password: str,
                     url_substrings: Iterable[str] = ("login", "auth", "signin", "session")) -> Dict[str, Any]:
    """A login JSON body using the target's ACTUAL field names when known."""
    f = credential_fields(ctx, url_substrings)
    return {f["username_field"]: username, f["password_field"]: password}


def build_register_body(ctx, username: str, password: str,
                        url_substrings: Iterable[str] = ("register", "signup", "users", "account")) -> Dict[str, Any]:
    """A registration JSON body mirroring the captured register form when known:
    username + password (+ confirm field if the form uses one)."""
    f = credential_fields(ctx, url_substrings)
    body: Dict[str, Any] = {f["username_field"]: username, f["password_field"]: password}
    if f["confirm_field"]:
        body[f["confirm_field"]] = password
    return body


def login_body_variants(ctx, username: str, password: str,
                        url_substrings: Iterable[str] = ("login", "auth", "signin", "session")) -> List[Dict[str, Any]]:
    """Ordered candidate login bodies: the captured-schema body first, then a few
    generic shapes as fallback (so a target that wasn't captured still works)."""
    out = [build_login_body(ctx, username, password, url_substrings)]
    for shape in ({"email": username, "password": password},
                  {"username": username, "password": password},
                  {"login": username, "password": password},
                  {"identifier": username, "password": password}):
        if shape not in out:
            out.append(shape)
    return out
