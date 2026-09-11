from __future__ import annotations
import logging
import re

logger = logging.getLogger(__name__)


class OsintBridgeMixin:
    @staticmethod
    def _mask_secret(val: str) -> str:
        s = str(val or "")
        if len(s) <= 4:
            return "•" * len(s)
        return s[:2] + "•" * max(4, len(s) - 4) + s[-2:]

    def _osint_spray_material(self):
        g = self.ctx.get
        leaked = g("leaked_credentials", []) or []
        employees = g("discovered_employees", []) or []
        harvested = getattr(self.ctx, "harvested_creds", []) or []

        creds, usernames, passwords = [], [], []
        seen_u = set()

        def _add_user(u):
            u = str(u or "").strip()
            if u and u.lower() not in seen_u:
                seen_u.add(u.lower())
                usernames.append(u)

        def _derive_from_email(email):
            local = str(email).split("@")[0].strip()
            if local:
                _add_user(local)
                _add_user(email)  # some apps log in with full email
            return local

        def _ascii(s):
            import unicodedata
            return unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode()

        def _derive_from_name(name):
            parts = [p for p in re.split(r"[\s.]+", _ascii(name).strip().lower()) if p.isalpha()]
            if len(parts) >= 2:
                f, l = parts[0], parts[-1]
                for u in (f"{f}.{l}", f"{f[0]}{l}", f"{f}{l}", f"{f}_{l}", f):
                    _add_user(u)
            elif parts:
                _add_user(parts[0])

        # 1) leaked credential pairs
        for c in (list(leaked) + list(harvested)):
            if not isinstance(c, dict):
                continue
            u = c.get("username") or c.get("user") or c.get("email")
            p = c.get("password") or c.get("secret") or c.get("value")
            if u and p:
                creds.append((str(u), str(p)))
            if u and "@" in str(u):
                _derive_from_email(u)
            elif u:
                _add_user(str(u))
            if p:
                passwords.append(str(p))

        # 2) employees -> usernames
        for e in employees:
            if isinstance(e, dict):
                if e.get("email"):
                    _derive_from_email(e["email"])
                if e.get("name"):
                    _derive_from_name(e["name"])
                if e.get("username"):
                    _add_user(e["username"])
            elif isinstance(e, str):
                (_derive_from_email(e) if "@" in e else _derive_from_name(e))

        # de-dup passwords, cap sizes
        passwords = list(dict.fromkeys(passwords))[:20]
        return creds[:100], usernames[:50], passwords

    def _osint_identities(self) -> dict:
        creds, users, _pw = self._osint_spray_material()
        g = self.ctx.get
        employees = g("discovered_employees", []) or []

        emails, admin_emails = [], []
        for e in employees:
            email = e.get("email") if isinstance(e, dict) else (e if isinstance(e, str) and "@" in e else None)
            title = (e.get("title", "") if isinstance(e, dict) else "").lower()
            if email:
                emails.append(email)
                if any(k in title for k in ("owner", "admin", "lead", "founder", "cto", "ceo", "director")):
                    admin_emails.append(email)
        # leaked-cred usernames that look like emails are admin candidates too
        for u, _p in creds:
            if "@" in u:
                emails.append(u)

        emails = list(dict.fromkeys(emails))
        idents = {
            "usernames": users,
            "emails": emails,
            "admin_emails": list(dict.fromkeys(admin_emails)) or emails[:2],
            "leaked_pairs": creds,
        }
        try:
            self.ctx.osint_identities = idents
            self.ctx._dynamic_keys.add("osint_identities")
        except Exception:
            pass
        return idents

    async def _augment_auth_with_osint(self):
        idents = self._osint_identities()
        pairs = idents.get("leaked_pairs") or []
        if not pairs:
            return
        # Find a login endpoint from what recon already discovered.
        login_url = ""
        candidates = []
        for r in getattr(self.ctx, "captured_requests", []) or []:
            u = getattr(r, "url", None) or (r.get("url") if isinstance(r, dict) else None)
            if u:
                candidates.append(str(u))
        for ep in getattr(self.ctx, "endpoint_catalog", []) or []:
            if isinstance(ep, dict) and ep.get("url"):
                candidates.append(ep["url"])
        for u in candidates:
            if any(k in u.lower() for k in ("login", "signin", "session", "/auth", "user/login")):
                login_url = u.split("?")[0]
                break

        existing = getattr(self.ctx, "auth_credentials", None) or []
        new_creds = list(existing)
        for i, (user, pw) in enumerate(pairs[:5]):
            new_creds.append({
                "role": f"osint_{i}_{user.split('@')[0][:12]}",
                "username": user, "password": pw,
                "login_url": login_url,   # may be "" -> auth layer will try form detection
            })
        self.ctx.auth_credentials = new_creds
        try:
            # Re-establish sessions (multi-role) — registers these leaked identities
            # into the replay/access-control engine via the identity bridge.
            await self._setup_auth_session()
            logger.info(f"[OSINT-Auth] Added {min(len(pairs),5)} leaked identities to auth/IDOR testing "
                        f"(login_url={login_url or 'auto-detect'})")
        except Exception as e:
            logger.warning(f"[OSINT-Auth] leaked-identity auth failed (non-fatal): {e}")

    def _build_osint_context(self) -> dict:
        g = self.ctx.get
        creds = g("leaked_credentials", []) or []
        masked_creds = []
        for c in creds:
            if isinstance(c, dict):
                masked_creds.append({
                    "username": c.get("username") or c.get("user") or c.get("email") or "",
                    "type": c.get("type") or c.get("credential_type") or "credential",
                    "source": c.get("source") or c.get("repo") or c.get("url") or "",
                    "secret": self._mask_secret(c.get("password") or c.get("secret") or c.get("value") or ""),
                })
            else:
                masked_creds.append({"source": str(c)})

        osint = {
            "employees": g("discovered_employees", []) or [],
            "leaked_credentials": masked_creds,
            "cloud_buckets": g("cloud_buckets", []) or [],
            "domain_intelligence": g("domain_intelligence", {}) or {},
            "threat_correlations": g("threat_correlations", []) or [],
            "findings": g("osint_findings", []) or [],
        }
        osint["summary"] = {
            "employees": len(osint["employees"]),
            "leaked_credentials": len(masked_creds),
            "cloud_buckets": len(osint["cloud_buckets"]),
            "threat_correlations": len(osint["threat_correlations"]),
        }
        # Include any other dynamically-collected intelligence not covered above.
        try:
            known = {"discovered_employees", "leaked_credentials", "cloud_buckets",
                     "domain_intelligence", "threat_correlations", "osint_findings",
                     "discovered_subdomains", "target_profile", "discovered_ips",
                     "discovered_domains", "subdomain_status", "endpoint_catalog"}
            extra = {k: v for k, v in self.ctx.dynamic_data().items()
                     if k not in known and not isinstance(v, (bytes,))}
            if extra:
                osint["other"] = extra
        except Exception:
            pass
        return osint

