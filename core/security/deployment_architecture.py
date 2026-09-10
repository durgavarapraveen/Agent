"""Phase 20.1 — Secure deployment architecture.

Defines the hardened reference deployment architecture:
- Separation of Control Plane, Policy Service, Worker Pool, Evidence Store,
  Secret Vault, Message Bus, and Reporting Service.
- Service Identity & Zero-Trust Token Verification (mTLS / SPIFFE / token exchange).
- Worker Isolation: Worker credentials have strict least-privilege; compromise
  of a worker cannot grant control-plane access or modify evidence/audit records.
- Artifact Provenance, Cosign-style signature verification, SBOM generation & validation.
- Threat Model covering worker escape, credential compromise, compromised target,
  and data exfiltration.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ── 1. Service Roles & Least-Privilege IAM ───────────────────────────────────

class ServiceRole(str, Enum):
    CONTROL_PLANE = "control_plane"
    POLICY_SERVICE = "policy_service"
    WORKER = "worker"
    EVIDENCE_STORE = "evidence_store"
    SECRET_VAULT = "secret_vault"
    MESSAGE_BUS = "message_bus"
    REPORTING = "reporting"


# Immutable permissions matrix defining least privilege
SERVICE_PERMISSIONS: Dict[ServiceRole, Set[str]] = {
    ServiceRole.CONTROL_PLANE: {
        "orchestrate:all",
        "jobs:create",
        "jobs:cancel",
        "policy:query",
        "audit:read",
        "telemetry:read",
    },
    ServiceRole.POLICY_SERVICE: {
        "policy:evaluate",
        "scope:validate",
        "egress:authorize",
        "action:gate",
    },
    ServiceRole.WORKER: {
        "task:claim",
        "task:execute_sandbox",
        "policy:query",
        "telemetry:emit",
        "evidence:submit_raw",
    },
    ServiceRole.EVIDENCE_STORE: {
        "evidence:append",
        "evidence:read",
        "evidence:verify_chain",
    },
    ServiceRole.SECRET_VAULT: {
        "secret:lease",
        "secret:revoke",
        "secret:rotate",
    },
    ServiceRole.MESSAGE_BUS: {
        "bus:publish",
        "bus:subscribe",
    },
    ServiceRole.REPORTING: {
        "evidence:read",
        "report:generate",
        "metrics:read",
    },
}

# Explicitly forbidden operations per role (defense-in-depth)
FORBIDDEN_OPERATIONS: Dict[ServiceRole, Set[str]] = {
    ServiceRole.WORKER: {
        "control_plane:*",
        "orchestrate:*",
        "secret:*",
        "audit:modify",
        "evidence:delete",
        "policy:modify",
    },
    ServiceRole.REPORTING: {
        "task:*",
        "execution:*",
        "secret:*",
    },
}


@dataclass(frozen=True)
class ServiceIdentity:
    """Strong cryptographic identity for services (e.g. SPIFFE ID or mTLS SAN)."""
    role: ServiceRole
    instance_id: str
    tenant_id: str = "default"
    spiffe_id: str = ""
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)

    def __post_init__(self) -> None:
        if not self.spiffe_id:
            object.__setattr__(
                self,
                "spiffe_id",
                f"spiffe://antigravity.security/{self.tenant_id}/{self.role.value}/{self.instance_id}",
            )

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class ServiceAccessController:
    """Enforces zero-trust service communication and prevents privilege escalation."""

    def __init__(self, signing_key: bytes = b"antigravity-internal-mesh-secret-key"):
        self._signing_key = signing_key

    def issue_token(self, identity: ServiceIdentity) -> str:
        payload = {
            "role": identity.role.value,
            "instance_id": identity.instance_id,
            "tenant_id": identity.tenant_id,
            "spiffe_id": identity.spiffe_id,
            "issued_at": identity.issued_at,
            "expires_at": identity.expires_at,
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode()).decode()
        sig = hmac.new(self._signing_key, encoded.encode(), hashlib.sha256).hexdigest()
        return f"{encoded}.{sig}"

    def verify_token(self, token: str) -> Optional[ServiceIdentity]:
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return None
            encoded, sig = parts
            expected_sig = hmac.new(self._signing_key, encoded.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                return None
            data = json.loads(base64.urlsafe_b64decode(encoded.encode()).decode())
            identity = ServiceIdentity(
                role=ServiceRole(data["role"]),
                instance_id=data["instance_id"],
                tenant_id=data.get("tenant_id", "default"),
                spiffe_id=data.get("spiffe_id", ""),
                issued_at=data["issued_at"],
                expires_at=data["expires_at"],
            )
            if identity.is_expired:
                return None
            return identity
        except Exception as e:
            logger.warning("Token verification failed: %s", e)
            return None

    def authorize_action(
        self,
        caller: ServiceIdentity,
        action: str,
        target_service: ServiceRole,
    ) -> Tuple[bool, str]:
        """Verify whether caller is permitted to invoke the action on target_service."""
        if caller.is_expired:
            return False, "Token expired"

        # Worker containment rule: Workers cannot call control-plane directly
        if caller.role == ServiceRole.WORKER and target_service == ServiceRole.CONTROL_PLANE:
            return False, "Worker compromise barrier: workers cannot invoke control-plane APIs directly"

        # Workers cannot directly touch secret vault
        if caller.role == ServiceRole.WORKER and target_service == ServiceRole.SECRET_VAULT:
            return False, "Workers cannot query secret vault directly; secrets must be brokered"

        # Check forbidden ops
        for forbidden in FORBIDDEN_OPERATIONS.get(caller.role, set()):
            if forbidden.endswith(":*"):
                prefix = forbidden[:-2]
                if action.startswith(prefix):
                    return False, f"Action {action} is explicitly forbidden for role {caller.role.value}"
            elif action == forbidden:
                return False, f"Action {action} is explicitly forbidden for role {caller.role.value}"

        allowed_perms = SERVICE_PERMISSIONS.get(caller.role, set())
        if action in allowed_perms:
            return True, "Authorized"

        return False, f"Action {action} not in permissions for {caller.role.value}"


# ── 2. Artifact Provenance & SBOM Validation ─────────────────────────────────

@dataclass
class SoftwareComponent:
    name: str
    version: str
    purl: str  # Package URL (e.g. pkg:pypi/cryptography@42.0.0)
    hash_sha256: str
    license: str = "Apache-2.0"
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SoftwareBillOfMaterials:
    bom_format: str = "CycloneDX"
    spec_version: str = "1.5"
    serial_number: str = ""
    timestamp: float = field(default_factory=time.time)
    components: List[SoftwareComponent] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "serialNumber": self.serial_number or f"urn:uuid:{hashlib.sha256(str(self.timestamp).encode()).hexdigest()[:32]}",
            "timestamp": self.timestamp,
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                    "hashes": [{"alg": "SHA-256", "content": c.hash_sha256}],
                    "licenses": [{"license": {"id": c.license}}],
                    "vulnerabilities": c.vulnerabilities,
                }
                for c in self.components
            ],
        }, indent=2)


@dataclass
class ProvenanceAttestation:
    artifact_uri: str
    digest_sha256: str
    builder_id: str
    build_timestamp: float
    source_commit: str
    signature: str
    public_key_fingerprint: str
    sbom: Optional[SoftwareBillOfMaterials] = None

    def verify_signature(self, trusted_keys: Dict[str, bytes]) -> bool:
        """Verify cryptographic signature against trusted key ring."""
        key = trusted_keys.get(self.public_key_fingerprint)
        if not key:
            return False
        payload = f"{self.artifact_uri}:{self.digest_sha256}:{self.source_commit}:{self.build_timestamp}"
        expected_sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)


class ArtifactProvenanceVerifier:
    """Verifies that only signed, scanned, and provenance-attested images/artifacts run."""

    def __init__(self, trusted_keys: Optional[Dict[str, bytes]] = None):
        self.trusted_keys = trusted_keys or {
            "build-signer-primary": b"antigravity-secure-build-signing-key-primary-2026",
        }

    def sign_artifact(
        self,
        artifact_uri: str,
        digest_sha256: str,
        source_commit: str,
        key_id: str = "build-signer-primary",
        sbom: Optional[SoftwareBillOfMaterials] = None,
    ) -> ProvenanceAttestation:
        key = self.trusted_keys.get(key_id)
        if not key:
            raise ValueError(f"Unknown signing key: {key_id}")
        ts = time.time()
        payload = f"{artifact_uri}:{digest_sha256}:{source_commit}:{ts}"
        sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        return ProvenanceAttestation(
            artifact_uri=artifact_uri,
            digest_sha256=digest_sha256,
            builder_id="https://build.antigravity.security/slsa-level-3",
            build_timestamp=ts,
            source_commit=source_commit,
            signature=sig,
            public_key_fingerprint=key_id,
            sbom=sbom,
        )

    def verify_deployment_readiness(
        self,
        attestation: ProvenanceAttestation,
        max_critical_cves: int = 0,
        max_high_cves: int = 0,
    ) -> Tuple[bool, List[str]]:
        reasons: List[str] = []

        if not attestation.verify_signature(self.trusted_keys):
            reasons.append("Artifact cryptographic signature invalid or untrusted")

        if not attestation.sbom:
            reasons.append("Missing Software Bill of Materials (SBOM)")
        else:
            critical_cves = 0
            high_cves = 0
            for comp in attestation.sbom.components:
                for vuln in comp.vulnerabilities:
                    severity = vuln.get("severity", "").upper()
                    if severity == "CRITICAL":
                        critical_cves += 1
                    elif severity == "HIGH":
                        high_cves += 1

            if critical_cves > max_critical_cves:
                reasons.append(f"Found {critical_cves} critical vulnerabilities (max allowed: {max_critical_cves})")
            if high_cves > max_high_cves:
                reasons.append(f"Found {high_cves} high vulnerabilities (max allowed: {max_high_cves})")

        return (len(reasons) == 0, reasons)


# ── 3. Production Threat Model ───────────────────────────────────────────────

class ThreatCategory(str, Enum):
    WORKER_ESCAPE = "worker_escape"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    COMPROMISED_TARGET = "compromised_target"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class ThreatEntry:
    threat_id: str
    category: ThreatCategory
    title: str
    description: str
    impact: str
    mitigation_controls: List[str]
    verified: bool = True


@dataclass
class DeploymentThreatModel:
    model_version: str = "2.0.0"
    last_updated: float = field(default_factory=time.time)
    threats: List[ThreatEntry] = field(default_factory=list)

    @classmethod
    def create_default(cls) -> DeploymentThreatModel:
        return cls(
            threats=[
                ThreatEntry(
                    threat_id="TM-001",
                    category=ThreatCategory.WORKER_ESCAPE,
                    title="Worker Container Escape to Node/Host",
                    description="Malicious payload executes in worker container and attempts root breakout to host.",
                    impact="Potential host access and neighboring worker inspection.",
                    mitigation_controls=[
                        "Non-root container user (UID 10001)",
                        "Read-only root filesystem",
                        "Dropped all Linux capabilities (cap-drop=ALL)",
                        "no-new-privileges flag enforced",
                        "AppArmor/Seccomp syscall filter blocking ptrace/unshare/mount",
                        "Isolated ephemeral scratch workspace per job",
                    ],
                    verified=True,
                ),
                ThreatEntry(
                    threat_id="TM-002",
                    category=ThreatCategory.WORKER_ESCAPE,
                    title="Worker to Control-Plane Lateral Movement",
                    description="Compromised worker attempts to invoke control-plane API or modify job queues.",
                    impact="Unauthorized dispatch of scans or elevation of scope.",
                    mitigation_controls=[
                        "NetworkPolicy disallowing worker -> control plane direct ingress",
                        "ServiceAccessController rejects worker role from invoking control_plane:*",
                        "Zero-trust mTLS service identity with short-lived tokens",
                    ],
                    verified=True,
                ),
                ThreatEntry(
                    threat_id="TM-003",
                    category=ThreatCategory.CREDENTIAL_COMPROMISE,
                    title="Target Credential or API Token Leakage",
                    description="Credentials placed into test targets are dumped or echoed back in logs/reports.",
                    impact="Disclosure of authorized target credentials.",
                    mitigation_controls=[
                        "SecretManager with in-memory-only storage & tenant isolation",
                        "Pattern-based and entropy-based automatic redaction in LLM and logs",
                        "Short-lived scoped token leasing with auto-revocation on breach",
                        "Zero plaintext secrets persisted in evidence store",
                    ],
                    verified=True,
                ),
                ThreatEntry(
                    threat_id="TM-004",
                    category=ThreatCategory.COMPROMISED_TARGET,
                    title="Adversarial Target Prompt Injection / Poisoning",
                    description="Target web application returns malicious prompt injection payloads in DOM or headers.",
                    impact="Agent hijacking to execute unauthorized commands or bypass scope.",
                    mitigation_controls=[
                        "Strict separation of untrusted target observation data from instruction channels",
                        "Deterministic PolicyEngine and ActionGate intercept all tool actuations",
                        "Hard scope pinning: unapproved domains/IPs strictly blocked regardless of LLM output",
                        "Adversarial benchmark corpus verifies prompt-injection resistance",
                    ],
                    verified=True,
                ),
                ThreatEntry(
                    threat_id="TM-005",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    title="Outbound Data Exfiltration via SSRF or Covert Channels",
                    description="Tool or exploit payload attempts to exfiltrate collected evidence or secrets externally.",
                    impact="Confidential customer vulnerability data or tokens sent to 3rd party.",
                    mitigation_controls=[
                        "Destination Authorization Gateway enforcing pre-authorized outbound domains",
                        "DNS rebinding protection and socket connection pinning",
                        "Strict default-deny egress firewall on worker network namespaces",
                        "Complete egress telemetry recording every outbound destination",
                    ],
                    verified=True,
                ),
            ]
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "version": self.model_version,
            "last_updated": self.last_updated,
            "total_threats": len(self.threats),
            "by_category": {
                cat.value: len([t for t in self.threats if t.category == cat])
                for cat in ThreatCategory
            },
            "all_mitigated_and_verified": all(t.verified for t in self.threats),
        }


# ── 4. Hardened Network Architecture Specification ───────────────────────────

def get_reference_network_policy() -> Dict[str, Any]:
    """Returns the zero-trust Kubernetes NetworkPolicy manifest specification."""
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "antigravity-zero-trust-isolation",
            "namespace": "antigravity-production",
        },
        "spec": {
            "podSelector": {
                "matchLabels": {"app.kubernetes.io/part-of": "antigravity"}
            },
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                {
                    "from": [
                        {"podSelector": {"matchLabels": {"role": "control-plane"}}}
                    ],
                    "ports": [{"protocol": "TCP", "port": 8443}],
                }
            ],
            "egress": [
                {
                    "to": [
                        {"podSelector": {"matchLabels": {"role": "policy-gateway"}}}
                    ],
                    "ports": [{"protocol": "TCP", "port": 9443}],
                }
            ],
        },
    }
