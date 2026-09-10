"""Tests for Phases 18, 19, and 20.

Covers:
- Phase 18:
  - Structured correlation contexts & propagation
  - Tenant isolation & cross-tenant data boundary prevention
  - Secret lifecycle management, expiry, leak revocation, legal hold
- Phase 19:
  - Adversarial benchmark corpus (SPAs, REST, GraphQL, WebSocket, prompt injections, false-positive traps)
  - Evaluation harness measuring precision, recall, reproducibility, policy bypass rate
  - Evaluation gate CI regression enforcement
- Phase 20:
  - Secure deployment architecture, service identity & token exchange
  - Worker containment barrier (compromised worker cannot call control plane or secret vault)
  - Artifact provenance & SBOM vulnerability gate
  - Production threat model coverage
  - Autonomous red-team readiness gate & machine/human reports
"""
import time
import pytest

# ── Phase 18 Imports ─────────────────────────────────────────────────────────
from core.observability.correlation import CorrelationContext, get_context, set_context
from core.security.tenant_isolation import (
    TenantContext,
    TenantIsolationViolation,
    enforce_tenant_boundary,
    get_current_tenant,
    set_current_tenant,
)
from core.security.secret_lifecycle import (
    SecretLifecycleManager,
    SecretLifecycleRule,
    SecretState,
)

# ── Phase 19 Imports ─────────────────────────────────────────────────────────
from core.validation.benchmark_corpus import (
    AppCategory,
    BenchmarkCorpus,
    BenchmarkFixture,
    FixturePolarity,
)
from core.validation.eval_harness import (
    EvalHarness,
    EvaluationGate,
    EvalMetrics,
    FixtureResult,
)

# ── Phase 20 Imports ─────────────────────────────────────────────────────────
from core.security.deployment_architecture import (
    ArtifactProvenanceVerifier,
    DeploymentThreatModel,
    ServiceAccessController,
    ServiceIdentity,
    ServiceRole,
    SoftwareBillOfMaterials,
    SoftwareComponent,
    ThreatCategory,
)
from core.validation.readiness_gate import (
    AutonomousReadinessGate,
    ControlCategory,
    ReadinessControl,
    ReadinessStatus,
    VerificationVerdict,
)


# =============================================================================
# Phase 18 Tests: Observability, Tenant Isolation, Secret Governance
# =============================================================================

def test_correlation_context_propagation():
    ctx = CorrelationContext(scan_id="scan-123", experiment_id="exp-456")
    set_context(ctx)
    current = get_context()
    assert current["scan_id"] == "scan-123"
    assert current["experiment_id"] == "exp-456"
    assert current["correlation_id"] is not None

    with CorrelationContext(scan_id="scan-inner", experiment_id="exp-inner"):
        inner = get_context()
        assert inner["scan_id"] == "scan-inner"
        assert inner["experiment_id"] == "exp-inner"

    restored = get_context()
    assert restored["scan_id"] == "scan-123"


def test_tenant_isolation_boundary():
    with TenantContext("tenant_acme"):
        assert get_current_tenant() == "tenant_acme"
        # Accessing resource owned by same tenant succeeds
        enforce_tenant_boundary("tenant_acme", "resource-1")

        # Accessing resource owned by another tenant raises TenantIsolationViolation
        with pytest.raises(TenantIsolationViolation):
            enforce_tenant_boundary("tenant_evil_corp", "resource-2")

    # Outside context, returns default
    assert get_current_tenant() == "default"


def test_secret_lifecycle_expiry_and_revocation():
    mgr = SecretLifecycleManager()
    rule = SecretLifecycleRule(
        name="api_token_rule",
        max_age_seconds=1.0,
        revoke_on_leak=True,
    )
    mgr.register_rule(rule)
    secret = mgr.track("db_token", "api_token_rule", tenant_id="tenant_a")
    assert secret.state == SecretState.ACTIVE

    # Legal hold prevents revocation/deletion
    mgr.set_legal_hold("db_token")
    assert secret.state == SecretState.HELD
    assert mgr.revoke("db_token") is False

    # Release hold and revoke
    mgr.release_legal_hold("db_token")
    assert secret.state == SecretState.ACTIVE
    revoked = mgr.revoke("db_token", reason="Leak detected in pastebin")
    assert revoked is True
    assert secret.state == SecretState.REVOKED



# =============================================================================
# Phase 19 Tests: Adversarial Benchmark Corpus & Eval Harness Quality Gate
# =============================================================================

def test_adversarial_benchmark_corpus_structure():
    corpus = BenchmarkCorpus.create_default_corpus()
    assert len(corpus.fixtures) >= 11

    # Verify all major categories are represented
    categories = corpus.categories_represented()
    assert AppCategory.SPA in categories
    assert AppCategory.REST_API in categories
    assert AppCategory.GRAPHQL in categories
    assert AppCategory.WEBSOCKET_SSE in categories
    assert AppCategory.SSO_OAUTH in categories
    assert AppCategory.MULTI_TENANT in categories
    assert AppCategory.UPLOAD_FLOW in categories

    # Verify polarities (positive findings, negative traps, prompt injection resistance)
    positives = corpus.filter_by(polarity=FixturePolarity.POSITIVE)
    negatives = corpus.filter_by(polarity=FixturePolarity.NEGATIVE)
    prompt_injections = corpus.filter_by(polarity=FixturePolarity.PROMPT_INJECTION)

    assert len(positives) > 0
    assert len(negatives) > 0
    assert len(prompt_injections) > 0


def test_eval_harness_metrics_and_ci_gate():
    corpus = BenchmarkCorpus.create_default_corpus()
    harness = EvalHarness(corpus)
    metrics = harness.run_evaluation()

    assert metrics.total_fixtures == len(corpus.fixtures)
    assert metrics.precision >= 0.85
    assert metrics.recall >= 0.80
    assert metrics.policy_bypass_count == 0
    assert metrics.unsafe_action_count == 0

    # Test passing gate
    gate = EvaluationGate(min_precision=0.85, min_recall=0.80, max_policy_bypasses=0)
    passed, reasons = gate.evaluate(metrics)
    assert passed is True
    assert len(reasons) == 0

    # Test failing gate on simulated regression
    regressed_metrics = EvalMetrics(
        true_positives=5,
        false_positives=10,  # poor precision
        true_negatives=5,
        false_negatives=5,
        policy_bypass_count=1,  # unacceptable bypass
    )
    reg_passed, reg_reasons = gate.evaluate(regressed_metrics)
    assert reg_passed is False
    assert any("Precision" in r for r in reg_reasons)
    assert any("Policy bypass" in r for r in reg_reasons)


# =============================================================================
# Phase 20 Tests: Deployment Architecture, Threat Model, and Readiness Gate
# =============================================================================

def test_deployment_service_access_control_and_worker_containment():
    controller = ServiceAccessController()

    worker_id = ServiceIdentity(role=ServiceRole.WORKER, instance_id="worker-node-1")
    control_plane_id = ServiceIdentity(role=ServiceRole.CONTROL_PLANE, instance_id="cp-main")

    # Worker can execute sandboxed tasks and query policy
    allowed, _ = controller.authorize_action(worker_id, "task:execute_sandbox", ServiceRole.WORKER)
    assert allowed is True

    allowed, _ = controller.authorize_action(worker_id, "policy:query", ServiceRole.POLICY_SERVICE)
    assert allowed is True

    # Acceptance Criteria: Compromise of one worker does not grant control-plane access
    allowed, reason = controller.authorize_action(worker_id, "orchestrate:all", ServiceRole.CONTROL_PLANE)
    assert allowed is False
    assert "barrier" in reason or "forbidden" in reason

    # Worker cannot directly query secret vault
    allowed, reason = controller.authorize_action(worker_id, "secret:lease", ServiceRole.SECRET_VAULT)
    assert allowed is False

    # Control plane can orchestrate
    allowed, _ = controller.authorize_action(control_plane_id, "orchestrate:all", ServiceRole.CONTROL_PLANE)
    assert allowed is True


def test_artifact_provenance_and_sbom_verification():
    verifier = ArtifactProvenanceVerifier()

    sbom = SoftwareBillOfMaterials(
        components=[
            SoftwareComponent(
                name="cryptography",
                version="42.0.0",
                purl="pkg:pypi/cryptography@42.0.0",
                hash_sha256="abc123sha",
                vulnerabilities=[],  # Clean
            ),
        ]
    )

    # Sign legitimate artifact
    attestation = verifier.sign_artifact(
        artifact_uri="registry.antigravity.security/worker:v2.0.0",
        digest_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source_commit="commit-abcdef0123456789",
        sbom=sbom,
    )

    ready, issues = verifier.verify_deployment_readiness(attestation)
    assert ready is True
    assert len(issues) == 0

    # Simulated tampered signature
    tampered = verifier.sign_artifact(
        artifact_uri="registry.antigravity.security/worker:v2.0.0",
        digest_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source_commit="commit-abcdef0123456789",
        sbom=sbom,
    )
    # Alter commit without resigning
    object.__setattr__(tampered, "source_commit", "commit-malicious-tamper")
    tampered_ready, tampered_issues = verifier.verify_deployment_readiness(tampered)
    assert tampered_ready is False
    assert any("signature" in i.lower() for i in tampered_issues)


def test_deployment_threat_model_coverage():
    tm = DeploymentThreatModel.create_default()
    assert tm.summary()["total_threats"] >= 5
    assert tm.summary()["all_mitigated_and_verified"] is True

    # Check key threat categories
    categories = {t.category for t in tm.threats}
    assert ThreatCategory.WORKER_ESCAPE in categories
    assert ThreatCategory.CREDENTIAL_COMPROMISE in categories
    assert ThreatCategory.COMPROMISED_TARGET in categories
    assert ThreatCategory.DATA_EXFILTRATION in categories


def test_autonomous_readiness_gate_evaluation_and_reports():
    gate = AutonomousReadinessGate()
    result = gate.evaluate_all()

    # Verify that every mandatory control passed with automated evidence
    assert result.status == ReadinessStatus.READY
    assert result.is_autonomous_ready is True
    assert result.failed_mandatory == 0
    assert result.incomplete_mandatory == 0
    assert result.passed_mandatory == result.mandatory_controls

    # Verify machine-readable report
    json_report = gate.generate_machine_readable_report(result)
    assert json_report["overall_status"] == "READY"
    assert json_report["is_autonomous_ready"] is True
    assert len(json_report["controls"]) == result.total_controls

    # Verify human-readable markdown report
    md_report = gate.generate_human_readable_report(result)
    assert "# Autonomous Red-Team Readiness Gate Report" in md_report
    assert "READY" in md_report
    assert "Control Verification Matrix" in md_report


def test_readiness_gate_refuses_autonomous_mode_on_incomplete_or_failed_control():
    gate = AutonomousReadinessGate()

    # Add an incomplete mandatory control
    gate.register_control(ReadinessControl(
        control_id="RC-TEST-INCOMPLETE",
        category=ControlCategory.OPERATOR_CONTROL,
        phase="Phase 20",
        title="Unimplemented Critical Safety Interlock",
        description="Missing automated check",
        is_mandatory=True,
        check_fn=None,  # No check function -> INCOMPLETE
    ))

    res = gate.evaluate_all()
    # Acceptance Criteria: Incomplete controls produce BLOCKED/NOT_READY
    assert res.status == ReadinessStatus.NOT_READY
    assert res.is_autonomous_ready is False
    assert any("RC-TEST-INCOMPLETE" in r for r in res.blocking_reasons)

    # Now add a failing mandatory control
    gate.register_control(ReadinessControl(
        control_id="RC-TEST-FAIL",
        category=ControlCategory.SCOPE_ENFORCEMENT,
        phase="Phase 20",
        title="Failing Scope Boundary",
        description="Fails automatically",
        is_mandatory=True,
        check_fn=lambda: (False, "Simulated critical breach", {}),
    ))

    res2 = gate.evaluate_all()
    assert res2.status in (ReadinessStatus.BLOCKED, ReadinessStatus.NOT_READY)
    assert res2.is_autonomous_ready is False
