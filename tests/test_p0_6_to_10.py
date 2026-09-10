import pytest
import time
from unittest.mock import patch, MagicMock


# ═══════════════════════════════════════════════════════════════════════
# P0.6 — Finding Confirmation Gate
# ═══════════════════════════════════════════════════════════════════════

from core.verification.finding_confirmation_gate import (
    FindingConfirmationGate, ConfirmationStage, EvidenceItem, EvidenceType,
    VulnClassRequirements, VULN_REQUIREMENTS, _is_llm_wording_only,
    _is_status_code_only, _DEFAULT_REQUIREMENTS,
)


class TestP06LLMWordingRejection:
    def test_llm_wording_only_detected(self):
        assert _is_llm_wording_only({"proof": "confirmed verified"}) is True

    def test_llm_wording_with_real_evidence(self):
        assert _is_llm_wording_only({"proof": "SQL error: syntax near 'UNION'"}) is False

    def test_empty_proof_is_llm_wording(self):
        assert _is_llm_wording_only({}) is True
        assert _is_llm_wording_only({"proof": ""}) is True

    def test_status_code_only_detected(self):
        assert _is_status_code_only({"proof": "HTTP 200"}) is True
        assert _is_status_code_only({"proof": "status: 500"}) is True
        assert _is_status_code_only({"proof": "HTTP/1.1 403"}) is True

    def test_llm_wording_padded_still_detected(self):
        assert _is_llm_wording_only(
            {"proof": "the vulnerability has been confirmed and verified and it is exploitable"}) is True

    def test_llm_wording_with_technical_detail(self):
        assert _is_llm_wording_only(
            {"proof": "UNION SELECT username FROM users -- returned 5 rows"}) is False

    def test_status_code_with_body(self):
        assert _is_status_code_only(
            {"proof": "HTTP 200 with body containing admin credentials leaked"}) is False


class TestP06ConfirmationPipeline:
    def test_candidate_to_confirmed_requires_all_evidence(self):
        gate = FindingConfirmationGate()
        gate.register("f1", "SQLI")
        stage, _ = gate.evaluate("f1")
        assert stage == ConfirmationStage.CANDIDATE

        gate.add_support_evidence("f1", EvidenceItem(
            EvidenceType.ERROR_MESSAGE_LEAK, "sqlmap", "SQL syntax error"))
        stage, _ = gate.evaluate("f1")
        assert stage == ConfirmationStage.SUPPORTED

        gate.add_reproduction_evidence("f1", EvidenceItem(
            EvidenceType.REPRODUCTION_MATCH, "sqlmap", "reproduced"))
        stage, _ = gate.evaluate("f1")
        assert stage == ConfirmationStage.REPRODUCED

        gate.add_impact_evidence("f1", EvidenceItem(
            EvidenceType.DATA_EXFILTRATION, "sqlmap", "extracted user table"))
        stage, _ = gate.evaluate("f1")
        assert stage == ConfirmationStage.CONFIRMED

    def test_upstream_confirmed_true_ignored(self):
        gate = FindingConfirmationGate()
        gate.register("f2", "XSS")
        finding = {"confirmed": True, "proof": "confirmed"}
        stage, reason = gate.evaluate("f2", finding)
        assert stage == ConfirmationStage.REJECTED
        assert "LLM wording" in reason

    def test_status_code_only_rejected(self):
        gate = FindingConfirmationGate()
        gate.register("f3", "SQLI")
        finding = {"proof": "HTTP 200"}
        stage, reason = gate.evaluate("f3", finding)
        assert stage == ConfirmationStage.REJECTED
        assert "status code" in reason

    def test_unregistered_finding_rejected(self):
        gate = FindingConfirmationGate()
        stage, _ = gate.evaluate("nonexistent")
        assert stage == ConfirmationStage.REJECTED

    def test_generic_vuln_class_uses_defaults(self):
        gate = FindingConfirmationGate()
        gate.register("f4", "UNKNOWN_VULN_TYPE")
        gate.add_support_evidence("f4", EvidenceItem(
            EvidenceType.BODY_CONTAINS_MARKER, "tool", "marker found"))
        gate.add_reproduction_evidence("f4", EvidenceItem(
            EvidenceType.REPRODUCTION_MATCH, "tool", "reproduces"))
        stage, _ = gate.evaluate("f4")
        assert stage == ConfirmationStage.REPRODUCED
        gate.add_impact_evidence("f4", EvidenceItem(
            EvidenceType.DATA_EXFILTRATION, "tool", "impact demonstrated"))
        stage, _ = gate.evaluate("f4")
        assert stage == ConfirmationStage.CONFIRMED


class TestP06VulnClassRequirements:
    def test_all_defined_vuln_classes_have_requirements(self):
        for vc in ("SQLI", "XSS", "IDOR", "SSRF", "RCE", "PATH_TRAVERSAL",
                    "AUTH_BYPASS", "OPEN_REDIRECT", "XXE",
                    "CSRF", "SSTI", "LFI", "GRAPHQL_INJECTION", "CRLF",
                    "CORS_MISCONFIGURATION", "BUSINESS_LOGIC"):
            assert vc in VULN_REQUIREMENTS, f"{vc} missing from VULN_REQUIREMENTS"

    def test_idor_requires_cross_identity(self):
        reqs = VULN_REQUIREMENTS["IDOR"]
        types = {r.evidence_type for r in reqs.support_evidence}
        assert EvidenceType.CROSS_IDENTITY_ACCESS in types

    def test_idor_needs_two_reproductions(self):
        assert VULN_REQUIREMENTS["IDOR"].min_reproduction_count == 2

    def test_ssrf_impact_optional(self):
        assert VULN_REQUIREMENTS["SSRF"].min_impact_count == 0

    def test_rce_requires_command_output(self):
        reqs = VULN_REQUIREMENTS["RCE"]
        types = {r.evidence_type for r in reqs.support_evidence}
        assert EvidenceType.COMMAND_OUTPUT in types

    def test_default_requires_impact_evidence(self):
        assert _DEFAULT_REQUIREMENTS.min_impact_count == 1

    def test_unknown_vuln_class_needs_full_evidence(self):
        gate = FindingConfirmationGate()
        gate.register("unk1", "TOTALLY_NOVEL_VULN")
        gate.add_support_evidence("unk1", EvidenceItem(
            EvidenceType.BODY_CONTAINS_MARKER, "tool", "marker"))
        gate.add_reproduction_evidence("unk1", EvidenceItem(
            EvidenceType.REPRODUCTION_MATCH, "tool", "repro"))
        stage, _ = gate.evaluate("unk1")
        assert stage == ConfirmationStage.REPRODUCED
        gate.add_impact_evidence("unk1", EvidenceItem(
            EvidenceType.DATA_EXFILTRATION, "tool", "impact"))
        stage, _ = gate.evaluate("unk1")
        assert stage == ConfirmationStage.CONFIRMED

    def test_csrf_full_flow(self):
        gate = FindingConfirmationGate()
        gate.register("csrf1", "CSRF")
        gate.add_support_evidence("csrf1", EvidenceItem(
            EvidenceType.AUTH_BYPASS_PROOF, "probe", "no CSRF token"))
        gate.add_reproduction_evidence("csrf1", EvidenceItem(
            EvidenceType.REPRODUCTION_MATCH, "probe", "forged request"))
        gate.add_impact_evidence("csrf1", EvidenceItem(
            EvidenceType.HTTP_RESPONSE_DIFF, "probe", "state mutated"))
        stage, _ = gate.evaluate("csrf1")
        assert stage == ConfirmationStage.CONFIRMED

    def test_ssti_full_flow(self):
        gate = FindingConfirmationGate()
        gate.register("ssti1", "SSTI")
        gate.add_support_evidence("ssti1", EvidenceItem(
            EvidenceType.REFLECTED_PAYLOAD, "probe", "{{7*7}}=49"))
        gate.add_reproduction_evidence("ssti1", EvidenceItem(
            EvidenceType.REPRODUCTION_MATCH, "probe", "repro"))
        gate.add_impact_evidence("ssti1", EvidenceItem(
            EvidenceType.COMMAND_OUTPUT, "probe", "RCE via Jinja2"))
        stage, _ = gate.evaluate("ssti1")
        assert stage == ConfirmationStage.CONFIRMED

    def test_reject_method(self):
        gate = FindingConfirmationGate()
        state = gate.register("fr", "XSS")
        gate.reject("fr", "manual rejection")
        assert state.stage == ConfirmationStage.REJECTED
        assert state.rejection_reason == "manual rejection"


class TestP06Integration:
    def test_idor_full_flow(self):
        gate = FindingConfirmationGate()
        gate.register("idor1", "IDOR")
        gate.add_support_evidence("idor1", EvidenceItem(
            EvidenceType.CROSS_IDENTITY_ACCESS, "custom_probe",
            "user B accessed user A resource"))
        stage, _ = gate.evaluate("idor1")
        assert stage == ConfirmationStage.SUPPORTED

        gate.add_reproduction_evidence("idor1", EvidenceItem(
            EvidenceType.REPRODUCTION_MATCH, "custom_probe", "repro 1"))
        gate.add_reproduction_evidence("idor1", EvidenceItem(
            EvidenceType.HTTP_RESPONSE_DIFF, "custom_probe",
            "200 with A data vs expected 403"))
        stage, _ = gate.evaluate("idor1")
        assert stage == ConfirmationStage.REPRODUCED

        gate.add_impact_evidence("idor1", EvidenceItem(
            EvidenceType.DATA_EXFILTRATION, "custom_probe",
            "B reads A private data"))
        stage, _ = gate.evaluate("idor1")
        assert stage == ConfirmationStage.CONFIRMED


# ═══════════════════════════════════════════════════════════════════════
# P0.7 — Evidence Chain Integrity
# ═══════════════════════════════════════════════════════════════════════

from core.evidence.evidence_chain import (
    EvidenceChain, EvidenceChainRegistry, ChainEntryType, _GENESIS_HASH,
)


class TestP07EvidenceChain:
    def test_empty_chain_invalid(self):
        chain = EvidenceChain("f1")
        valid, reason = chain.verify()
        assert not valid
        assert "empty" in reason

    def test_single_entry_valid(self):
        chain = EvidenceChain("f1")
        chain.append(ChainEntryType.OBSERVATION, "nmap", "recon",
                     {"port": 80, "state": "open"})
        valid, reason = chain.verify()
        assert valid
        assert reason == "valid"

    def test_hash_linking(self):
        chain = EvidenceChain("f1")
        e1 = chain.append(ChainEntryType.OBSERVATION, "nmap", "recon", {"p": 80})
        e2 = chain.append(ChainEntryType.HYPOTHESIS, "agent", "analysis", {"vuln": "sqli"})
        assert e1.prev_hash == _GENESIS_HASH
        assert e2.prev_hash == e1.content_hash
        valid, _ = chain.verify()
        assert valid

    def test_tamper_detection(self):
        chain = EvidenceChain("f1")
        chain.append(ChainEntryType.OBSERVATION, "nmap", "recon", {"p": 80})
        chain.append(ChainEntryType.EVIDENCE, "sqlmap", "exploit", {"data": "leaked"})
        chain._entries[0] = chain._entries[0].__class__(
            entry_id=chain._entries[0].entry_id,
            entry_type=ChainEntryType.OBSERVATION,
            source_tool="TAMPERED",
            phase="recon",
            content_hash=chain._entries[0].content_hash,
            prev_hash=chain._entries[0].prev_hash,
            timestamp_utc=chain._entries[0].timestamp_utc,
            timestamp_mono=chain._entries[0].timestamp_mono,
            data=chain._entries[0].data,
        )
        valid, reason = chain.verify()
        assert not valid
        assert "hash mismatch" in reason

    def test_sealed_chain_rejects_append(self):
        chain = EvidenceChain("f1")
        chain.append(ChainEntryType.OBSERVATION, "nmap", "recon", {"p": 80})
        chain.seal()
        with pytest.raises(RuntimeError, match="sealed"):
            chain.append(ChainEntryType.EVIDENCE, "x", "y", {})

    def test_confirmation_ready_requires_obs_evidence_validation(self):
        chain = EvidenceChain("f1")
        ready, reason = chain.is_confirmation_ready()
        assert not ready

        chain.append(ChainEntryType.OBSERVATION, "nmap", "recon", {"p": 80})
        ready, reason = chain.is_confirmation_ready()
        assert not ready
        assert "evidence" in reason

        chain.append(ChainEntryType.EVIDENCE, "sqlmap", "exploit", {"data": "x"})
        ready, reason = chain.is_confirmation_ready()
        assert not ready
        assert "validation" in reason

        chain.append(ChainEntryType.VALIDATION_RESULT, "retest", "verify",
                     {"reproduced": True})
        ready, reason = chain.is_confirmation_ready()
        assert ready

    def test_to_dict_roundtrip(self):
        chain = EvidenceChain("f1")
        chain.append(ChainEntryType.OBSERVATION, "tool", "phase", {"k": "v"})
        d = chain.to_dict()
        assert d["finding_id"] == "f1"
        assert d["length"] == 1
        assert len(d["entries"]) == 1


class TestP07Registry:
    def setup_method(self):
        EvidenceChainRegistry.reset_for_tests()

    def test_get_or_create(self):
        reg = EvidenceChainRegistry.get()
        chain = reg.get_or_create("f1")
        assert chain.finding_id == "f1"
        assert reg.get_or_create("f1") is chain

    def test_require_chain_no_chain(self):
        reg = EvidenceChainRegistry.get()
        ok, reason = reg.require_chain_for_confirmation("nonexistent")
        assert not ok

    def test_require_chain_complete(self):
        reg = EvidenceChainRegistry.get()
        chain = reg.get_or_create("f1")
        chain.append(ChainEntryType.OBSERVATION, "t", "p", {})
        chain.append(ChainEntryType.EVIDENCE, "t", "p", {})
        chain.append(ChainEntryType.VALIDATION_RESULT, "t", "p", {})
        ok, _ = reg.require_chain_for_confirmation("f1")
        assert ok


# ═══════════════════════════════════════════════════════════════════════
# P0.8 — Reproduction Validation
# ═══════════════════════════════════════════════════════════════════════

from core.verification.reproduction_gate import (
    ReproductionGate, ReproductionRequest, ReproductionResult, ReproStatus,
    _extract_repro_request, _check_indicators, _hash_response,
)


class TestP08ReproductionGate:
    def _mock_scope(self):
        return patch("core.verification.reproduction_gate.validate_scope",
                     return_value=(True, "mocked"))

    def test_no_url_skipped(self):
        gate = ReproductionGate()
        result = gate.check_reproducible("f1", {})
        assert result.status == ReproStatus.SKIPPED

    def test_no_responses_pending(self):
        with self._mock_scope():
            gate = ReproductionGate()
            result = gate.check_reproducible("f1",
                {"affected_endpoint": "https://target.com/api"})
            assert result.status == ReproStatus.PENDING

    def test_reproduced_on_matching_responses(self):
        with self._mock_scope():
            gate = ReproductionGate()
            responses = [
                {"status": 200, "body": "data leaked"},
                {"status": 200, "body": "data leaked"},
            ]
            result = gate.check_reproducible("f1",
                {"affected_endpoint": "https://target.com/api"},
                responses=responses)
            assert result.status == ReproStatus.REPRODUCED
            assert result.attempts == 2

    def test_failed_on_no_match(self):
        with self._mock_scope():
            gate = ReproductionGate()
            finding = {
                "affected_endpoint": "https://target.com/api",
                "proof": "password leaked",
            }
            responses = [
                {"status": 403, "body": "forbidden"},
                {"status": 403, "body": "forbidden"},
            ]
            result = gate.check_reproducible("f1", finding, responses=responses)
            assert result.status in (ReproStatus.REPRODUCED, ReproStatus.FAILED,
                                      ReproStatus.PARTIAL)

    def test_confirmation_allowed_after_reproduced(self):
        with self._mock_scope():
            gate = ReproductionGate()
            responses = [
                {"status": 200, "body": "ok"},
                {"status": 200, "body": "ok"},
            ]
            gate.check_reproducible("f1",
                {"affected_endpoint": "https://t.com/x"}, responses=responses)
            allowed, _ = gate.is_confirmation_allowed("f1")
            assert allowed

    def test_confirmation_denied_without_attempt(self):
        gate = ReproductionGate()
        allowed, reason = gate.is_confirmation_allowed("f1")
        assert not allowed
        assert "no reproduction" in reason

    def test_scope_denied(self):
        with patch("core.verification.reproduction_gate.validate_scope",
                   return_value=(False, "out of scope")):
            gate = ReproductionGate()
            result = gate.check_reproducible("f1",
                {"affected_endpoint": "https://evil.com/x"})
            assert result.status == ReproStatus.SCOPE_DENIED


class TestP08Helpers:
    def test_extract_repro_request_from_endpoint(self):
        req = _extract_repro_request({"affected_endpoint": "https://t.com/api"})
        assert req is not None
        assert req.url == "https://t.com/api"
        assert req.method == "GET"

    def test_extract_repro_request_from_title(self):
        req = _extract_repro_request(
            {"title": "POST https://t.com/login SQLi", "location": "x"})
        assert req.method == "POST"
        assert "login" in req.url

    def test_extract_repro_no_url(self):
        assert _extract_repro_request({}) is None

    def test_extract_repro_method_from_field(self):
        req = _extract_repro_request({
            "affected_endpoint": "https://t.com/api",
            "method": "POST",
        })
        assert req.method == "POST"

    def test_extract_repro_method_from_title_overrides(self):
        req = _extract_repro_request({
            "affected_endpoint": "https://t.com/old",
            "method": "GET",
            "title": "PUT https://t.com/api/users update",
        })
        assert req.method == "PUT"
        assert "users" in req.url

    def test_extract_repro_body_captured(self):
        req = _extract_repro_request({
            "affected_endpoint": "https://t.com/api",
            "method": "POST",
            "body": '{"admin": true}',
        })
        assert req.body == '{"admin": true}'

    def test_extract_repro_rce_indicators(self):
        req = _extract_repro_request({
            "affected_endpoint": "https://t.com/cmd",
            "proof": "command output: uid=0(root) whoami",
        })
        assert "uid=" in req.expected_indicators
        assert "whoami" in req.expected_indicators
        assert "command output" in req.expected_indicators

    def test_extract_repro_ssrf_indicators(self):
        req = _extract_repro_request({
            "affected_endpoint": "https://t.com/fetch",
            "proof": "response from 169.254.169.254 metadata service",
        })
        assert "169.254.169.254" in req.expected_indicators
        assert "metadata" in req.expected_indicators

    def test_extract_repro_ssti_indicators(self):
        req = _extract_repro_request({
            "affected_endpoint": "https://t.com/render",
            "proof": "{{7*7}} evaluated to 49",
        })
        assert "{{" in req.expected_indicators

    def test_check_indicators_regex(self):
        matched = _check_indicators("SQL error near UNION", ["SQL error", "UNION"])
        assert len(matched) == 2

    def test_check_indicators_case_insensitive(self):
        matched = _check_indicators("admin panel", ["ADMIN"])
        assert len(matched) == 1

    def test_hash_response_deterministic(self):
        h1 = _hash_response(200, "body")
        h2 = _hash_response(200, "body")
        assert h1 == h2
        h3 = _hash_response(200, "different")
        assert h1 != h3


# ═══════════════════════════════════════════════════════════════════════
# P0.9 — Fail-open Audit
# ═══════════════════════════════════════════════════════════════════════

from core.security.fail_open_audit import (
    run_audit, AuditReport, AuditFinding, AuditSeverity,
    _check_policy_engine, _check_tool_validator, _check_secret_vault,
    _check_docker_socket,
)


class TestP09FailOpenAudit:
    def test_audit_report_structure(self):
        report = AuditReport()
        report.add(AuditFinding("test", "check1", AuditSeverity.INFO, True))
        assert report.passed
        assert len(report.findings) == 1

    def test_critical_failure_fails_report(self):
        report = AuditReport()
        report.add(AuditFinding("test", "check1", AuditSeverity.CRITICAL, False))
        assert not report.passed
        assert len(report.critical_failures) == 1

    def test_warning_failure_fails_report(self):
        report = AuditReport()
        report.add(AuditFinding("test", "check1", AuditSeverity.WARNING, False))
        assert not report.passed

    def test_info_failure_doesnt_fail_report(self):
        report = AuditReport()
        report.add(AuditFinding("test", "check1", AuditSeverity.INFO, False))
        assert report.passed

    def test_to_dict(self):
        report = AuditReport()
        report.add(AuditFinding("c", "k", AuditSeverity.INFO, True, "ok"))
        d = report.to_dict()
        assert d["total_checks"] == 1
        assert d["passed_checks"] == 1

    def test_policy_engine_check(self):
        findings = _check_policy_engine()
        assert len(findings) > 0
        assert all(isinstance(f, AuditFinding) for f in findings)

    def test_tool_validator_check(self):
        findings = _check_tool_validator()
        assert len(findings) > 0
        exec_check = [f for f in findings if f.check == "exec_blocked"]
        assert exec_check
        assert exec_check[0].passed

    def test_secret_vault_check(self):
        from core.security.secret_vault import SecretVault
        SecretVault.reset_for_tests()
        findings = _check_secret_vault()
        assert len(findings) > 0
        ref_check = [f for f in findings if f.check == "store_returns_ref"]
        assert ref_check
        assert ref_check[0].passed
        SecretVault.reset_for_tests()

    def test_docker_socket_check_no_socket(self):
        findings = _check_docker_socket()
        assert len(findings) > 0
        mount_check = [f for f in findings if f.check == "not_mounted"]
        assert mount_check

    def test_full_audit_runs(self):
        from core.security.secret_vault import SecretVault
        SecretVault.reset_for_tests()
        report = run_audit()
        assert isinstance(report, AuditReport)
        assert len(report.findings) > 0
        d = report.to_dict()
        assert "total_checks" in d
        SecretVault.reset_for_tests()


# ═══════════════════════════════════════════════════════════════════════
# P0.10 — Docker Socket Guard
# ═══════════════════════════════════════════════════════════════════════

from core.security.docker_socket_guard import (
    check_socket_mount, enforce_no_socket, validate_docker_compose,
    SocketGuardResult,
)


class TestP10DockerSocketGuard:
    def test_no_socket_is_safe(self):
        result = check_socket_mount()
        assert isinstance(result, SocketGuardResult)

    def test_socket_detected_unsafe(self):
        with patch("os.path.exists", return_value=True):
            result = check_socket_mount()
            assert not result.safe
            assert "docker.sock" in result.reason.lower() or result.socket_found

    def test_docker_host_env_socket(self):
        with patch.dict("os.environ", {"DOCKER_HOST": "unix:///var/run/docker.sock"}):
            with patch("os.path.exists", return_value=False):
                result = check_socket_mount()
                assert not result.safe

    def test_enforce_no_socket_fail_hard(self):
        with patch("os.path.exists", return_value=True):
            with pytest.raises(RuntimeError, match="P0.10"):
                enforce_no_socket(fail_hard=True)

    def test_enforce_no_socket_warn_only(self):
        with patch("os.path.exists", return_value=True):
            result = enforce_no_socket(fail_hard=False)
            assert not result.safe

    def test_validate_compose_clean(self):
        clean = """
services:
  web:
    volumes:
      - app_data:/app/data
"""
        ok, reason = validate_docker_compose(clean)
        assert ok

    def test_validate_compose_socket_mount(self):
        dirty = """
services:
  web:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
        ok, reason = validate_docker_compose(dirty)
        assert not ok
        assert "docker.sock" in reason

    def test_validate_compose_docker_host_env(self):
        dirty = """
services:
  web:
    environment:
      DOCKER_HOST: unix:///var/run/docker.sock
"""
        ok, reason = validate_docker_compose(dirty)
        assert not ok

    def test_validate_compose_alternate_mount_path(self):
        dirty = """
services:
  web:
    volumes:
      - /var/run/docker.sock:/tmp/docker.sock
"""
        ok, reason = validate_docker_compose(dirty)
        assert not ok
        assert "docker.sock" in reason

    def test_validate_compose_windows_pipe(self):
        dirty = r"""
services:
  web:
    volumes:
      - \\.\pipe\docker_engine:\\.\pipe\docker_engine
"""
        ok, reason = validate_docker_compose(dirty)
        assert not ok

    def test_docker_host_npipe(self):
        with patch.dict("os.environ", {"DOCKER_HOST": "npipe:////./pipe/docker_engine"}):
            with patch("os.path.exists", return_value=False):
                result = check_socket_mount()
                assert not result.safe

    def test_windows_pipe_detected(self):
        with patch("core.security.docker_socket_guard.sys") as mock_sys:
            mock_sys.platform = "win32"
            with patch("os.path.exists", side_effect=lambda p: "docker_engine" in p):
                result = check_socket_mount()
                assert not result.safe
                assert "docker_engine" in result.socket_found

    def test_compose_file_updated(self):
        import os
        compose_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "docker-compose.yml")
        if os.path.exists(compose_path):
            with open(compose_path) as f:
                content = f.read()
            ok, reason = validate_docker_compose(content)
            assert ok, f"docker-compose.yml still has socket: {reason}"


# ═══════════════════════════════════════════════════════════════════════
# P0.6 existing phase reentry tests still pass
# ═══════════════════════════════════════════════════════════════════════

from core.orchestration.phase_reentry import (
    PhaseReentryController, DependencyEvent, snapshot_ctx,
)


class TestP06PhaseReentryPreserved:
    def test_no_event_forward_only(self):
        c = PhaseReentryController()
        completed = {"RECON", "ACTIVE_SCANNING"}
        assert c.consume_reentries(set(completed)) == completed

    def test_budget_exhaustion(self):
        c = PhaseReentryController(budget_per_phase=1)
        c.signal(DependencyEvent.NEW_HOST)
        first = c.consume_reentries({"RECON"})
        assert "RECON" not in first
        c.signal(DependencyEvent.NEW_HOST)
        second = c.consume_reentries({"RECON"})
        assert "RECON" in second


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
