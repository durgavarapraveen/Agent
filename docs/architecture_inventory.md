# Architecture Inventory

**Generated**: 2026-09-10T04:36:34.956767+00:00  
**Source checksum**: `310dafe3bac0cb61`  
**Components**: 460  

## Risk Summary

| Category | Count |
|----------|-------|
| Network I/O | 4813 |
| Filesystem Write | 444 |
| State Mutation (DB) | 353 |
| Dynamic Code Execution | 162 |
| Process Execution | 132 |
| Credential Access | 121 |
| Browser Automation | 3 |

## Duplicate/Competing Implementations

### authorization (5 files)
- `core/security/authorization.py`
- `core/security/authorization_service.py`
- `agents/authorization.py`
- `core/decisions/policy_engine.py`
- `core/security/policy_engine.py`

### coverage_tracking (4 files)
- `core/coverage/coverage_tracker.py`
- `core/coverage/coverage_engine.py`
- `core/exploitation/coverage_tracker.py`
- `core/orchestration/endpoint_coverage.py`

### hypothesis_engine (3 files)
- `core/hypothesis/hypothesis_engine.py`
- `core/reasoning/hypothesis_engine.py`
- `core/coverage/hypothesis_engine.py`

### state_store (4 files)
- `core/memory/shared_context.py`
- `core/memory/context.py`
- `core/intelligence/application_model.py`
- `core/knowledge/knowledge_graph.py`

### scheduling (3 files)
- `core/orchestration/scheduler.py`
- `core/orchestration/legacy_scheduler.py`
- `core/scheduling/experiment_scheduler.py`

### evidence_findings (6 files)
- `core/evidence/evidence.py`
- `core/evidence/evidence_chain.py`
- `core/findings/finding.py`
- `core/findings/finding_store.py`
- `core/domain/finding.py`
- `core/domain/evidence.py`

### convergence (2 files)
- `core/convergence/convergence_engine.py`
- `core/coverage/convergence_engine.py`

### error_handling (2 files)
- `core/error/error_classifier.py`
- `core/common/error_classifier.py`


## Components by Type

### access_control (6 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/access_control/base.py` | AuthorizationOracle, AccessControlTest | 0 | - |
| `core/access_control/horizontal.py` | HorizontalTest | 0 | - |
| `core/access_control/idor.py` | IdorTest | 1 | - |
| `core/access_control/matrix_engine.py` | MatrixEngine | 1 | - |
| `core/access_control/unauthenticated.py` | UnauthenticatedTest | 0 | - |
| `core/access_control/vertical.py` | VerticalTest | 0 | - |

### adaptation (3 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/adaptation/__init__.py` |  | 0 | - |
| `core/adaptation/generic_site_adapter.py` | AuthModel, APIStructure, SiteProfile +1 | 5 | - |
| `core/adaptation/waf_state.py` | WafMode, TargetWafState, WafStateMachine | 1 | - |

### agent (9 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `agents/__init__.py` |  | 0 | - |
| `agents/authorization.py` | ExploitTier, AuthorizationManager | 12 | - |
| `agents/base.py` | BaseAgent | 0 | - |
| `agents/exploit_agent.py` | UniversalExploitAgent | 138 | - |
| `agents/kali_executor.py` | KaliDockerExecutor | 29 | - |
| `agents/llm_client.py` | LLMProvider, DeepSeekProvider, LLMClient +1 | 11 | - |
| `agents/llm_harness_adapter.py` |  | 15 | - |
| `agents/payload_generator.py` | PayloadType, PayloadGenerator | 4 | - |
| `agents/universal_llm_harness.py` | ProviderType, PricingTier, UsageMetrics +8 | 60 | - |

### analysis_engine (39 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/analysis/__init__.py` |  | 0 | - |
| `core/analysis/codeql_runner.py` |  | 40 | - |
| `core/analysis/correlation_engine.py` | AttackChain, CorrelationEngine | 38 | - |
| `core/analysis/finding_confidence.py` | FindingConfidence | 7 | - |
| `core/analysis/source_extractor.py` |  | 32 | - |
| `core/intelligence/__init__.py` |  | 1 | - |
| `core/intelligence/_provider_gate.py` | ProviderGate, ProviderCircuitOpen, _AcquireCtx | 4 | - |
| `core/intelligence/application_model.py` | ModelEvent, ServiceInfo, RoleInfo +11 | 20 | `tests/test_p1_1_application_model.py` |
| `core/intelligence/asset_classifier.py` | AssetClass, AssetProfile | 1 | - |
| `core/intelligence/censys_client.py` | CensysClient | 8 | - |
| `core/intelligence/differential/__init__.py` |  | 0 | - |
| `core/intelligence/differential/comparison.py` | ResponseSnapshot, Divergence | 9 | - |
| `core/intelligence/differential/engine.py` | DifferentialResult, DifferentialEngine | 3 | `tests/test_p0_1_policy_engine.py` |
| `core/intelligence/differential/representations.py` | HttpRequest | 0 | - |
| `core/intelligence/framework_corpus/__init__.py` |  | 6 | - |
| `core/intelligence/intelligence_fetcher.py` | IntelligenceFetcher | 75 | - |
| `core/intelligence/invariants/__init__.py` |  | 0 | - |
| `core/intelligence/invariants/engine.py` | InvariantViolation, InvariantEngine | 0 | `tests/test_p0_1_policy_engine.py` |
| `core/intelligence/invariants/library.py` | SecurityInvariant | 7 | - |
| `core/intelligence/llm_context_builder.py` | LLMContextBuilder | 0 | - |
| `core/intelligence/metamorphic/__init__.py` |  | 0 | - |
| `core/intelligence/metamorphic/engine.py` | MetamorphicViolation, MetamorphicResult, MetamorphicEngine | 3 | `tests/test_p0_1_policy_engine.py` |
| `core/intelligence/metamorphic/relations.py` | MetamorphicRelation | 2 | - |
| `core/intelligence/osint_engine.py` | Employee, LeakedCredential, DomainIntelligence +5 | 19 | - |
| `core/intelligence/osint_integration.py` | OSINTAgentSpec, OSINTOrchestrator, OSINTCapabilityResolver | 9 | - |
| `core/intelligence/parser_differential/__init__.py` |  | 0 | - |
| `core/intelligence/parser_differential/engine.py` | ParserObservation, ParserAnalysis, ParserDifferentialEngine | 2 | `tests/test_p0_1_policy_engine.py` |
| `core/intelligence/parser_differential/mutations.py` | ParserProbe | 0 | - |
| `core/intelligence/patch_tracker.py` | PatchTracker | 7 | - |
| `core/intelligence/subdomain_enum.py` | Subdomain, VirtualHost, CloudStorageBucket +5 | 39 | - |
| `core/intelligence/takeover_detector.py` | TakeoverVerdict | 0 | - |
| `core/intelligence/takeover_workflow.py` | TakeoverStage, TakeoverCandidate | 9 | - |
| `core/intelligence/target_profiler.py` | TargetType, TechnologyStack, TargetProfile +1 | 19 | - |
| `core/intelligence/threat_intel.py` | ThreatIndicator, ReputationScore, CompromisedService +4 | 38 | - |
| `core/intelligence/vuln_intel/__init__.py` |  | 0 | - |
| `core/intelligence/vuln_intel/feeds.py` | FeedResult, VulnerabilityDatabase, FeedClient +1 | 34 | - |
| `core/intelligence/vuln_intel/matcher.py` | PackageMatch, CVEMatcher | 28 | - |
| `core/intelligence/vuln_intel/scorer.py` | RiskVerdict | 7 | - |
| `core/intelligence/vulnerability_intelligence.py` | VulnerabilityIntelligence | 5 | - |

### attack_surface (11 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/attack_surface/__init__.py` |  | 0 | - |
| `core/attack_surface/attack_surface_state.py` | AttackSurfaceState | 9 | - |
| `core/attack_surface/endpoint_inventory.py` | EndpointInventoryV2 | 12 | - |
| `core/attack_surface/graph.py` | AttackSurfaceGraph | 9 | - |
| `core/attack_surface/infra_layer.py` | InfraLayer | 1 | - |
| `core/attack_surface/object_inventory.py` | ObjectInventory | 1 | - |
| `core/attack_surface/parameter_inventory.py` | ParameterInventory | 1 | - |
| `core/attack_surface/request_inventory.py` | RequestInventory | 3 | - |
| `core/attack_surface/route_normalizer.py` | RouteNormalizer | 0 | - |
| `core/attack_surface/spa_detector.py` | SPADetector | 2 | - |
| `core/attack_surface/workflow_inventory.py` | WorkflowInventory | 0 | - |

### authentication (3 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/authentication/__init__.py` |  | 0 | - |
| `core/authentication/auth_session.py` | AuthConfig, AuthSessionManager, MultiIdentityAuthManager | 42 | - |
| `core/authentication/identity_bridge.py` | SessionIdentity | 2 | - |

### browser_driver (6 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/actuation/__init__.py` |  | 0 | - |
| `core/actuation/actuators.py` | Actuators | 5 | - |
| `core/actuation/agent_loop.py` | ObjectiveAgentLoop | 41 | - |
| `core/actuation/browser_actuator.py` | BrowserActuator | 10 | - |
| `core/workflows/__init__.py` |  | 0 | - |
| `core/workflows/browser_workflows.py` | WorkflowState, StepOutcome, WorkflowStep +1 | 1 | - |

### checkpointing (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/checkpointing/__init__.py` |  | 0 | - |
| `core/checkpointing/secure_checkpoint.py` | SecureCheckpoint | 7 | - |

### cloud (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/cloud/__init__.py` |  | 0 | - |
| `core/cloud/iam_privesc.py` | IAMPrivescAnalyzer, K8sRBACAnalyzer, ContainerEscapeChecker +1 | 34 | - |

### common (24 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/common/__init__.py` |  | 1 | - |
| `core/common/config.py` | Config | 31 | - |
| `core/common/endpoint_hints.py` |  | 21 | - |
| `core/common/endpoint_normalizer.py` | CanonicalEndpoint, EndpointDedupe | 3 | - |
| `core/common/error_classifier.py` | ErrorClassifier | 3 | - |
| `core/common/error_hygiene.py` |  | 1 | - |
| `core/common/error_translator.py` | ErrorCategory, ErrorTranslator | 0 | - |
| `core/common/events.py` | EventType, Event, EventBus +1 | 2 | - |
| `core/common/exceptions.py` | AutonomousPentestException, ToolValidationError, LLMEmptyResponseError +13 | 0 | - |
| `core/common/hybrid_executor_logger.py` | HybridExecutorLogger | 5 | - |
| `core/common/llm_schemas.py` | LLMHypothesis, LLMDecision, HypothesisProposal +1 | 0 | - |
| `core/common/models.py` | TaskStatus, FindingSeverity, FindingStatus +10 | 2 | - |
| `core/common/normalizer.py` | PlannerSchemaError, PlannerResponseNormalizer | 33 | - |
| `core/common/recovery_engine.py` | RecoveryEngine | 13 | - |
| `core/common/recovery_strategies.py` | FallbackRecoveryManager | 3 | - |
| `core/common/reports_config.py` |  | 3 | - |
| `core/common/result_formatter.py` | ToolResultFormatter | 9 | - |
| `core/common/result_normalizers.py` | ResultNormalizer, DNSResultNormalizer, NmapResultNormalizer +4 | 7 | - |
| `core/common/retry_policy.py` | RetryDecision, RetryPolicy | 9 | - |
| `core/common/scan_cleanup.py` |  | 4 | - |
| `core/common/schemas.py` | TaskStatus, CapabilityType, ErrorType +21 | 3 | - |
| `core/common/startup_diagnostics.py` |  | 4 | - |
| `core/common/token_optimizer.py` | TokenOptimizer | 21 | - |
| `core/common/tool_retry.py` |  | 3 | - |

### compliance (4 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/compliance/__init__.py` |  | 0 | - |
| `core/compliance/frameworks.py` |  | 2 | - |
| `core/compliance/mapper.py` | ComplianceHit, ComplianceMapper | 9 | - |
| `core/compliance/reporter.py` | ControlResult, ComplianceReporter | 9 | - |

### convergence (3 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/convergence/__init__.py` |  | 0 | - |
| `core/convergence/completion_validator.py` | CompletionValidator | 0 | - |
| `core/convergence/convergence_engine.py` | ConvergenceState, ConvergenceMetrics, ConvergenceEngine +1 | 0 | - |

### coverage (17 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/coverage/__init__.py` |  | 0 | - |
| `core/coverage/applicability.py` | ApplicabilityEngine | 0 | - |
| `core/coverage/applicability_engine.py` | ApplicabilityResult, ApplicabilityEngine | 6 | - |
| `core/coverage/catalog.py` | SecurityTestCatalog | 1 | - |
| `core/coverage/convergence_engine.py` | ConvergenceStatus, ConvergenceEngine | 0 | - |
| `core/coverage/coverage_engine.py` | CoverageEngine | 12 | - |
| `core/coverage/coverage_matrix.py` | CoverageState, CoverageMatrix | 16 | - |
| `core/coverage/coverage_report.py` | CoverageReportGenerator | 0 | - |
| `core/coverage/coverage_state.py` | TestRunState, CoverageStateV2 | 0 | - |
| `core/coverage/coverage_tracker.py` | TestOutcome, FailureReason, TestAttempt +1 | 8 | - |
| `core/coverage/feedback_loop.py` | ResponseSignature, ResponseClassifier, ErrorMiner +2 | 6 | - |
| `core/coverage/hypothesis_engine.py` | HypothesisEngine | 21 | - |
| `core/coverage/hypothesis_ledger.py` | HypothesisLedger | 2 | - |
| `core/coverage/identity_coverage.py` | IdentityCoverageCell, IdentityCoverageEngine | 2 | - |
| `core/coverage/payload_catalog.py` | Payload, PayloadCatalog | 1 | - |
| `core/coverage/security_test_catalog.py` | SecurityTest, SecurityTestCatalog | 50 | - |
| `core/coverage/test_definition.py` | ApplicabilityRule, SecurityTestDefinition | 0 | - |

### database (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/database/__init__.py` |  | 0 | - |
| `core/database/pg_store.py` | TargetRepo, ScanRepo, VulnRepo +20 | 194 | - |

### defensive (5 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/defensive/__init__.py` |  | 0 | - |
| `core/defensive/credential_hardening.py` | SecretFinding, SecretScanner, CredentialHardeningAuditor | 2 | - |
| `core/defensive/manager.py` | DefensiveRiskAssessor | 6 | - |
| `core/defensive/network_audit.py` | ExposureFinding, NetworkAuditor | 5 | - |
| `core/defensive/persistence_monitor.py` | PersistenceMonitor | 2 | - |

### discovery (3 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/discovery/__init__.py` |  | 0 | - |
| `core/discovery/api_schema_importer.py` | APISchemaImporter | 63 | - |
| `core/discovery/js_analyzer.py` | JSFinding, JSAnalyzer | 22 | - |

### domain_model (16 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/domain/__init__.py` |  | 0 | - |
| `core/domain/artifact_registry.py` | ArtifactType, Artifact, ArtifactRegistry | 2 | - |
| `core/domain/asset.py` | Technology, Application, Host +6 | 0 | - |
| `core/domain/asset_registry.py` | Asset, AssetRegistry | 3 | - |
| `core/domain/base.py` | DomainModel, Config | 0 | - |
| `core/domain/coverage.py` | TestState, CoverageState | 0 | - |
| `core/domain/endpoint.py` | DiscoveryState, SchemaNode, Endpoint | 0 | `tests/test_p0_1_endpoint_counts.py` |
| `core/domain/evidence.py` | SecurityEvidence | 0 | - |
| `core/domain/experiment.py` | ExperimentState, ExperimentResult, SecurityExperiment | 1 | - |
| `core/domain/finding.py` | FindingState, SecurityFinding | 0 | `tests/test_p1_finding_endpoint.py` |
| `core/domain/hypothesis.py` | HypothesisState, SecurityHypothesis | 0 | - |
| `core/domain/identity.py` | Role, AuthenticationState, Identity | 0 | - |
| `core/domain/parameter.py` | ParameterType, Parameter | 0 | - |
| `core/domain/request.py` | ResponseData, CapturedRequest | 0 | - |
| `core/domain/session.py` | Session | 0 | `tests/test_p0_2_session_isolation.py` |
| `core/domain/task_state_machine.py` | TaskState, TaskStateMachine | 2 | - |

### economics (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/economics/__init__.py` |  | 0 | - |
| `core/economics/budget_governor.py` | BudgetGovernor | 4 | - |

### error (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/error/__init__.py` |  | 0 | - |
| `core/error/error_classifier.py` | ErrorCategory, RecoveryAction, ClassifiedError +2 | 5 | - |

### escalation (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/escalation/__init__.py` |  | 0 | - |
| `core/escalation/escalation_gate.py` | RiskLevel, ApprovalStatus, ApprovalDecision +1 | 18 | - |

### evidence (7 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/evidence/__init__.py` |  | 0 | - |
| `core/evidence/confidence_model.py` | ConfidenceInputs | 2 | - |
| `core/evidence/evidence.py` | Evidence | 0 | - |
| `core/evidence/evidence_chain.py` | ChainEntryType, ChainEntry, EvidenceChain +1 | 2 | - |
| `core/evidence/oracle.py` | Oracle, DifferentialResponseOracle, ErrorSignatureOracle +7 | 24 | - |
| `core/evidence/screenshot_capture.py` | ScreenshotResult, ScreenshotCapture | 31 | - |
| `core/evidence/validator.py` | ValidationResult, EvidenceValidator | 1 | - |

### executor (13 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/execution/__init__.py` |  | 0 | - |
| `core/execution/environment_profile.py` |  | 1 | - |
| `core/execution/execution_pipeline.py` | PipelineStage, PipelineResult, ExecutionPipelineV2 | 9 | - |
| `core/execution/executors/__init__.py` |  | 0 | - |
| `core/execution/executors/auth_registry.py` |  | 4 | - |
| `core/execution/executors/authentication.py` | AuthenticationExecutor | 11 | - |
| `core/execution/executors/authorization.py` | AuthorizationExecutor | 4 | - |
| `core/execution/executors/base.py` | ExecutionStatus, ExecutionResult, ExecutorBase | 0 | - |
| `core/execution/executors/differential_research.py` | _ResearchBase, DifferentialResearchExecutor, MetamorphicConsistencyExecutor +1 | 1 | - |
| `core/execution/executors/generic.py` | GenericHTTPExecutor, CORSExecutor, InfoDisclosureExecutor +69 | 256 | - |
| `core/execution/executors/sql_injection.py` | SQLiExecutor | 6 | - |
| `core/execution/executors/xss.py` | XSSExecutor | 6 | - |
| `core/execution/sandbox.py` | SandboxMode, ExecutionLanguage, SandboxConfig +2 | 11 | - |

### exploitation (33 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/exploitation/__init__.py` |  | 1 | - |
| `core/exploitation/api_reconstructor.py` | APIReconstructor | 16 | - |
| `core/exploitation/chain_detector.py` | ScoredChain, ChainDetector | 32 | - |
| `core/exploitation/chain_executor.py` | StepResult, ChainResult, ChainExecutor | 20 | - |
| `core/exploitation/chain_integration.py` | ChainManager | 3 | - |
| `core/exploitation/coverage_tracker.py` | _EndpointBucket, CoverageTracker | 2 | - |
| `core/exploitation/credential_spray.py` | SprayResult, CredentialSprayEngine | 16 | - |
| `core/exploitation/cross_role_replay.py` |  | 16 | - |
| `core/exploitation/custom_probe.py` | _ScopedHTTPX | 35 | - |
| `core/exploitation/dom_sink_monitor.py` |  | 7 | - |
| `core/exploitation/dump_extractor.py` |  | 10 | - |
| `core/exploitation/expert_probes.py` |  | 23 | - |
| `core/exploitation/exploit_chain.py` | ChainPrerequisite, ExploitChain, POCGate | 14 | - |
| `core/exploitation/exploit_factory.py` | SafeExploitFactory | 10 | - |
| `core/exploitation/format_probes/__init__.py` |  | 0 | - |
| `core/exploitation/format_probes/fsspec_jinja_probes.py` |  | 1 | - |
| `core/exploitation/format_probes/hdf5_probes.py` |  | 4 | - |
| `core/exploitation/format_probes/parquet_probes.py` |  | 0 | - |
| `core/exploitation/format_probes/yaml_pickle_probes.py` | _PickleRCE | 4 | - |
| `core/exploitation/graphql_ws_probe.py` |  | 18 | - |
| `core/exploitation/hash_cracker.py` |  | 22 | - |
| `core/exploitation/js_bundle_analyzer.py` |  | 7 | - |
| `core/exploitation/lateral_movement.py` | Credential, PivotPoint, LateralMovementPlanner | 13 | - |
| `core/exploitation/modern_api.py` | GraphQLTester, GrpcTester, WebSocketTester +1 | 17 | - |
| `core/exploitation/payload_tester.py` | PayloadTester | 4 | - |
| `core/exploitation/poc_generator.py` | POCGenerator, _FileLike, _FileLike +1 | 8 | - |
| `core/exploitation/post_exploit.py` | PostExploitManager | 6 | - |
| `core/exploitation/privesc_detector.py` | PrivescFinding, PrivescDetector | 23 | - |
| `core/exploitation/request_capture.py` | CapturedRequest, CaptureResult, RequestCapturer | 32 | - |
| `core/exploitation/request_replayer.py` |  | 17 | - |
| `core/exploitation/sandbox_detonator.py` | SynthesizedExploit, DetonationResult, ExploitSynthesizer +2 | 23 | - |
| `core/exploitation/semantic_api_fuzzer.py` |  | 15 | - |
| `core/exploitation/waf_evasion.py` | WAFType, WAFEvasionManager | 0 | - |

### extraction (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/extraction/endpoint_extractor.py` | EndpointExtractor | 0 | - |
| `core/extraction/parameter_extractor.py` | ParameterExtractor | 0 | - |

### failure (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/failure/__init__.py` |  | 0 | - |
| `core/failure/failure_taxonomy.py` | FailureType, FailureClassifier | 1 | - |

### findings (5 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/findings/__init__.py` |  | 0 | - |
| `core/findings/finding.py` | FindingState, FindingSeverity, Finding | 22 | `tests/test_p1_finding_endpoint.py` |
| `core/findings/finding_state_machine.py` | FindingStateMachine | 1 | - |
| `core/findings/finding_store.py` | FindingStore | 11 | - |
| `core/findings/observation.py` | KnowledgeType, LifecycleStage, Observation +1 | 1 | - |

### fuzzing (3 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/fuzzing/adapters.py` | BaseAdapter, SQLMapAdapter, NucleiAdapter +1 | 12 | - |
| `core/fuzzing/fuzzer_orchestrator.py` | FuzzerOrchestrator | 1 | - |
| `core/fuzzing/models.py` | ToolStatus, ToolResult | 0 | - |

### identity (6 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/identity/credential_store.py` | CredentialRef, CredentialStore | 2 | - |
| `core/identity/identity_manager.py` | Identity, IdentityManager | 1 | - |
| `core/identity/login_detector.py` | LoginType, LoginDetector | 0 | - |
| `core/identity/session_manager.py` | SessionArtifact, SessionManager | 1 | - |
| `core/identity/session_refresh.py` | SessionRefreshRequired, SessionRefreshHandler | 1 | - |
| `core/identity/session_validator.py` | SessionValidator | 1 | - |

### injection (4 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/injection/eligibility.py` | InjectionEligibilityChecker | 0 | - |
| `core/injection/injection_matrix.py` | InjectionMatrix | 0 | - |
| `core/injection/injection_reporter.py` | InjectionReporter | 1 | - |
| `core/injection/models.py` | TestStatus, Payload, InjectionTest +2 | 0 | - |

### intel (5 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/intel/__init__.py` |  | 0 | - |
| `core/intel/security_kb.py` |  | 18 | - |
| `core/intel/skill_library.py` |  | 21 | - |
| `core/intel/target_memory.py` |  | 33 | - |
| `core/intel/tool_authoring.py` |  | 14 | - |

### learning (4 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/learning/__init__.py` |  | 0 | - |
| `core/learning/experience_learner.py` | StorageBackend, InMemoryStorage, ExperienceLearner | 2 | - |
| `core/learning/reward_policy.py` | RewardPolicy | 21 | - |
| `core/learning/structured_learning.py` | LearningRecord, StructuredLearningEngine | 8 | - |

### llm (5 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/llm/circuit_breaker.py` | CircuitOpen, _Breaker | 4 | - |
| `core/llm/context_builder.py` | ContextBuilder | 0 | - |
| `core/llm/llm_router.py` | LLMRouter | 4 | - |
| `core/llm/prompt_safety.py` |  | 3 | - |
| `core/llm/schemas.py` | RankedCandidate, RankedCandidatesResult, GeneratedPayload +2 | 0 | - |

### monitoring (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/monitoring/__init__.py` |  | 0 | - |
| `core/monitoring/asm_monitor.py` | ASMDelta, ASMMonitor | 42 | - |

### network (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/network/__init__.py` |  | 0 | - |
| `core/network/network_broker.py` | ResolvedTarget, NetworkDecision, DNSResolver +3 | 5 | `tests/test_p0_2_network_broker.py` |

### notifications (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/notifications/__init__.py` |  | 0 | - |
| `core/notifications/notify.py` |  | 18 | - |

### observability (6 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/observability/__init__.py` |  | 0 | - |
| `core/observability/logging_setup.py` | PIIRedactionFilter, JSONFormatter | 2 | - |
| `core/observability/metrics.py` | _Noop, _CM | 0 | - |
| `core/observability/scan_metrics.py` | ScanMetrics, MetricsCollector | 1 | - |
| `core/observability/structured_logger.py` |  | 0 | - |
| `core/observability/tracing.py` |  | 3 | - |

### orchestration (35 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/orchestration/__init__.py` |  | 1 | - |
| `core/orchestration/adversarial_critic.py` |  | 19 | - |
| `core/orchestration/agent_scratchpad.py` | ScratchpadEntry, Scratchpad | 7 | - |
| `core/orchestration/agent_spawner.py` | AgentSpawner | 34 | - |
| `core/orchestration/agentic_executor.py` | AgenticResult, AgenticExecutor | 236 | - |
| `core/orchestration/automation.py` | Rule, RemediationItem, AutomationEngine | 12 | - |
| `core/orchestration/campaign.py` | TargetResult, CampaignManager | 8 | - |
| `core/orchestration/capability_resolver.py` | CapabilityResolver | 1 | - |
| `core/orchestration/capability_worker.py` | CapabilityWorker | 36 | - |
| `core/orchestration/central_brain.py` | PhaseConfig, PhaseState, ExecutionPhase +1 | 492 | - |
| `core/orchestration/central_brain_mixins/__init__.py` |  | 0 | - |
| `core/orchestration/central_brain_mixins/finding_ingestion.py` | FindingIngestionMixin | 81 | - |
| `core/orchestration/central_brain_mixins/osint_bridge.py` | OsintBridgeMixin | 25 | - |
| `core/orchestration/central_brain_mixins/persistence.py` | PersistenceMixin | 81 | - |
| `core/orchestration/central_brain_mixins/recon_context.py` | ReconContextMixin | 21 | - |
| `core/orchestration/checkpointer.py` | Checkpointer | 19 | - |
| `core/orchestration/claude_agent_loop.py` | LLMToolProvider, ClaudeAgentLoop | 1 | - |
| `core/orchestration/decision_pipeline.py` | DecisionAction, StructuredDecision, DecisionValidationResult +3 | 25 | - |
| `core/orchestration/dynamic_agent.py` | DynamicAgent | 34 | - |
| `core/orchestration/endpoint_coverage.py` | CoverageRecord, CoverageTracker | 1 | - |
| `core/orchestration/execution_mode.py` | ExecutionMode, ExecutionConfig | 7 | - |
| `core/orchestration/hexstrike_decision_engine.py` | TargetType, TechnologyStack, TargetProfile +3 | 4 | - |
| `core/orchestration/legacy_scheduler.py` | Scheduler | 3 | - |
| `core/orchestration/meta_brain.py` | MetaBrain | 9 | - |
| `core/orchestration/parallel_agents.py` | AgentTracker | 0 | - |
| `core/orchestration/parallel_executor.py` | TaskResult, ParallelExecutor | 3 | - |
| `core/orchestration/phase_dag.py` | PhaseNode, PhaseScheduler | 0 | - |
| `core/orchestration/phase_reentry.py` | DependencyEvent, PhaseReentryController | 12 | `tests/test_p0_6_phase_reentry.py` |
| `core/orchestration/progress.py` | ProgressSnapshot, ProgressEvaluator | 1 | - |
| `core/orchestration/resume.py` |  | 4 | - |
| `core/orchestration/scheduler.py` | ScanSchedule, ScanScheduler | 16 | - |
| `core/orchestration/target_health_manager.py` | TargetHealthManager | 4 | - |
| `core/orchestration/target_plan.py` | TargetSummary, PlanItem | 0 | - |
| `core/orchestration/task_evaluator.py` | CompletionStatus, TaskCompletionEvaluator, TaskEvaluator | 12 | - |
| `core/orchestration/task_manager.py` | TaskStateTransitionError, Task, TaskManager | 21 | - |

### other (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/__init__.py` |  | 2 | - |
| `main.py` | _AnsiResetFormatter | 18 | - |

### policy_engine (4 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/decisions/__init__.py` |  | 0 | - |
| `core/decisions/decision_guard.py` | DecisionGuardV2 | 1 | - |
| `core/decisions/policy_engine.py` | DecisionOwner, PolicyVerdict | 14 | `tests/test_p0_1_policy_engine.py` |
| `core/decisions/provenance.py` | Decision, DecisionLog | 3 | - |

### prompts (1 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/prompts/adaptive.py` | AdaptivePromptEngine | 4 | - |

### rag (8 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/rag/__init__.py` |  | 0 | - |
| `core/rag/embedder.py` | EmbedResult, Embedder | 6 | - |
| `core/rag/hyde.py` |  | 10 | - |
| `core/rag/ingestion.py` |  | 17 | - |
| `core/rag/knowledge_seeder.py` |  | 5 | - |
| `core/rag/local_embedder.py` | LocalSemanticEmbedder | 3 | - |
| `core/rag/pipeline.py` | SecurityRAGPipeline | 33 | `tests/test_e2e_pipeline.py` |
| `core/rag/reranker.py` | Reranker | 11 | - |

### reasoning (7 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/hypothesis/__init__.py` |  | 0 | - |
| `core/hypothesis/hypothesis_engine.py` | HypothesisState, Hypothesis, HypothesisEngine | 4 | - |
| `core/hypothesis/hypothesis_generator.py` | HypothesisGenerator | 3 | - |
| `core/hypothesis/hypothesis_ranker.py` | StrategyEffectivenessScorer, HypothesisRanker | 1 | - |
| `core/reasoning/__init__.py` |  | 0 | - |
| `core/reasoning/hypothesis_engine.py` | Hypothesis, HypothesisEngine | 2 | - |
| `core/reasoning/reasoning_engine.py` | Hypothesis, ReasoningEngine | 4 | - |

### recovery (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/recovery/__init__.py` |  | 0 | - |
| `core/recovery/recovery_policy.py` | RetryAction, RecoveryPolicy | 2 | - |

### replay (4 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/replay/http_proxy.py` | HttpProxy | 4 | - |
| `core/replay/identity_store.py` | IdentityStore | 4 | - |
| `core/replay/replay_engine.py` | ReplayEngine | 1 | - |
| `core/replay/session_manager.py` | SessionManager | 1 | - |

### reporting (29 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/reporting/__init__.py` |  | 2 | - |
| `core/reporting/agent_activity.py` | AgentActivityLog | 2 | - |
| `core/reporting/baseline.py` | BaselineManager | 29 | - |
| `core/reporting/canonical_reporter.py` | CanonicalReporter | 23 | - |
| `core/reporting/chain_intelligence.py` |  | 19 | - |
| `core/reporting/compliance_gate.py` | ComplianceGate | 0 | - |
| `core/reporting/compliance_mapper.py` | ComplianceMapper | 27 | - |
| `core/reporting/contextual_scorer.py` | ContextualScorer | 8 | - |
| `core/reporting/coverage_report.py` | CoverageReport | 1 | - |
| `core/reporting/fp_filter.py` | FalsePositiveFilter | 45 | - |
| `core/reporting/llm_validator.py` | LLMFindingValidator | 56 | - |
| `core/reporting/metrics.py` | MetricsTracker | 6 | - |
| `core/reporting/mitre.py` | TechniqueMapping, MitreMapper | 12 | - |
| `core/reporting/quality_gate.py` | QualityGate | 6 | - |
| `core/reporting/remediation_engine.py` | RemediationEngine | 35 | - |
| `core/reporting/report_builder.py` | CustomReportBuilder | 48 | - |
| `core/reporting/reporting.py` | EncryptedTrendStore, ExecutiveSummaryGenerator, EnterpriseReporter | 98 | - |
| `core/reporting/reporting_engine.py` | ReportingEngine | 6 | - |
| `core/reporting/repro_bundle.py` |  | 25 | - |
| `core/reporting/retest_engine.py` | RetestEngine | 78 | - |
| `core/reporting/review_queue.py` | ReviewQueue | 9 | - |
| `core/reporting/risk_prioritizer.py` | RiskPrioritizer | 31 | - |
| `core/reporting/sarif_export.py` | SARIFExporter | 49 | - |
| `core/reporting/scan_chatbot.py` |  | 29 | - |
| `core/reporting/scan_diff.py` |  | 14 | - |
| `core/reporting/significance_filter.py` | SignificanceFilter | 1 | - |
| `core/reporting/trend_analyzer.py` | TrendAnalyzer | 15 | - |
| `core/reporting/vuln_graph.py` | VulnNode, AttackEdge, AttackPath +1 | 11 | - |
| `core/reporting/websocket_pusher.py` | RealtimeStreamServer | 12 | - |

### scheduling (3 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/scheduling/__init__.py` |  | 0 | - |
| `core/scheduling/duplicate_detector.py` | DuplicateDetector | 0 | - |
| `core/scheduling/experiment_scheduler.py` | ExperimentScheduler | 0 | - |

### scope (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/scope/__init__.py` |  | 0 | - |
| `core/scope/manager.py` | ScopeManager | 1 | - |

### scoring (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/scoring/__init__.py` |  | 0 | - |
| `core/scoring/confidence_scorer.py` | EvidenceType, ConfidenceLevel, ResponseSample +2 | 6 | - |

### script (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `scripts/inventory_generator.py` | RiskPrimitive, ClassInfo, ComponentInfo +1 | 19 | - |
| `scripts/set_execution_mode.py` |  | 2 | - |

### security (27 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/security/__init__.py` |  | 1 | - |
| `core/security/action_gate.py` | GateDecision, ActionGate | 4 | - |
| `core/security/anon_gate.py` | AnonGateFailed | 12 | - |
| `core/security/audit_logger.py` | AuditLogger | 29 | - |
| `core/security/authorization.py` | TargetScopeValidator, AuthContext | 5 | - |
| `core/security/authorization_service.py` | AuthorizationPolicy, AuthorizationService | 2 | - |
| `core/security/capability_registry.py` | CapabilityDefinition, ExecutorRegistry | 2 | - |
| `core/security/compliance_gate.py` | ComplianceCheckResult, ScopeValidator, ComplianceAuditLogger +1 | 0 | - |
| `core/security/consent.py` | ExploitConsentManager | 19 | - |
| `core/security/docker_socket_guard.py` | SocketGuardResult | 1 | - |
| `core/security/egress_firewall.py` | EgressBlocked | 5 | - |
| `core/security/encryption.py` | EncryptionKeyMissingError | 6 | - |
| `core/security/execution_auditor.py` | ExecutionAuditor | 17 | - |
| `core/security/fail_open_audit.py` | AuditSeverity, AuditFinding, AuditReport | 1 | - |
| `core/security/legal_validator.py` | ScopeViolationException, LegalValidator | 9 | - |
| `core/security/llm_redact.py` |  | 9 | - |
| `core/security/mutation_ledger.py` | Mutation, MutationLedger | 9 | - |
| `core/security/platform_contract.py` | ContractViolation, ContractNotEnforced, DataClassification +15 | 12 | `tests/test_p1_2_platform_contract.py` |
| `core/security/policy_engine.py` | PolicyAction, DenyReason, PolicyDecision +2 | 7 | `tests/test_p0_1_policy_engine.py` |
| `core/security/policy_validator.py` | PolicyValidator, ScopeValidator, CommandPolicyValidator | 0 | - |
| `core/security/resource_limiter.py` | ScanTimeoutError, ResourceViolationError, ResourceLimiter | 3 | - |
| `core/security/scope_facade.py` | ScopeAuthority | 1 | - |
| `core/security/secret_manager.py` | SecretManager | 11 | - |
| `core/security/secret_vault.py` | SecretCategory, VaultEntry, SecretVault | 23 | - |
| `core/security/security_context.py` | SecurityContext | 3 | - |
| `core/security/session_context.py` | RequestIdentity | 12 | - |
| `core/security/tool_validator.py` | ToolCapability, RiskLevel, AuthoredToolDefinition +2 | 0 | - |

### skills (1 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/skills/__init__.py` | Skill, SkillLoader | 12 | - |

### state_store (23 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/knowledge/__init__.py` |  | 0 | - |
| `core/knowledge/attack_surface_graph.py` | Endpoint, LiveService, Subdomain +1 | 2 | - |
| `core/knowledge/freshness.py` | FreshnessEntry, KnowledgeFreshness | 2 | - |
| `core/knowledge/knowledge_graph.py` | KnowledgeGraph | 9 | - |
| `core/knowledge/persistent_store.py` | KnowledgeStore | 1 | - |
| `core/knowledge/state_summary.py` | NormalizedState | 2 | - |
| `core/memory/__init__.py` |  | 1 | - |
| `core/memory/context.py` | ExecutionContext | 0 | - |
| `core/memory/context_resolver.py` | ContextResolver | 4 | - |
| `core/memory/database.py` | DatabaseManager, MemoryDatabase | 16 | - |
| `core/memory/dedup_tracker.py` | DeduplicationTracker, TaskRecord, DedupTracker | 8 | - |
| `core/memory/experience_store.py` | ExperienceStore | 15 | - |
| `core/memory/failure_store.py` | FailureStore | 10 | - |
| `core/memory/knowledge_base.py` | KnowledgeBase | 31 | - |
| `core/memory/memory_retriever.py` | MemoryRetriever | 1 | - |
| `core/memory/pentest_memory.py` | SimpleVectorStore, PentestMemoryEngine | 10 | - |
| `core/memory/persistence.py` | PersistenceMechanism, PersistenceManager | 1 | - |
| `core/memory/relationship_db.py` | RelationshipDB | 5 | - |
| `core/memory/retention_policy.py` | RetentionPolicy | 19 | - |
| `core/memory/shared_context.py` | SharedContextV2 | 56 | - |
| `core/memory/stores.py` | EvidenceStore, KnowledgeStore, FindingStore | 7 | - |
| `core/memory/strategy_store.py` | StrategyStore | 15 | - |
| `core/memory/tool_learning.py` | ToolScore, ToolLearningEngine | 2 | - |

### tool (31 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/tools/__init__.py` |  | 1 | - |
| `core/tools/adapters/base.py` | BaseAdapter | 0 | - |
| `core/tools/adapters/masscan.py` | MasscanAdapter | 2 | - |
| `core/tools/adapters/nmap.py` | NmapAdapter | 10 | - |
| `core/tools/capability_mapper.py` | CapabilityMapper | 1 | - |
| `core/tools/http_ops.py` | _LinkExtractor | 21 | - |
| `core/tools/http_ops_tools.py` | _HttpFetchTool, _ExtractLinksTool, _ExtractApiRoutesTool +6 | 10 | - |
| `core/tools/models.py` | ExecutionStatus, ToolAttempt, ExecutionResult | 0 | - |
| `core/tools/nuclei_runner.py` | NucleiRunner | 20 | - |
| `core/tools/nuclei_template_gen.py` | NucleiTemplateGenerator | 33 | - |
| `core/tools/rate_limiter.py` | TargetState, AdaptiveRateLimiter | 0 | - |
| `core/tools/result_cache.py` | CachedResult, ResultCache | 1 | - |
| `core/tools/smart_wordlists.py` | SmartWordlistManager | 3 | - |
| `core/tools/timeout_classes.py` | TimeoutScope | 2 | - |
| `core/tools/tool_adapter.py` | ToolInvocation, NmapAdapter, SubfinderAdapter +16 | 66 | - |
| `core/tools/tool_cache.py` | ToolResultCache | 2 | - |
| `core/tools/tool_definitions.py` | ToolType, OperationType, ToolDefinition +1 | 3 | - |
| `core/tools/tool_effectiveness.py` | ToolEffectivenessEngine | 10 | - |
| `core/tools/tool_executor.py` | ToolExecutor | 0 | - |
| `core/tools/tool_gateway.py` | ToolGateway | 16 | - |
| `core/tools/tool_health.py` | HealthState, ToolHealth, ToolHealthManager | 12 | - |
| `core/tools/tool_installer.py` | ToolInstaller | 12 | - |
| `core/tools/tool_intelligence.py` | TargetContext, ToolProfile | 2 | - |
| `core/tools/tool_invocation_engine.py` | InvocationSource, ToolInvocationContext, ToolInvocationEngine | 2 | - |
| `core/tools/tool_knowledge_store.py` | ToolKnowledgeStore | 5 | - |
| `core/tools/tool_portfolio.py` | ToolPortfolio | 1 | - |
| `core/tools/tool_ranking.py` | ToolRankingEngine | 0 | - |
| `core/tools/tool_registry.py` | ToolResult, Tool, KaliTool +6 | 32 | `tests/test_tool_registry.py` |
| `core/tools/tool_router.py` | ToolRouter, EffectivenessDB | 33 | - |
| `core/tools/tool_use_executor.py` | ToolUseExecutor | 1 | - |
| `core/tools/tool_validation.py` | ToolInvocationValidator | 7 | - |

### ui (2 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `ui/api/routers/__init__.py` |  | 0 | - |
| `ui/api/server.py` | TargetCreate, ScanRequest, ScanChatMessage +10 | 405 | - |

### utility (3 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/utils/__init__.py` |  | 0 | - |
| `core/utils/sanitize.py` |  | 1 | - |
| `core/utils/scan_flags.py` |  | 3 | - |

### validation (6 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/validation/__init__.py` |  | 0 | - |
| `core/validation/confidence.py` | ConfidenceVerdict, ConfidenceCalibrator | 25 | - |
| `core/validation/contract_validator.py` | ContractValidator | 0 | - |
| `core/validation/dedup.py` | DedupResult, DedupStore | 33 | - |
| `core/validation/reachability.py` | ReachabilityResult, _PyCallGraph, ReachabilityAnalyzer | 4 | - |
| `core/validation/tool_argument_validator.py` | ToolArgumentValidationError, ToolArgumentValidator | 0 | - |

### verification (4 modules)

| Module | Classes | Risk Primitives | Test |
|--------|---------|-----------------|------|
| `core/verification/__init__.py` |  | 0 | - |
| `core/verification/critic_agent.py` | Verdict, CriticVerdict, CriticAgent | 54 | - |
| `core/verification/finding_confirmation_gate.py` | ConfirmationStage, EvidenceType, EvidenceRequirement +4 | 15 | - |
| `core/verification/reproduction_gate.py` | ReproStatus, ReproductionRequest, ReproductionResult +1 | 13 | - |

## Unowned High-Risk Paths (no test coverage)

- `agents/authorization.py:32 (filesystem_write: mkdir())`
- `agents/authorization.py:57 (network_io: get())`
- `agents/authorization.py:58 (network_io: get())`
- `agents/authorization.py:183 (network_io: get())`
- `agents/authorization.py:192 (filesystem_write: open())`
- `agents/authorization.py:208 (filesystem_write: open())`
- `agents/authorization.py:42 (filesystem_write: open())`
- `agents/authorization.py:53 (network_io: get())`
- `agents/authorization.py:162 (process_exec: run())`
- `agents/authorization.py:186 (network_io: get())`
- `agents/authorization.py:94 (credential_access: getenv())`
- `agents/authorization.py:44 (network_io: get())`
- `agents/exploit_agent.py:476 (network_io: get())`
- `agents/exploit_agent.py:488 (network_io: get())`
- `agents/exploit_agent.py:779 (filesystem_write: makedirs())`
- `agents/exploit_agent.py:783 (network_io: get())`
- `agents/exploit_agent.py:784 (network_io: get())`
- `agents/exploit_agent.py:863 (network_io: get())`
- `agents/exploit_agent.py:867 (network_io: get())`
- `agents/exploit_agent.py:868 (network_io: get())`
- `agents/exploit_agent.py:869 (network_io: get())`
- `agents/exploit_agent.py:870 (network_io: get())`
- `agents/exploit_agent.py:871 (network_io: get())`
- `agents/exploit_agent.py:873 (network_io: get())`
- `agents/exploit_agent.py:874 (network_io: get())`
- `agents/exploit_agent.py:994 (network_io: get())`
- `agents/exploit_agent.py:996 (network_io: get())`
- `agents/exploit_agent.py:1003 (network_io: get())`
- `agents/exploit_agent.py:1004 (network_io: get())`
- `agents/exploit_agent.py:1037 (network_io: get())`
- `agents/exploit_agent.py:1038 (network_io: get())`
- `agents/exploit_agent.py:1040 (network_io: get())`
- `agents/exploit_agent.py:1143 (network_io: get())`
- `agents/exploit_agent.py:1171 (network_io: get())`
- `agents/exploit_agent.py:1223 (network_io: get())`
- `agents/exploit_agent.py:1226 (network_io: get())`
- `agents/exploit_agent.py:1240 (network_io: get())`
- `agents/exploit_agent.py:1241 (network_io: get())`
- `agents/exploit_agent.py:1291 (network_io: get())`
- `agents/exploit_agent.py:511 (network_io: get())`
- `agents/exploit_agent.py:627 (network_io: get())`
- `agents/exploit_agent.py:628 (network_io: get())`
- `agents/exploit_agent.py:877 (network_io: get())`
- `agents/exploit_agent.py:894 (network_io: get())`
- `agents/exploit_agent.py:1044 (network_io: get())`
- `agents/exploit_agent.py:1174 (process_exec: run())`
- `agents/exploit_agent.py:1227 (network_io: get())`
- `agents/exploit_agent.py:1227 (network_io: get())`
- `agents/exploit_agent.py:1252 (network_io: get())`
- `agents/exploit_agent.py:1253 (network_io: get())`
- ... and 5813 more

## Call Graph

Total edges: 25211  
Full graph available in `architecture_inventory.json`.

---
*Auto-generated by `scripts/inventory_generator.py`. Regenerate in CI.*