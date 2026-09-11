
import argparse
import asyncio
import json
import logging
import sys, os
from pathlib import Path

# ── Observability bootstrap ─────────────────────────────────────────────
# Configure structured JSON logging + PII redaction BEFORE any other logger
# instantiates. Inherit trace context from the parent API process via the
# `TRACEPARENT` env var so scan spans link back to the launching HTTP request.
try:
    from core.observability import logging as _ag_logging
    _ag_logging.configure_root(level=os.environ.get("LOG_LEVEL", "INFO"))
    from core.observability import tracing as _tracing
    _tracing.context_from_env(dict(os.environ))
except Exception as _obs_err:
    # Observability must never block a scan; fall back to stdlib logging.
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger(__name__).warning("Observability bootstrap skipped: %s", _obs_err)


# Force UTF-8 encoding for standard streams on Windows to prevent UnicodeEncodeErrors
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

# Ensure standard storage directories exist. reports/ is opt-in via
# REPORTS_ENABLED — see core/common/reports_config.py.
_standard_dirs = ["data/db", "loot", ".audit_logs"]
if os.getenv("REPORTS_ENABLED", "0").lower() in ("1", "true", "yes", "on"):
    _standard_dirs.append(os.getenv("REPORTS_DIR", "reports"))
for _dir in _standard_dirs:
    os.makedirs(_dir, exist_ok=True)

from core.common.config import load_config
from core.common.startup_diagnostics import log_startup_diagnostics
from core.orchestration.central_brain import CentralBrain
from core.orchestration.meta_brain import MetaBrain

try:
    from core.security.egress_firewall import install_httpx_guard
    install_httpx_guard()
except Exception as _e:
    logging.getLogger(__name__).warning(f"SECURITY: egress guard install failed: {_e}")


_LOG_FMT = '[%(asctime)s] %(name)s - %(levelname)s - %(message)s'


class _AnsiResetFormatter(logging.Formatter):

    def format(self, record):
        s = super().format(record)
        return s + "\x1b[0m"


_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(_AnsiResetFormatter(_LOG_FMT))

_file = logging.FileHandler("pentest.log", encoding="utf-8")
_file.setFormatter(logging.Formatter(_LOG_FMT))

logging.basicConfig(level=logging.INFO, handlers=[_console, _file])
logger = logging.getLogger(__name__)

async def run_single(target: str, auth_file: str | None = None, tier: str = "POC",
                     resume: bool = False, phases: list | None = None, credentials: dict | None = None,
                     scan_id: str | None = None):
    auth_document = ""
    if auth_file:
        auth_path = Path(auth_file)
        if auth_path.exists():
            auth_document = auth_path.read_text(encoding="utf-8")
        else:
            logger.error(f"Auth file not found: {auth_path}")
            sys.exit(1)

    scope = {"domains": [target], "max_tier": tier}
    if scan_id is not None:
        brain = CentralBrain(target=target, scope=scope, scan_id=scan_id)
    else:
        brain = CentralBrain(target=target, scope=scope)

    if credentials:
        cred_list = credentials if isinstance(credentials, list) else [credentials]
        # Feed the multi-role auth manager: one live session per role.
        brain.ctx.auth_credentials = [c for c in cred_list if isinstance(c, dict) and c.get("username")]
        for cred in cred_list:
            if cred.get("username"):
                brain.ctx.harvested_creds.append(cred)
                logger.info(f"Injected credentials: role={cred.get('role', 'default')}, user={cred['username']}, login_url={cred.get('login_url', 'N/A')}")
        if brain.ctx.auth_credentials:
            logger.info(f"Total credential sets loaded: {len(brain.ctx.auth_credentials)} "
                        f"(roles: {', '.join(c.get('role','?') for c in brain.ctx.auth_credentials)})")

    # Phase 4.4: merge mobile-app-derived backend endpoints into the scan scope.
    _mobile_eps = os.getenv("ANTIGRAVITY_MOBILE_ENDPOINTS", "")
    if _mobile_eps:
        try:
            from core.discovery.mobile_analyzer import inject_endpoints_into_context
            n = inject_endpoints_into_context(brain.ctx, json.loads(_mobile_eps), "mobile_apk")
            logger.info("Injected %d mobile-derived endpoint(s) into scan scope "
                        "(out-of-scope hosts still blocked at request time).", n)
        except Exception as e:
            logger.warning("Mobile endpoint injection failed: %s", e)

    if resume:
        cp_path = brain.checkpointer.get_latest_checkpoint(target)
        if cp_path:
            state = brain.checkpointer.load_checkpoint(cp_path)
            if state:
                brain.checkpointer.apply_checkpoint(brain, state)
                logger.info(f"RESUMED from checkpoint: {cp_path}")
                logger.info(f"Resuming at phase: {brain.current_phase.value if brain.current_phase else 'COMPLETE'}")
            else:
                logger.warning("Checkpoint file corrupt, starting fresh")
        else:
            logger.warning("No checkpoint found for this target, starting fresh")

    try:
        await brain.run_main_loop(auth_document=auth_document, phases=phases if phases is not None else [])
    finally:
        try:
            if hasattr(brain, "_persist_vulnerabilities"):
                await brain._persist_vulnerabilities()
        except Exception as e:
            logger.error(f"Final vulnerability flush failed: {e}")

    # Phase 4.5: correlate grey-box SAST findings with the scan's DAST findings.
    _sast = os.getenv("ANTIGRAVITY_SAST_FINDINGS", "")
    if _sast:
        try:
            from core.analysis.sast_bridge import correlate_and_persist
            sid = scan_id or getattr(brain, "_scan_id", None) or target
            dast = list(getattr(brain.ctx, "vulnerabilities", []) or [])
            summary = correlate_and_persist(sid, json.loads(_sast), dast)
            logger.info("SAST↔DAST correlation: %d confirmed, %d SAST-only, %d DAST-only",
                        summary["counts"]["confirmed"], summary["counts"]["sast_only"],
                        summary["counts"]["dast_only"])
        except Exception as e:
            logger.warning("SAST/DAST correlation failed: %s", e)


async def run_multi(targets: list, auth_file: str | None = None):
    auth_document = ""
    if auth_file:
        auth_path = Path(auth_file)
        if auth_path.exists():
            auth_document = auth_path.read_text(encoding="utf-8")

    meta = MetaBrain(targets, auth_document=auth_document)
    await meta.run_all()


def _analyze_mobile_apps(args) -> list:
    """Phase 4.4: analyze an APK/IPA (if supplied) and return discovered backend
    endpoint dicts. Guarded — never fails the run if analysis tools are absent."""
    endpoints = []
    apk = getattr(args, "mobile_app", "") or ""
    ipa = getattr(args, "ipa_app", "") or ""
    try:
        if apk:
            from core.discovery.mobile_analyzer import MobileAnalyzer
            analysis = MobileAnalyzer().analyze(apk)
            endpoints += analysis.to_endpoints()
            logger.info("APK %s: %d endpoints, %d secrets, %d deeplinks (cert_pinning=%s)",
                        apk, len(analysis.endpoints), len(analysis.secrets),
                        len(analysis.deeplinks), analysis.cert_pinning)
        if ipa:
            from core.discovery.ipa_analyzer import IPAAnalyzer
            analysis = IPAAnalyzer().analyze(ipa)
            endpoints += analysis.to_endpoints()
            logger.info("IPA %s: %d endpoints, %d secrets, %d deeplinks",
                        ipa, len(analysis.endpoints), len(analysis.secrets),
                        len(analysis.deeplinks))
    except Exception as e:
        logger.warning("Mobile app analysis failed: %s", e)
    return endpoints


def _run_sast(args) -> list:
    """Phase 4.5: run grey-box SAST if --source-repo/--source-path given. Guarded
    — returns [] and never fails the run when Semgrep/git are unavailable."""
    repo = getattr(args, "source_repo", "") or ""
    path = getattr(args, "source_path", "") or ""
    if not (repo or path):
        return []
    try:
        from core.analysis.sast_bridge import SastBridge
        return SastBridge().analyze(source_path=path, source_repo=repo)
    except Exception as e:
        logger.warning("Grey-box SAST failed: %s", e)
        return []


def main():
    try:
        from core.security.anon_gate import enforce_or_die
        enforce_or_die()
    except SystemExit:
        raise
    except Exception as _e:
        # Missing httpx / etc. — soft-warn, do NOT silently proceed.
        print(f"[AnonGate] skipped (import error): {_e}")

    parser = argparse.ArgumentParser(
        description="Autonomous Pentesting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target example.com
  python main.py --target example.com --auth auth.txt --tier SHALLOW
  python main.py --targets example.com,app2.io,api.com
  python main.py --targets-file targets.txt --tier POC
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Single target domain or URL")
    group.add_argument("--targets", help="Comma-separated list of targets")
    group.add_argument("--targets-file", help="File with one target per line")
    parser.add_argument("--auth", default=None, help="Authorization document")
    parser.add_argument("--tier", default="POC",
                         choices=["POC", "SHALLOW", "DEEP"],
                         help="Max exploitation tier (default: POC)")
    parser.add_argument("--skip-osint", action="store_true",
                         help="Skip OSINT reconnaissance phase")
    parser.add_argument("--reset-dedup", action="store_true",
                         help="Reset deduplication database before starting pentest")
    parser.add_argument("--auto-approve", "-y", action="store_true",
                         help="Auto-approve active exploit attempts without interactive consent prompts")
    parser.add_argument("--resume", action="store_true",
                         help="Resume a previously stopped scan from its last checkpoint")
    parser.add_argument("--phases", default="",
                         help="Comma-separated phases to run (RECON,ACTIVE_SCANNING,EXPLOITATION,REPORTING). Default: all")
    parser.add_argument("--credentials", default="",
                         help='DEPRECATED — leaks via /proc/<pid>/cmdline. Use --credentials-file instead.')
    parser.add_argument("--credentials-file", default="",
                         help='Path to a temporary JSON file containing login creds. '
                              'File is unlinked after read. Recommended over --credentials.')
    parser.add_argument("--scan-id", default=None,
                         help="Canonical run id (from the UI); every DB row for this run uses it so runs never merge")
    parser.add_argument("--frameworks", default="",
                         help="Comma-separated compliance frameworks to map findings "
                              "to (choices: pci,soc2,hipaa,cis,nist). "
                              "Default: all. Example: --frameworks pci,soc2,hipaa")
    parser.add_argument("--campaign", action="store_true",
                         help="Use campaign mode for multi-target: parallel scanning with shared reporting")
    parser.add_argument("--max-parallel", type=int, default=3,
                         help="Max parallel targets in campaign mode (default: 3)")
    parser.add_argument("--schedule", type=int, default=0,
                         help="Schedule recurring scans every N hours (0 = disabled)")
    parser.add_argument("--sarif", action="store_true",
                         help="Also export findings in SARIF format to reports/findings.sarif")
    parser.add_argument("--mobile-app", default="",
                         help="Path to an Android .apk to analyze; discovered backend "
                              "endpoints are fed into the scan (Phase 4.4)")
    parser.add_argument("--ipa-app", default="",
                         help="Path to an iOS .ipa to analyze for backend endpoints (Phase 4.4)")
    parser.add_argument("--source-repo", default="",
                         help="Grey-box: git URL of the target's source to run SAST on (Phase 4.5)")
    parser.add_argument("--source-path", default="",
                         help="Grey-box: local path to the target's source for SAST (Phase 4.5)")
    parser.add_argument("--incremental", action="store_true",
                         help="Incremental scan: diff against the saved attack-surface "
                              "baseline and test only new/changed endpoints (Phase 6.2)")
    args = parser.parse_args()

    if args.incremental:
        os.environ["ANTIGRAVITY_INCREMENTAL"] = "1"
        logger.info("Incremental scanning enabled — will diff against the saved baseline.")

    # Phase 4.4: mobile app backend analysis — enrich scope with discovered endpoints.
    mobile_endpoints = _analyze_mobile_apps(args)
    if mobile_endpoints:
        os.environ["ANTIGRAVITY_MOBILE_ENDPOINTS"] = json.dumps([e["url"] for e in mobile_endpoints])
        logger.info("Mobile analysis surfaced %d backend endpoint(s) for the scan.",
                    len(mobile_endpoints))

    # Phase 4.5: grey-box SAST — findings correlated with DAST later in reporting.
    sast_findings = _run_sast(args)
    if sast_findings:
        os.environ["ANTIGRAVITY_SAST_FINDINGS"] = json.dumps(sast_findings)
        logger.info("SAST surfaced %d source finding(s) for SAST/DAST correlation.",
                    len(sast_findings))

    if args.auto_approve:
        os.environ["AUTO_APPROVE_EXPLOITS"] = "true"
        from core.security.consent import get_consent
        get_consent().set_auto_approve(True)
        logger.info("Auto-approve exploits enabled via CLI.")

    if args.skip_osint:
        os.environ["ENABLE_OSINT"] = "false"
        logger.info("OSINT disabled via --skip-osint flag.")

    # Load .env config
    config = load_config()

    # Override tier in config
    config.config["MAX_EXPLOITATION_TIER"] = args.tier

    # Active compliance frameworks (validated against the compliance module)
    from core.compliance import available_frameworks
    if args.frameworks.strip():
        requested = [f.strip().lower() for f in args.frameworks.split(",") if f.strip()]
        valid = [f for f in requested if f in available_frameworks()]
        invalid = [f for f in requested if f not in available_frameworks()]
        if invalid:
            logger.warning(f"Ignoring unknown frameworks: {invalid} "
                           f"(valid: {available_frameworks()})")
        config.config["COMPLIANCE_FRAMEWORKS"] = valid or available_frameworks()
    else:
        config.config["COMPLIANCE_FRAMEWORKS"] = available_frameworks()
    logger.info(f"Compliance frameworks: {config.config['COMPLIANCE_FRAMEWORKS']}")

    if args.reset_dedup:
        from core.memory.dedup_tracker import DeduplicationTracker
        DeduplicationTracker().reset_all()

    log_startup_diagnostics()
    logger.info("=" * 60)
    logger.info("AUTONOMOUS PENTESTING AGENT v2.0")
    logger.info("=" * 60)

    if args.target:
        # Single target
        logger.info(f"Mode: Single target")
        logger.info(f"Target: {args.target}")
        logger.info(f"Tier: {args.tier}")
        logger.info("=" * 60)
        phases_list = [p.strip().upper() for p in args.phases.split(",") if p.strip()] if args.phases else None
        creds = None
        creds_file_arg = getattr(args, "credentials_file", "")
        if creds_file_arg:
            import json as _json
            from pathlib import Path as _Path
            _p = _Path(creds_file_arg)
            try:
                creds = _json.loads(_p.read_text(encoding="utf-8"))
            except (_json.JSONDecodeError, OSError) as e:
                logger.error(f"Invalid --credentials-file: {e}")
                sys.exit(1)
            finally:
                # Always unlink — the file is expected to be short-lived.
                try:
                    _p.unlink(missing_ok=True)
                except Exception:
                    pass
        elif args.credentials:
            # Legacy path — logged as a warning so operators migrate away.
            logger.warning("--credentials passed via argv (deprecated: leaks via /proc). "
                           "Migrate to --credentials-file.")
            import json as _json
            try:
                creds = _json.loads(args.credentials)
            except _json.JSONDecodeError:
                logger.error(f"Invalid --credentials JSON: {args.credentials[:100]}")
                sys.exit(1)
        asyncio.run(run_single(args.target, args.auth, args.tier, resume=args.resume, phases=phases_list, credentials=creds, scan_id=args.scan_id))

        if args.schedule and args.schedule > 0:
            from core.orchestration.scheduler import get_scheduler
            scheduler = get_scheduler()
            scheduler.add_schedule(args.target, interval_hours=args.schedule, tier=args.tier,
                                   phases=phases_list)
            logger.info(f"Scheduled recurring scan every {args.schedule}h for {args.target}")
            scheduler.start()
            try:
                while True:
                    import time
                    time.sleep(3600)
            except KeyboardInterrupt:
                scheduler.stop()
                logger.info("Scheduler stopped")

    elif args.targets:
        # Multi-target from CLI
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        logger.info(f"Mode: Multi-target ({len(targets)} targets)")
        for t in targets:
            logger.info(f"  - {t}")
        logger.info(f"Tier: {args.tier}")
        logger.info("=" * 60)
        if args.campaign:
            from core.orchestration.campaign import CampaignManager
            campaign = CampaignManager(targets, tier=args.tier, max_parallel=args.max_parallel,
                                        auth_file=args.auth)
            asyncio.run(campaign.run())
        else:
            asyncio.run(run_multi(targets, args.auth))

    elif args.targets_file:
        # Multi-target from file
        path = Path(args.targets_file)
        if not path.exists():
            logger.error(f"Targets file not found: {path}")
            sys.exit(1)
        targets = [
            line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        logger.info(f"Mode: Multi-target ({len(targets)} from {path})")
        logger.info(f"Tier: {args.tier}")
        logger.info("=" * 60)
        if args.campaign:
            from core.orchestration.campaign import CampaignManager
            campaign = CampaignManager(targets, tier=args.tier, max_parallel=args.max_parallel,
                                        auth_file=args.auth)
            asyncio.run(campaign.run())
        else:
            asyncio.run(run_multi(targets, args.auth))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Clean stop on Ctrl+C — asyncio unwinds in-flight tasks with
        # CancelledError; that's expected shutdown, not a crash.
        logger.info("Scan interrupted by user (Ctrl+C) — shutting down.")
        sys.exit(130)
