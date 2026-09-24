"""Infrastructure red-team agents → attack-planner bridge (spec §12/§17/§19/§20).

Runs the Kubernetes, cloud (AWS/Azure/GCP) and dependency/container SCA agents
from operator-provided inputs and returns their findings + attack paths in the
shape the orchestrator merges into the scan context. Findings enter
``ctx.vulnerabilities`` before the exploitation-phase attack-path correlation, so
the planner reasons over them like any other finding.

Each agent is bound to an Engagement built from the live scan scope plus the
exact resource ids the operator authorized (cluster / cloud account / SCA
target), so the deterministic fail-closed gate still governs every agent — the
AI never widens scope. Every input is opt-in; nothing runs without config.

Config keys (read from the settings facade):
  INFRA_AGENTS_ENABLED           master switch (default off)
  K8S_SNAPSHOT_FILE / K8S_KUBECONFIG [+ K8S_CONTEXT] , K8S_CLUSTER_ID
  CLOUD_PROVIDER (aws|azure|gcp), CLOUD_SNAPSHOT_FILE | CLOUD_PRIVESC_LIVE,
    CLOUD_ACCOUNT_ID
  SCA_FILES (comma-separated manifest/Dockerfile paths), SCA_TARGET,
    SCA_ADVISORIES_FILE (JSON list) | SCA_USE_OSV
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _read_json(path: str) -> Optional[Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("[infra] could not read JSON %s: %s", path, e)
        return None


def _build_engagement(scope: Dict[str, Any], *, cluster_id: str = "",
                      account_id: str = "", sca_target: str = "",
                      default_target: str = ""):
    """Engagement authorizing exactly the resources under analysis (fail-closed
    for anything else). Reuses the scan's domain scope."""
    from core.domain.engagement import Engagement, EngagementStatus
    domains = []
    if isinstance(scope, dict):
        domains = scope.get("domains") or scope.get("authorized_targets") or []
    authorized_targets = [t for t in (sca_target, default_target) if t]
    return Engagement(
        name=f"scan:{default_target or 'engagement'}",
        status=EngagementStatus.ACTIVE,
        allowed_domains=list(domains),
        allowed_kubernetes_clusters=[cluster_id] if cluster_id else [],
        allowed_cloud_accounts=[account_id] if account_id else [],
        authorized_targets=authorized_targets,
    )


def _run_kubernetes(cfg, scope, default_target) -> Dict[str, List]:
    snap_file = cfg.get("K8S_SNAPSHOT_FILE") or None
    kubeconfig = cfg.get("K8S_KUBECONFIG") or None
    if not snap_file and not kubeconfig:
        return {}
    cluster_id = cfg.get("K8S_CLUSTER_ID") or "cluster"
    eng = _build_engagement(scope, cluster_id=cluster_id, default_target=default_target)
    from core.kubernetes import KubernetesAgent
    if snap_file:
        snap = _read_json(snap_file)
        if not isinstance(snap, dict):
            return {}
        agent = KubernetesAgent.from_snapshot(snap, cluster_id=cluster_id, engagement=eng)
    else:
        agent = KubernetesAgent.from_kubeconfig(
            kubeconfig=kubeconfig, context=cfg.get("K8S_CONTEXT") or None,
            cluster_id=cluster_id, engagement=eng)
    res = agent.run()
    logger.info("[infra] kubernetes: %d findings, %d paths",
                len(res.get("findings", [])), len(res.get("attack_paths", [])))
    return res


def _run_cloud(cfg, scope, default_target) -> Dict[str, List]:
    provider = (cfg.get("CLOUD_PROVIDER") or "").strip().lower()
    if not provider:
        return {}
    snap_file = cfg.get("CLOUD_SNAPSHOT_FILE") or None
    live = cfg.get_bool("CLOUD_PRIVESC_LIVE", False)
    if not snap_file and not live:
        return {}
    account_id = cfg.get("CLOUD_ACCOUNT_ID") or "account"
    eng = _build_engagement(scope, account_id=account_id, default_target=default_target)
    from core.cloud import CloudAgent
    from core.cloud.providers import PROVIDERS
    if provider not in PROVIDERS:
        logger.warning("[infra] unknown CLOUD_PROVIDER %r", provider)
        return {}
    if snap_file:
        snap = _read_json(snap_file)
        if not isinstance(snap, dict):
            return {}
        agent = CloudAgent.from_snapshot(provider, snap, account_id=account_id, engagement=eng)
    else:
        # Live source (AWS boto3 today; azure/gcp are integration points).
        if provider == "aws":
            from core.cloud.providers.aws import Boto3Source
            source = Boto3Source(region=cfg.get("AWS_REGION") or "us-east-1")
        else:
            logger.info("[infra] live %s discovery not wired; provide CLOUD_SNAPSHOT_FILE", provider)
            return {}
        agent = CloudAgent(provider, source, account_id=account_id, engagement=eng)
    res = agent.run()
    logger.info("[infra] cloud/%s: %d findings, %d paths", provider,
                len(res.get("findings", [])), len(res.get("attack_paths", [])))
    return res


def _run_sca(cfg, scope, default_target) -> Dict[str, List]:
    raw = cfg.get("SCA_FILES") or ""
    paths = [p.strip() for p in raw.split(",") if p.strip()]
    if not paths:
        return {}
    files: Dict[str, str] = {}
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                files[p] = f.read()
        except Exception as e:
            logger.warning("[infra] SCA could not read %s: %s", p, e)
    if not files:
        return {}
    sca_target = cfg.get("SCA_TARGET") or default_target or "artifact"
    eng = _build_engagement(scope, sca_target=sca_target, default_target=default_target)

    from core.sca import ScaAgent
    from core.sca.advisories import StaticAdvisorySource, OsvSource
    adv_file = cfg.get("SCA_ADVISORIES_FILE") or None
    if adv_file:
        advs = _read_json(adv_file) or []
        source = StaticAdvisorySource(advs if isinstance(advs, list) else [])
    elif cfg.get_bool("SCA_USE_OSV", False):
        source = OsvSource()
    else:
        source = StaticAdvisorySource([])
    res = ScaAgent(files, advisory_source=source, target=sca_target, engagement=eng).run()
    logger.info("[infra] sca: %d findings, %d paths",
                len(res.get("findings", [])), len(res.get("attack_paths", [])))
    return res


def collect_infra_findings(cfg, scope: Dict[str, Any],
                           default_target: str = "") -> Dict[str, Any]:
    """Run whichever infra agents are configured; merge findings + attack paths.

    Returns {"findings": [...], "attack_paths": [...], "ran": [...]}. Never
    raises — each agent is isolated so one failure cannot abort the others.
    """
    findings: List[Dict[str, Any]] = []
    paths: List[Dict[str, Any]] = []
    ran: List[str] = []

    for name, fn in (("kubernetes", _run_kubernetes),
                     ("cloud", _run_cloud), ("sca", _run_sca)):
        try:
            res = fn(cfg, scope, default_target)
        except Exception as e:
            logger.warning("[infra] %s agent failed (non-fatal): %s", name, e)
            continue
        if not res:
            continue
        ran.append(name)
        findings.extend(res.get("findings", []) or [])
        paths.extend(res.get("attack_paths", []) or [])

    if ran:
        logger.info("[infra] ran %s → %d findings, %d attack paths",
                    ", ".join(ran), len(findings), len(paths))
    return {"findings": findings, "attack_paths": paths, "ran": ran}
