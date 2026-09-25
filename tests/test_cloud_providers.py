"""Cloud provider adapters — discovery + attack-path synthesis (spec §17)."""
import pytest

from core.cloud import CloudAgent
from core.cloud.providers import PROVIDERS
from core.domain.engagement import Engagement, EngagementStatus


# ── AWS ────────────────────────────────────────────────────────────────
def _aws_snapshot():
    return {
        "identities": [
            {"id": "arn:user/dev", "name": "dev", "type": "user",
             "permissions": ["iam:createpolicyversion", "s3:getobject"],
             "can_assume": ["arn:role/admin"]},
            {"id": "arn:role/admin", "name": "admin", "type": "role",
             "permissions": ["*"], "privileged": True},
            {"id": "arn:user/readonly", "name": "readonly", "type": "user",
             "permissions": ["s3:getobject"], "can_assume": []},
        ],
        "storage": [
            {"id": "public-bucket", "name": "public-bucket",
             "public": True, "encrypted": False},
            {"id": "private-bucket", "name": "private-bucket", "public": False},
        ],
        "databases": [
            {"id": "prod-db", "name": "prod-db", "engine": "postgres",
             "public": True, "encrypted": True},
        ],
        "kubernetes": [{"id": "eks-1", "name": "eks-1"}],
    }


def _run(provider, snapshot, engagement=None, account_id="acct-1"):
    return CloudAgent.from_snapshot(provider, snapshot, account_id=account_id,
                                    engagement=engagement).run()


def test_aws_iam_privesc_path_detected():
    res = _run("aws", _aws_snapshot())
    privesc = [p for p in res["attack_paths"]
               if "IAM privilege escalation" in p["objective"]
               and "dev" in p["starting_position"]]
    assert privesc, [p["objective"] for p in res["attack_paths"]]


def test_aws_assume_role_to_admin_path():
    res = _run("aws", _aws_snapshot())
    assert any(p["objective"] == "Assume a privileged role"
               and "dev" in p["starting_position"]
               and "admin" in p["target"] for p in res["attack_paths"])


def test_aws_public_storage_and_db_exposure():
    res = _run("aws", _aws_snapshot())
    targets = {p["target"] for p in res["attack_paths"]}
    assert "storage:public-bucket" in targets
    assert "database:prod-db" in targets
    # public + unencrypted bucket is CRITICAL
    bucket = next(p for p in res["attack_paths"] if p["target"] == "storage:public-bucket")
    assert bucket["severity"] == "CRITICAL"


def test_aws_readonly_identity_yields_no_privesc():
    res = _run("aws", _aws_snapshot())
    assert not any("readonly" in p["starting_position"]
                   and "privilege escalation" in p["objective"].lower()
                   for p in res["attack_paths"])


def test_aws_eks_surfaced_in_inventory():
    res = _run("aws", _aws_snapshot())
    assert res["inventory"]["kubernetes"] == 1


# ── Azure ──────────────────────────────────────────────────────────────
def test_azure_owner_role_is_critical_tenant_path():
    snap = {"identities": [
        {"id": "sp-1", "name": "ci-sp", "type": "service_principal",
         "permissions": ["Owner"]},
        {"id": "sp-2", "name": "reader-sp", "permissions": ["Reader"]},
    ]}
    res = _run("azure", snap)
    owner = [p for p in res["attack_paths"] if "ci-sp" in p["starting_position"]]
    assert owner and owner[0]["severity"] == "CRITICAL" and owner[0]["target"] == "tenant"
    assert not any("reader-sp" in p["starting_position"] for p in res["attack_paths"])


# ── GCP ────────────────────────────────────────────────────────────────
def test_gcp_owner_and_token_creator_paths():
    snap = {"identities": [
        {"id": "sa-1", "name": "deploy-sa", "type": "service_account",
         "permissions": ["roles/owner"]},
        {"id": "sa-2", "name": "impersonator",
         "permissions": ["roles/iam.serviceaccounttokencreator"]},
    ]}
    res = _run("gcp", snap)
    objs = {p["starting_position"]: p for p in res["attack_paths"]}
    assert objs["identity:deploy-sa"]["severity"] == "CRITICAL"
    assert objs["identity:impersonator"]["objective"] == "Impersonate a service account"


# ── cross-cutting ──────────────────────────────────────────────────────
def test_unknown_provider_rejected():
    with pytest.raises(ValueError):
        CloudAgent.from_snapshot("oracle", {})


def test_all_providers_registered():
    assert set(PROVIDERS) == {"aws", "azure", "gcp"}


def test_confidence_and_status_are_disciplined():
    res = _run("aws", _aws_snapshot())
    for p in res["attack_paths"]:
        assert p["status"] == "hypothesized"
        assert 0.0 < p["exploit_confidence"] <= 0.9


def test_engagement_scope_gate_denies_unauthorized_account():
    eng = Engagement(name="e", status=EngagementStatus.ACTIVE,
                     allowed_cloud_accounts=["other-acct"])
    res = _run("aws", _aws_snapshot(), engagement=eng, account_id="acct-1")
    assert res["attack_paths"] == [] and res["findings"] == []
    assert res["inventory"]["identities"] == 0


def test_engagement_scope_gate_allows_authorized_account():
    eng = Engagement(name="e", status=EngagementStatus.ACTIVE,
                     allowed_cloud_accounts=["acct-1"])
    res = _run("aws", _aws_snapshot(), engagement=eng, account_id="acct-1")
    assert res["attack_paths"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
