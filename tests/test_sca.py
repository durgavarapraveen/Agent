"""Container / dependency SCA — parsing, matching, Dockerfile, agent (spec §5/§20/§21)."""
import pytest

from core.sca import (
    ScaAgent, analyze_dockerfile, parse_files, version_in_range,
)
from core.sca.advisories import Range, StaticAdvisorySource
from core.sca.matcher import match
from core.sca.parsers import Package
from core.domain.engagement import Engagement, EngagementStatus


# ── parsers ────────────────────────────────────────────────────────────
def test_parse_requirements():
    pkgs = parse_files({"requirements.txt":
                        "flask==1.0.0\n# c\nrequests>=2.0  # range ignored\ndjango[argon2]==3.2.1\n"})
    names = {(p.name, p.version, p.ecosystem) for p in pkgs}
    assert ("flask", "1.0.0", "PyPI") in names
    assert ("django", "3.2.1", "PyPI") in names
    assert not any(p.name == "requests" for p in pkgs)  # non-== skipped


def test_parse_package_lock_v3():
    content = '{"packages": {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.15"}}}'
    pkgs = parse_files({"package-lock.json": content})
    assert ("lodash", "4.17.15", "npm") in {(p.name, p.version, p.ecosystem) for p in pkgs}


def test_parse_go_mod():
    content = "module x\n\nrequire (\n  github.com/gin-gonic/gin v1.6.0\n)\n"
    pkgs = parse_files({"go.mod": content})
    assert ("github.com/gin-gonic/gin", "1.6.0", "Go") in {(p.name, p.version, p.ecosystem) for p in pkgs}


def test_parse_pom_xml():
    content = ("<dependency><groupId>org.apache</groupId>"
               "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>")
    pkgs = parse_files({"pom.xml": content})
    assert ("org.apache:log4j-core", "2.14.1", "Maven") in {(p.name, p.version, p.ecosystem) for p in pkgs}


# ── version ranges ─────────────────────────────────────────────────────
def test_version_in_range_boundaries():
    r = Range(introduced="1.0.0", fixed="1.2.0")
    assert version_in_range("1.0.0", r) is True     # inclusive lower
    assert version_in_range("1.1.9", r) is True
    assert version_in_range("1.2.0", r) is False    # exclusive upper
    assert version_in_range("0.9.9", r) is False
    assert version_in_range("1.10.0", r) is False   # numeric, not lexical


def test_unbounded_range_no_fix():
    assert version_in_range("9.9.9", Range(introduced="1.0.0", fixed="")) is True


# ── matcher ────────────────────────────────────────────────────────────
def test_match_flags_vulnerable_and_spares_fixed():
    advs = [{"id": "CVE-2020-1", "ecosystem": "PyPI", "package": "flask",
             "severity": "HIGH", "ranges": [{"introduced": "0", "fixed": "1.1.0"}]}]
    src = StaticAdvisorySource(advs)
    vuln = match([Package("flask", "1.0.0", "PyPI", "requirements.txt")], src)
    safe = match([Package("flask", "1.1.0", "PyPI", "requirements.txt")], src)
    assert len(vuln) == 1 and vuln[0]["cve"] == "CVE-2020-1"
    assert vuln[0]["fixed_version"] == "1.1.0"
    assert safe == []


# ── dockerfile ─────────────────────────────────────────────────────────
def test_dockerfile_flags_root_latest_and_secret():
    df = ("FROM python:latest\n"
          "ENV API_KEY=supersecretvalue123\n"
          "RUN curl http://x/i.sh | sh\n")
    findings = analyze_dockerfile(df)
    types = {f["type"] for f in findings}
    titles = " | ".join(f["title"] for f in findings)
    assert "CONTAINER_SECRET" in types
    assert "runs as root" in titles.lower()
    assert ":latest" in titles or "Mutable" in titles
    assert "piped to a shell" in titles.lower()


def test_dockerfile_nonroot_user_clears_root_finding():
    df = "FROM python:3.12-slim\nUSER app\n"
    findings = analyze_dockerfile(df)
    assert not any("runs as root" in f["title"].lower() for f in findings)


# ── agent ──────────────────────────────────────────────────────────────
def _advs():
    return [{"id": "CVE-LOG4J", "ecosystem": "Maven", "package": "org.apache:log4j-core",
             "severity": "CRITICAL", "ranges": [{"introduced": "2.0.0", "fixed": "2.17.0"}],
             "cve": "CVE-2021-44228"}]


def _files():
    return {
        "pom.xml": ("<dependency><groupId>org.apache</groupId>"
                    "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"),
        "Dockerfile": "FROM openjdk:latest\n",
    }


def test_agent_reports_dep_vuln_and_container_findings():
    res = ScaAgent.from_advisories(_files(), _advs(), target="repo-1").run()
    dep = [f for f in res["findings"] if f["type"] == "VULNERABLE_DEPENDENCY"]
    cont = [f for f in res["findings"] if f["type"].startswith("CONTAINER")]
    assert dep and dep[0]["severity"] == "CRITICAL"
    assert cont
    assert "Maven" in res["ecosystems"]


def test_agent_emits_attack_path_for_critical_dep():
    res = ScaAgent.from_advisories(_files(), _advs(), target="repo-1").run()
    paths = res["attack_paths"]
    assert any(p["target"] == "component:org.apache:log4j-core"
               and p["status"] == "hypothesized" for p in paths)


def test_agent_scope_gate_denies_unauthorized_target():
    eng = Engagement(name="e", status=EngagementStatus.ACTIVE,
                     authorized_targets=["https://ok/"])
    res = ScaAgent.from_advisories(_files(), _advs(), target="repo-1", engagement=eng).run()
    assert res["findings"] == [] and res["attack_paths"] == [] and res["packages"] == 0


def test_agent_scope_gate_allows_authorized_target():
    eng = Engagement(name="e", status=EngagementStatus.ACTIVE,
                     allowed_cloud_accounts=["repo-1"])
    res = ScaAgent.from_advisories(_files(), _advs(), target="repo-1", engagement=eng).run()
    assert any(f["type"] == "VULNERABLE_DEPENDENCY" for f in res["findings"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
