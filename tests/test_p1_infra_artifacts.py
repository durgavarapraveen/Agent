import pytest


# ---- P1.3 ------------------------------------------------------------------

def test_artifact_classification_and_registry():
    from core.domain.artifact_registry import ArtifactRegistry, classify_url, ArtifactType
    assert classify_url("https://h/v2/api-docs") == ArtifactType.OPENAPI
    assert classify_url("https://h/main.bundle.js") == ArtifactType.JS_BUNDLE
    reg = ArtifactRegistry()
    a = reg.register("https://h/swagger.json")
    assert a is not None and a.artifact_type == "SWAGGER"
    reg.register("https://h/graphql")
    reg.register("https://h/robots.txt")
    assert set(reg.urls_of("SWAGGER")) == {"https://h/swagger.json"}
    assert reg.summary()["total"] == 3


def test_harvest_from_ctx_finds_schema_urls():
    from core.domain.artifact_registry import harvest_from_ctx

    class _Ctx:
        endpoints = {"a": {"url": "https://h/api/v3/api-docs", "method": "GET"},
                     "b": {"url": "https://h/home", "method": "GET"}}
        captured_requests = [{"url": "https://h/openapi.json"}]
        asset_registry = None
    ctx = _Ctx()
    reg = harvest_from_ctx(ctx)
    urls = set(reg.urls_of("OPENAPI"))
    assert "https://h/api/v3/api-docs" in urls
    assert "https://h/openapi.json" in urls


def test_importer_consumes_registered_urls_first():
    from core.discovery.api_schema_importer import APISchemaImporter
    from core.domain.artifact_registry import ArtifactRegistry
    reg = ArtifactRegistry()
    reg.register("https://real/custom/spec.json", artifact_type="OPENAPI")
    imp = APISchemaImporter(target="https://real", artifacts=reg)
    # The registered non-standard URL must be attempted before the hardcoded list.
    tried = []
    imp._fetch = lambda url: (tried.append(url) or (404, ""))
    imp.discover_openapi()
    assert tried[0] == "https://real/custom/spec.json"


# ---- P1.8 ------------------------------------------------------------------

def test_env_profile_describes_sandbox():
    from core.execution.environment_profile import describe_for_llm, get_profile
    desc = describe_for_llm()
    assert "run_custom_python" in desc
    assert "RESULT" in desc
    assert "do NOT probe" in desc.lower() or "do not probe" in desc.lower()
    prof = get_profile()
    assert "httpx (async, scope-limited)" in prof["custom_python_sandbox"]["preloaded_modules"]
    assert "playwright" in prof["custom_python_sandbox"]["unavailable"]


# ---- P1.15 -----------------------------------------------------------------

def test_infra_layer_edge_vs_origin_vs_app():
    from core.attack_surface.infra_layer import classify_layer
    assert classify_layer({"CF-RAY": "abc", "Server": "cloudflare"}) == "EDGE"
    assert classify_layer({"X-Cache": "HIT"}) == "EDGE"
    assert classify_layer({"Server": "nginx"}) == "ORIGIN"
    assert classify_layer({"X-Powered-By": "Express", "Server": "nginx"}) == "APPLICATION"
    assert classify_layer({}) == "UNKNOWN"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
