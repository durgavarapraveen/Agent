"""Phase 4.1 — API-first deep testing: importers + spec generation."""
from __future__ import annotations

from core.discovery.api_test_generator import (
    APITestGenerator,
    parse_grpc_proto,
    parse_postman_collection,
)


def test_parse_postman_collection():
    collection = {
        "item": [
            {"name": "Login", "request": {"method": "POST",
             "url": {"raw": "https://api.test/login?debug=1"},
             "body": {"raw": '{"username":"a","password":"b"}'}}},
            {"name": "Folder", "item": [
                {"name": "GetUser", "request": {"method": "GET",
                 "url": {"raw": "https://api.test/users/1"}}},
            ]},
        ]
    }
    eps = parse_postman_collection(collection)
    by_name = {e["name"]: e for e in eps}
    assert by_name["Login"]["method"] == "POST"
    assert "username" in by_name["Login"]["params"]
    assert "debug" in by_name["Login"]["params"]      # query param
    assert by_name["GetUser"]["method"] == "GET"


def test_parse_grpc_proto():
    proto = """
    service AccountService {
      rpc GetBalance (BalanceRequest) returns (BalanceResponse);
      rpc Transfer (stream TransferRequest) returns (TransferResponse);
    }
    """
    eps = parse_grpc_proto(proto)
    paths = {e["path"] for e in eps}
    assert "/AccountService/GetBalance" in paths
    assert "/AccountService/Transfer" in paths
    assert all(e["method"] == "POST" for e in eps)


def test_generate_mass_assignment_and_pollution():
    endpoints = [{"url": "https://api.test/profile", "method": "PUT",
                  "params": ["name", "email"], "source": "openapi"}]
    specs = APITestGenerator().generate(endpoints)
    techniques = {s["technique"] for s in specs}
    assert "mass_assignment" in techniques
    assert "parameter_pollution" in techniques
    ma = next(s for s in specs if s["technique"] == "mass_assignment")
    assert "is_admin" in ma["mutation"]["extra_fields"]
    assert ma["priority"] == "high"


def test_generate_bfla_for_privileged_endpoint():
    endpoints = [{"url": "https://api.test/admin/users", "method": "GET",
                  "params": [], "source": "openapi"}]
    specs = APITestGenerator().generate(endpoints)
    assert any(s["technique"] == "broken_function_level_auth" for s in specs)


def test_generate_excessive_data_exposure():
    endpoints = [{"url": "https://api.test/users/1", "method": "GET",
                  "params": [], "response_fields": ["id", "name"], "source": "openapi"}]
    specs = APITestGenerator().generate(endpoints)
    ede = [s for s in specs if s["technique"] == "excessive_data_exposure"]
    assert ede and ede[0]["mutation"]["documented_fields"] == ["id", "name"]


def test_from_importer_reuse():
    class _FakeImporter:
        def import_all(self):
            return [{"url": "https://api.test/x", "method": "POST", "params": ["a"]}]

    specs = APITestGenerator().from_importer(_FakeImporter())
    assert specs and any(s["technique"] == "mass_assignment" for s in specs)


def test_from_importer_handles_failure():
    class _BadImporter:
        def import_all(self):
            raise RuntimeError("network")

    assert APITestGenerator().from_importer(_BadImporter()) == []
