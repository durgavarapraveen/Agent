import pytest
import tempfile
from pathlib import Path

from knowledge.store import KnowledgeStore

@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        yield str(db_path)

class TestKnowledgeStore:
    def test_store_creation(self, temp_db):
        store = KnowledgeStore(temp_db)
        assert Path(temp_db).exists()
    
    def test_add_target(self, temp_db):
        store = KnowledgeStore(temp_db)
        store.add_target("target1", "https://example.com", "WEB")
        
        findings = store.get_target_findings("target1")
        assert isinstance(findings, list)
    
    def test_add_asset(self, temp_db):
        store = KnowledgeStore(temp_db)
        store.add_target("target1", "https://example.com", "WEB")
        store.add_asset("asset1", "target1", "domain", "example.com")
        
        assets = store.get_target_assets("target1")
        assert len(assets) >= 1
    
    def test_add_technology(self, temp_db):
        store = KnowledgeStore(temp_db)
        store.add_target("target1", "https://example.com", "WEB")
        store.add_asset("asset1", "target1", "domain", "example.com")
        store.add_technology("tech1", "asset1", "Flask", "2.0.1", 0.95, "fingerprint")
        
        techs = store.get_asset_technologies("asset1")
        assert len(techs) >= 1
    
    def test_add_endpoint(self, temp_db):
        store = KnowledgeStore(temp_db)
        store.add_target("target1", "https://example.com", "WEB")
        store.add_asset("asset1", "target1", "domain", "example.com")
        store.add_endpoint("ep1", "asset1", "/api/users", "GET", 200)
        
        endpoints = store.get_asset_endpoints("asset1")
        assert len(endpoints) >= 1
    
    def test_add_finding(self, temp_db):
        store = KnowledgeStore(temp_db)
        store.add_target("target1", "https://example.com", "WEB")
        store.add_finding(
            "finding1", "target1",
            "Test Finding",
            "Test Description",
            severity="HIGH"
        )
        
        findings = store.get_target_findings("target1")
        assert len(findings) >= 1
    
    def test_update_finding_status(self, temp_db):
        store = KnowledgeStore(temp_db)
        store.add_target("target1", "https://example.com", "WEB")
        store.add_finding("finding1", "target1", "Test", "Desc")
        store.update_finding_status("finding1", "CONFIRMED")
        
        findings = store.get_target_findings("target1")
        assert any(f["status"] == "CONFIRMED" for f in findings)
    
    def test_database_summary(self, temp_db):
        store = KnowledgeStore(temp_db)
        store.add_target("target1", "https://example.com", "WEB")
        
        summary = store.export_database_summary()
        assert "targets" in summary
        assert summary["targets"] >= 1
