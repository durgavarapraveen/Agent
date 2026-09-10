import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.inventory_generator import (
    build_inventory,
    classify_component,
    emit_json,
    emit_markdown,
    RISK_CATEGORIES,
)


class TestComponentClassifier:
    def test_agent_classification(self):
        assert classify_component("agents/exploit_agent.py") == "agent"

    def test_security_classification(self):
        assert classify_component("core/security/policy_engine.py") == "security"

    def test_tool_classification(self):
        assert classify_component("core/tools/tool_registry.py") == "tool"

    def test_executor_classification(self):
        assert classify_component("core/execution/sandbox.py") == "executor"

    def test_database_classification(self):
        assert classify_component("core/database/pg_store.py") == "database"

    def test_unknown_classification(self):
        assert classify_component("unknown/module.py") == "other"

    def test_backslash_normalization(self):
        assert classify_component("core\\security\\policy_engine.py") == "security"


class TestInventoryBuilder:
    @pytest.fixture(scope="class")
    def inventory(self):
        return build_inventory()

    def test_has_components(self, inventory):
        assert len(inventory.components) > 50

    def test_has_risk_summary(self, inventory):
        assert len(inventory.risk_summary) > 0

    def test_has_call_graph_edges(self, inventory):
        assert len(inventory.call_graph_edges) > 100

    def test_has_checksum(self, inventory):
        assert len(inventory.checksum) == 16

    def test_has_generated_at(self, inventory):
        assert inventory.generated_at

    def test_version(self, inventory):
        assert inventory.version == "1.0.0"

    def test_detects_duplicates(self, inventory):
        assert len(inventory.duplicates) > 0
        responsibility_names = [d["responsibility"] for d in inventory.duplicates]
        assert "authorization" in responsibility_names

    def test_detects_network_io(self, inventory):
        assert inventory.risk_summary.get("network_io", 0) > 0

    def test_detects_process_exec(self, inventory):
        assert inventory.risk_summary.get("process_exec", 0) > 0

    def test_detects_filesystem_write(self, inventory):
        assert inventory.risk_summary.get("filesystem_write", 0) > 0

    def test_detects_credential_access(self, inventory):
        assert inventory.risk_summary.get("credential_access", 0) > 0

    def test_security_components_exist(self, inventory):
        security_modules = [
            c for c in inventory.components if c.component_type == "security"
        ]
        assert len(security_modules) >= 10

    def test_policy_engine_found(self, inventory):
        pe = [c for c in inventory.components if "policy_engine" in c.module_path and "security" in c.module_path]
        assert len(pe) >= 1

    def test_classes_extracted(self, inventory):
        total_classes = sum(len(c.classes) for c in inventory.components)
        assert total_classes > 50

    def test_imports_extracted(self, inventory):
        total_imports = sum(len(c.imports_from) for c in inventory.components)
        assert total_imports > 50


class TestInventoryOutput:
    @pytest.fixture(scope="class")
    def inventory(self):
        return build_inventory()

    def test_json_output(self, inventory, tmp_path):
        path = tmp_path / "test_inventory.json"
        emit_json(inventory, path)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "components" in data
        assert "risk_summary" in data
        assert "checksum" in data

    def test_markdown_output(self, inventory, tmp_path):
        path = tmp_path / "test_inventory.md"
        emit_markdown(inventory, path)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "# Architecture Inventory" in content
        assert "Risk Summary" in content
        assert "Components by Type" in content

    def test_json_roundtrip_checksum(self, inventory, tmp_path):
        path = tmp_path / "test_inventory.json"
        emit_json(inventory, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["checksum"] == inventory.checksum
