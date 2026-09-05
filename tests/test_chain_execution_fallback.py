import asyncio
from unittest.mock import AsyncMock, MagicMock
from core.memory.shared_context import SharedContextV2 as SharedContext
from core.exploitation.request_capture import CapturedRequest
from core.exploitation.chain_executor import ChainExecutor, ChainResult
from core.exploitation.chain_detector import ScoredChain
from core.exploitation.chain_integration import ChainManager
from core.reporting.vuln_graph import VulnGraph
from core.memory.relationship_db import RelationshipDB

def test_captured_request_object_context_generation():
    ctx = SharedContext("https://example.com")
    req = CapturedRequest(
        method="GET",
        url="https://example.com/api/test",
        resource_type="fetch",
        is_preflight=False,
        status=200,
        headers={"Content-Type": "application/json"},
        post_data='{"key": "val"}'
    )
    # Add object directly
    ctx.add_captured_requests([req])
    
    # Generate agent context
    context_str = ctx.get_context_for_agent("Exploit XSS", ["target", "captured_requests"])
    assert "https://example.com/api/test" in context_str
    assert "CAPTURED REQUESTS" in context_str

def test_chain_manager_alternative_fallback():
    async def _test():
        ctx = SharedContext("https://example.com")
        spawner = MagicMock()
        graph = VulnGraph()
        detector = MagicMock()
        rel_db = RelationshipDB()
        executor = ChainExecutor(graph, detector, rel_db, ctx, spawner)
        
        chain1 = ScoredChain(
            chain_id="CHAIN-001",
            steps=[{"vuln_id": "v1", "type": "missing_csp", "location": "https://example.com"}],
            edges=[],
            score=0.75,
            description="Chain 1"
        )
        chain2 = ScoredChain(
            chain_id="CHAIN-002",
            steps=[{"vuln_id": "v3", "type": "missing_x_frame_options", "location": "https://example.com"}],
            edges=[],
            score=0.70,
            description="Chain 2"
        )
        
        # Mock executor.execute_chain to fail on chain1 and succeed on chain2
        async def mock_execute(chain):
            if chain.chain_id == "CHAIN-001":
                return ChainResult(chain_id="CHAIN-001", status="failed", steps_completed=0, steps_total=1)
            else:
                return ChainResult(chain_id="CHAIN-002", status="completed", steps_completed=1, steps_total=1)
                
        executor.execute_chain = AsyncMock(side_effect=mock_execute)
        
        mgr = ChainManager(ctx, spawner)
        mgr.executor = executor
        mgr.detector = MagicMock()
        mgr.detector.get_top_chains.return_value = [chain1, chain2]
        
        mgr.llm = MagicMock()
        mgr.llm.generate_json = AsyncMock(return_value={"selected_chain_id": "CHAIN-001", "reasoning": "Try chain 1 first"})
        mgr.graph = MagicMock()
        mgr.graph.summary_for_llm.return_value = "Graph summary"
        mgr.detector.summary_for_llm.return_value = "Chain summary"
        
        final_result = await mgr.llm_select_and_execute()
        assert final_result.status == "completed"
        assert final_result.chain_id == "CHAIN-002"
        
    asyncio.run(_test())
