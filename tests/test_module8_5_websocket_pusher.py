"""
Unit tests for Phase 8 Module 8.5: Result Streaming & Real-Time Progress (core/websocket_pusher.py)
"""

import asyncio
import json
import unittest
from core.websocket_pusher import RealtimeStreamServer


class TestModule8_5_WebSocketPusher(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.server = RealtimeStreamServer(host="127.0.0.1", port=8765)

    async def test_sse_event_formatting_and_queue_buffering(self):
        """Verify SSE queue registration, formatting, and buffer receiving."""
        scan_id = "test_scan_sse_001"
        sse_queue = self.server.register_sse_client(scan_id)

        finding = {"cve": "CVE-2026-9999", "severity": "CRITICAL", "title": "Test Vulnerability"}
        await self.server.push_finding(scan_id, finding)

        event_msg = await asyncio.wait_for(sse_queue.get(), timeout=2.0)
        self.assertIn("event: new_finding", event_msg)
        self.assertIn("CVE-2026-9999", event_msg)

        self.server.unregister_sse_client(scan_id, sse_queue)

    async def test_progress_update_push(self):
        """Verify progress update calculation and SSE queue push."""
        scan_id = "test_scan_progress_001"
        sse_queue = self.server.register_sse_client(scan_id)

        await self.server.push_progress_update(scan_id, completed_modules=5, total_modules=10, description="Nuclei scan in progress")

        event_msg = await asyncio.wait_for(sse_queue.get(), timeout=2.0)
        self.assertIn("event: progress_update", event_msg)
        self.assertIn("50.0% complete", event_msg)

        self.server.unregister_sse_client(scan_id, sse_queue)

    def test_gzip_compression_for_large_payloads(self):
        """Verify payload compression threshold logic."""
        small_payload = b"small data string"
        res_small, is_compressed = self.server.compress_payload_if_large(small_payload, threshold_bytes=1024)
        self.assertFalse(is_compressed)

        large_payload = b"large data string " * 200
        res_large, is_compressed = self.server.compress_payload_if_large(large_payload, threshold_bytes=1024)
        self.assertTrue(is_compressed)


if __name__ == "__main__":
    unittest.main()
