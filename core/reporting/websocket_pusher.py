
import asyncio
import gzip
import json
import logging
import time
from typing import Dict, List, Any, Set, Tuple

import websockets

logger = logging.getLogger(__name__)


class RealtimeStreamServer:

    def __init__(self, host: str = "127.0.0.1", port: int = 8765):
        self.host = host
        self.port = port
        self.subscribers: Dict[str, Set[Any]] = {}  # scan_id -> Set[websocket]
        self.sse_queues: Dict[str, List[asyncio.Queue]] = {}  # scan_id -> List[Queue]
        self.server = None

    async def register(self, websocket: Any, scan_id: str):
        if scan_id not in self.subscribers:
            self.subscribers[scan_id] = set()
        self.subscribers[scan_id].add(websocket)
        logger.info(f"[WebSocketServer] Client registered to scan_id={scan_id}")

    async def unregister(self, websocket: Any, scan_id: str):
        if scan_id in self.subscribers and websocket in self.subscribers[scan_id]:
            self.subscribers[scan_id].remove(websocket)
            logger.info(f"[WebSocketServer] Client unregistered from scan_id={scan_id}")

    async def handler(self, websocket: Any):
        current_scan_id = None
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    if data.get("action") == "subscribe" and "scan_id" in data:
                        current_scan_id = data["scan_id"]
                        await self.register(websocket, current_scan_id)
                        ack = json.dumps({"status": "subscribed", "scan_id": current_scan_id})
                        await websocket.send(ack)
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.debug(f"[WebSocketServer] Connection exception: {e}")
        finally:
            if current_scan_id:
                await self.unregister(websocket, current_scan_id)

    async def start_server(self):
        self.server = await websockets.serve(self.handler, self.host, self.port)
        logger.info(f"[WebSocketServer] Listening on ws://{self.host}:{self.port}")

    async def stop_server(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    def compress_payload_if_large(self, payload_bytes: bytes, threshold_bytes: int = 1024) -> Tuple[bytes, bool]:
        if len(payload_bytes) > threshold_bytes:
            return gzip.compress(payload_bytes), True
        return payload_bytes, False

    async def push_finding(self, scan_id: str, finding: Dict[str, Any]):
        payload = {
            "type": "new_finding",
            "scan_id": scan_id,
            "timestamp": time.time(),
            "finding": finding
        }
        msg = json.dumps(payload)

        # 1. Push to WebSockets
        if scan_id in self.subscribers:
            dead_sockets = set()
            for ws in self.subscribers[scan_id]:
                try:
                    await ws.send(msg)
                except Exception:
                    dead_sockets.add(ws)
            self.subscribers[scan_id] -= dead_sockets

        # 2. Push to SSE queues
        if scan_id in self.sse_queues:
            sse_msg = self.format_sse_event("new_finding", payload)
            for q in self.sse_queues[scan_id]:
                await q.put(sse_msg)

    async def push_progress_update(self, scan_id: str, completed_modules: int, total_modules: int, description: str):
        pct = round((completed_modules / max(1, total_modules)) * 100, 1)
        payload = {
            "type": "progress_update",
            "scan_id": scan_id,
            "completed_modules": completed_modules,
            "total_modules": total_modules,
            "percentage": pct,
            "description": f"{description} ({pct}% complete)",
            "timestamp": time.time()
        }
        msg = json.dumps(payload)

        if scan_id in self.subscribers:
            for ws in list(self.subscribers[scan_id]):
                try:
                    await ws.send(msg)
                except Exception:
                    pass

        if scan_id in self.sse_queues:
            sse_msg = self.format_sse_event("progress_update", payload)
            for q in self.sse_queues[scan_id]:
                await q.put(sse_msg)

    def register_sse_client(self, scan_id: str) -> asyncio.Queue:
        q = asyncio.Queue()
        if scan_id not in self.sse_queues:
            self.sse_queues[scan_id] = []
        self.sse_queues[scan_id].append(q)
        return q

    def unregister_sse_client(self, scan_id: str, q: asyncio.Queue):
        if scan_id in self.sse_queues and q in self.sse_queues[scan_id]:
            self.sse_queues[scan_id].remove(q)

    @staticmethod
    def format_sse_event(event_type: str, data: Dict[str, Any]) -> str:
        return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
