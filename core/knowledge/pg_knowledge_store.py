from __future__ import annotations

import logging
from typing import Any, Dict, List

import psycopg2.extras

from core.knowledge.knowledge_graph import KnowledgeGraph, _BUCKETS
from core.memory.database import DatabaseManager
from core.utils.sanitize import safe_json_dumps

logger = logging.getLogger(__name__)

_dumps = safe_json_dumps


class PgKnowledgeStore:
    """Postgres-backed persistence for the in-memory KnowledgeGraph.

    Mirrors the FindingStore idiom (DatabaseManager pooled connections,
    ON CONFLICT upserts). All state is scoped by ``scan_id`` so multiple
    concurrent scans never collide. Persisting on every checkpoint lets a
    crashed/resumed scan reload its entity graph and hypotheses instead of
    starting from an empty graph.
    """

    # ── Knowledge graph ────────────────────────────────────────────────
    def save_graph(self, scan_id: str, kg: KnowledgeGraph) -> Dict[str, int]:
        """Upsert every node + edge of ``kg`` under ``scan_id``.

        Returns {"nodes": N, "edges": M} counts written.
        """
        data = kg.to_serializable()
        node_rows: List[tuple] = []
        for node_type in _BUCKETS:
            for node_id, node_data in (data.get(node_type) or {}).items():
                if not node_id:
                    continue
                node_rows.append((scan_id, str(node_id), node_type, _dumps(node_data)))

        edge_rows: List[tuple] = []
        for edge in data.get("edges") or []:
            frm, to, etype = edge.get("from"), edge.get("to"), edge.get("type")
            if not (frm and to and etype):
                continue
            edge_rows.append((scan_id, str(frm), str(to), str(etype), _dumps(edge)))

        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                if node_rows:
                    psycopg2.extras.execute_values(
                        cur,
                        """
                        INSERT INTO kg_nodes (scan_id, node_id, node_type, data)
                        VALUES %s
                        ON CONFLICT (scan_id, node_type, node_id) DO UPDATE SET
                            data = EXCLUDED.data,
                            updated_at = NOW()
                        """,
                        node_rows,
                        template="(%s, %s, %s, %s::jsonb)",
                    )
                if edge_rows:
                    psycopg2.extras.execute_values(
                        cur,
                        """
                        INSERT INTO kg_edges (scan_id, from_id, to_id, edge_type, data)
                        VALUES %s
                        ON CONFLICT (scan_id, from_id, to_id, edge_type) DO UPDATE SET
                            data = EXCLUDED.data
                        """,
                        edge_rows,
                        template="(%s, %s, %s, %s, %s::jsonb)",
                    )
            conn.commit()

        counts = {"nodes": len(node_rows), "edges": len(edge_rows)}
        logger.info("KnowledgeGraph persisted for scan %s: %s", scan_id, counts)
        return counts

    def load_graph(self, scan_id: str) -> KnowledgeGraph:
        """Rebuild a KnowledgeGraph from persisted rows for ``scan_id``."""
        snapshot: Dict[str, Any] = {b: {} for b in _BUCKETS}
        snapshot["edges"] = []
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT node_id, node_type, data FROM kg_nodes WHERE scan_id = %s",
                    (scan_id,),
                )
                for row in cur.fetchall():
                    bucket = snapshot.get(row["node_type"])
                    if bucket is not None:
                        bucket[row["node_id"]] = row["data"]
                cur.execute(
                    "SELECT from_id, to_id, edge_type, data FROM kg_edges WHERE scan_id = %s",
                    (scan_id,),
                )
                for row in cur.fetchall():
                    edge = dict(row["data"] or {})
                    edge.setdefault("from", row["from_id"])
                    edge.setdefault("to", row["to_id"])
                    edge.setdefault("type", row["edge_type"])
                    snapshot["edges"].append(edge)
        return KnowledgeGraph.from_serializable(snapshot)

    def incremental_sync(self, scan_id: str, kg: KnowledgeGraph) -> Dict[str, int]:
        """Alias of save_graph — upserts are already idempotent, so a full
        save only rewrites changed rows. Kept as the roadmap's named entry."""
        return self.save_graph(scan_id, kg)

    @staticmethod
    def unify_asset_inventory(kg: KnowledgeGraph, brain) -> int:
        """Unify the disconnected asset stores (AttackSurfaceGraph +
        EndpointInventoryV2) INTO the KnowledgeGraph so a single persisted graph
        holds all endpoints/assets. Idempotent (KG upserts by id). Returns count
        of endpoint nodes merged in."""
        merged = 0

        def _ep_dict(ep) -> dict:
            if isinstance(ep, dict):
                return ep
            if hasattr(ep, "to_dict"):
                try:
                    return ep.to_dict()
                except Exception:
                    pass
            return {k: v for k, v in vars(ep).items() if not k.startswith("_")} if hasattr(ep, "__dict__") \
                else {"url": str(ep)}

        # AttackSurfaceGraph.api_endpoints() -> List[Endpoint]
        asg = getattr(brain, "attack_surface", None)
        try:
            if asg is not None and hasattr(asg, "api_endpoints"):
                for ep in asg.api_endpoints():
                    d = _ep_dict(ep)
                    d.setdefault("source", "attack_surface_graph")
                    kg.add_endpoint(d)
                    merged += 1
        except Exception as e:
            logger.debug("unify attack_surface failed: %s", e)

        # EndpointInventoryV2.list_endpoints() -> List[Dict]
        inv = getattr(brain, "endpoint_inventory", None)
        try:
            if inv is not None and hasattr(inv, "list_endpoints"):
                for ep in inv.list_endpoints():
                    d = _ep_dict(ep)
                    d.setdefault("source", "endpoint_inventory_v2")
                    kg.add_endpoint(d)
                    merged += 1
        except Exception as e:
            logger.debug("unify endpoint_inventory failed: %s", e)

        logger.info("Unified %d endpoints from asset inventories into KnowledgeGraph", merged)
        return merged

    # ── Hypotheses ─────────────────────────────────────────────────────
    def save_hypotheses(self, scan_id: str, hypotheses: List[Dict[str, Any]]) -> int:
        """Persist a list of hypothesis dicts. Each must have an id field
        (``hypothesis_id``/``hyp_id``/``id``); others are skipped."""
        rows: List[tuple] = []
        for h in hypotheses or []:
            hid = h.get("hypothesis_id") or h.get("hyp_id") or h.get("id")
            if not hid:
                continue
            rows.append((scan_id, str(hid), _dumps(h)))
        if not rows:
            return 0
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO kg_hypotheses (scan_id, hypothesis_id, data)
                    VALUES %s
                    ON CONFLICT (scan_id, hypothesis_id) DO UPDATE SET
                        data = EXCLUDED.data,
                        updated_at = NOW()
                    """,
                    rows,
                    template="(%s, %s, %s::jsonb)",
                )
            conn.commit()
        logger.info("Persisted %d hypotheses for scan %s", len(rows), scan_id)
        return len(rows)

    def load_hypotheses(self, scan_id: str) -> List[Dict[str, Any]]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT data FROM kg_hypotheses WHERE scan_id = %s",
                    (scan_id,),
                )
                return [row["data"] for row in cur.fetchall()]
