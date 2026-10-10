"""Detection run runner (Stage-5 §4.3 lifecycle, empty-pack M1 subset).

Zero rules ⇒ zero rule_run rows, zero findings, terminal status `completed`
(M1 exit ①; Stage-6 D6-015).  The L0–L4 gates run vacuously.
"""
from __future__ import annotations

import uuid
from typing import Any

import psycopg

from sentinel_storage import repos_detect

from .store import EmptyRuleStore


def run_detection(
    conn: psycopg.Connection,
    *,
    run_id: uuid.UUID,
    tenant_id: str,
    workspace_id: str,
    requested_by: str,
    scope: dict[str, Any],
) -> dict[str, Any]:
    repos_detect.mark_running(conn, run_id)
    store = EmptyRuleStore()
    rules = store.load(tenant_id, workspace_id)
    # M1: empty store.  Each rule would be accounted in rule_run here; with
    # zero rules there are zero accounting rows (PK (run_id, rule_id)).
    assert len(rules) == 0
    summary = {
        "rules_total": len(rules),
        "findings": 0,
        "engine": "empty-pack",
    }
    repos_detect.finish_run(conn, run_id, status="completed", summary=summary)
    return {"run_id": str(run_id), "status": "completed", **summary}
