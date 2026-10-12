"""M1 exit ①② end-to-end: upload the harvested 1 MiB EVTX, drain the queue,
assert events>0, rule_run empty, run status completed; cross-tenant probe."""
from __future__ import annotations

import time

from ..conftest import drain_jobs
from ..keys import KEY_A, KEY_B


def test_e2e_upload_ingest_detect(client, app_settings, m1_fixture_evtx):
    with m1_fixture_evtx.open("rb") as fh:
        data = fh.read()
    assert len(data) >= 1024 * 1024, "M1 exit ① requires >= 1 MiB fixture"

    r = client.post(
        "/v1/workspaces/default/uploads",
        files={"file": ("sentinel_m1.evtx", data, "application/octet-stream")},
        data={"collection_kind": "harvest"},
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 202, r.text
    body = r.json()
    artifact_id = body["artifact_id"]
    run_id = body["run_id"]
    assert body["size"] == len(data)
    assert body["triage_state"] == "queued"
    assert len(body["sha256"]) == 64

    # drain: ingest_file + chained detect_run
    processed = drain_jobs(app_settings)
    assert processed >= 2, f"expected ingest + detect jobs, processed {processed}"

    # upload completed
    r = client.get(
        f"/v1/workspaces/default/uploads/{artifact_id}",
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 200
    assert r.json()["triage_state"] == "done"

    # events > 0 (M1 exit ①)
    r = client.get(
        "/v1/workspaces/default/events",
        params={"run_id": run_id, "limit": 5},
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) > 0, "no events rows after ingest"

    # paginated count via direct DB (worker role, scoped)
    from sentinel_core.db import tx
    from sentinel_core.rls import set_rls
    from sentinel_storage.repos_events import count_for_run

    with tx(app_settings.database_url) as conn:
        set_rls(conn, "default", "default")
        n = count_for_run(conn, run_id)
    assert n > 0

    # detection run (auto-chained): completed, zero rule_run rows (empty pack)
    r = client.get(
        "/v1/workspaces/default/runs",
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 200
    runs = r.json()["items"]
    assert len(runs) >= 1, "auto-chained detect_run did not create a run"
    run_detail = None
    for candidate in runs:
        g = client.get(
            f"/v1/workspaces/default/runs/{candidate['run_id']}",
            headers={"X-API-Key": KEY_A},
        )
        if g.status_code == 200 and (g.json().get("scope") or {}).get("harvest_run_id") == run_id:
            run_detail = g.json()
            break
    assert run_detail is not None, "no detection run for this harvest run"
    assert run_detail["status"] == "completed", run_detail

    rr = client.get(
        f"/v1/workspaces/default/runs/{run_detail['run_id']}/rule-runs",
        headers={"X-API-Key": KEY_A},
    )
    assert rr.status_code == 200
    assert rr.json()["items"] == [], "empty pack must produce zero rule_run rows"

    # empty pack ⇒ zero findings, asserted against the findings table itself
    # (M1 content bullet: "detect run completes with empty findings").
    import uuid as _uuid

    from sentinel_storage.repos_detect import count_findings_for_run

    with tx(app_settings.database_url) as conn:
        set_rls(conn, "default", "default")
        assert count_findings_for_run(conn, _uuid.UUID(run_detail["run_id"])) == 0


def test_e2e_cross_tenant_sees_nothing(client, app_settings, m1_fixture_evtx):
    """M1 exit ② half-2: tenant-b sees zero rows for tenant-a's data."""
    with m1_fixture_evtx.open("rb") as fh:
        data = fh.read()[:64 * 1024]  # small slice is enough to create a row

    r = client.post(
        "/v1/workspaces/default/uploads",
        files={"file": ("slice.evtx", data, "application/octet-stream")},
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 202
    run_id = r.json()["run_id"]

    # tenant-b is scoped to ws-b, not default → 403
    r = client.get(
        "/v1/workspaces/default/events",
        params={"run_id": run_id},
        headers={"X-API-Key": KEY_B},
    )
    assert r.status_code == 403

    # even on its own workspace, tenant-b sees zero events for A's run_id
    r = client.get(
        "/v1/workspaces/ws-b/events",
        params={"run_id": run_id},
        headers={"X-API-Key": KEY_B},
    )
    assert r.status_code == 200
    assert r.json()["items"] == []

    from sentinel_core.db import tx
    from sentinel_core.rls import set_rls
    from sentinel_storage.repos_events import count_for_run

    with tx(app_settings.database_url) as conn:
        set_rls(conn, "tenant-b", "ws-b")
        assert count_for_run(conn, run_id) == 0
