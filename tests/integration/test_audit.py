"""Stage-6 §5.4 audit: every mutating call and operator action lands in
``audit_log`` — denied attempts included — and the reader is workspace-scoped."""
from __future__ import annotations

import uuid

from sentinel_core.db import tx
from sentinel_core.rls import set_rls

from ..keys import KEY_A, KEY_B

AUDIT_FIELDS = {
    "audit_uid",
    "at",
    "principal",
    "action",
    "object_kind",
    "object_id",
    "outcome",
    "detail",
}


def _count(
    settings,
    tenant: str,
    workspace: str,
    *,
    action: str,
    outcome: str,
    object_id: str | None = None,
    requested_workspace: str | None = None,
) -> int:
    clauses = ["action = %s", "outcome = %s"]
    args: list = [action, outcome]
    if object_id is not None:
        clauses.append("object_id = %s")
        args.append(object_id)
    if requested_workspace is not None:
        clauses.append("detail->>'requested_workspace' = %s")
        args.append(requested_workspace)
    with tx(settings.database_url) as conn:
        set_rls(conn, tenant, workspace)
        row = conn.execute(
            f"SELECT count(*) FROM audit_log WHERE {' AND '.join(clauses)}", args
        ).fetchone()
    return int(row[0])


def _upload(client, data: bytes = b"\x00" * 4096, *, key: str = KEY_A, ws: str = "default"):
    r = client.post(
        f"/v1/workspaces/{ws}/uploads",
        files={"file": ("audit-probe.bin", data, "application/octet-stream")},
        headers={"X-API-Key": key},
    )
    return r


def test_accepted_upload_writes_an_ok_audit_row(client, app_settings):
    r = _upload(client)
    assert r.status_code == 202, r.text
    artifact_id = r.json()["artifact_id"]

    assert (
        _count(
            app_settings,
            "default",
            "default",
            action="upload.accept",
            outcome="ok",
            object_id=artifact_id,
        )
        == 1
    )


def test_denied_cross_workspace_upload_is_audited(client, app_settings):
    """A 403 must still leave evidence (§5.4 "denied attempts included")."""
    before = _count(
        app_settings,
        "tenant-b",
        "ws-b",
        action="upload.reject",
        outcome="denied",
        requested_workspace="default",
    )

    r = _upload(client, key=KEY_B, ws="default")
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "GATE_TENANT_MISMATCH"

    assert (
        _count(
            app_settings,
            "tenant-b",
            "ws-b",
            action="upload.reject",
            outcome="denied",
            requested_workspace="default",
        )
        == before + 1
    ), "denied upload attempt left no audit row"


def test_run_create_writes_an_ok_audit_row(client, app_settings):
    r = client.post(
        "/v1/workspaces/default/runs",
        json={"reason": "audit probe"},
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 202, r.text
    run_id = r.json()["run_id"]

    assert (
        _count(
            app_settings,
            "default",
            "default",
            action="run.create",
            outcome="ok",
            object_id=run_id,
        )
        == 1
    )


def test_denied_run_create_is_audited(client, app_settings):
    before = _count(
        app_settings,
        "tenant-b",
        "ws-b",
        action="run.create",
        outcome="denied",
        requested_workspace="default",
    )
    r = client.post(
        "/v1/workspaces/default/runs",
        json={},
        headers={"X-API-Key": KEY_B},
    )
    assert r.status_code == 403, r.text
    assert (
        _count(
            app_settings,
            "tenant-b",
            "ws-b",
            action="run.create",
            outcome="denied",
            requested_workspace="default",
        )
        == before + 1
    )


def test_audit_reader_is_scoped_to_the_callers_workspace(client, app_settings):
    # Positive control: tenant-b's own denied attempt must be readable...
    r = _upload(client, key=KEY_B, ws="default")
    assert r.status_code == 403, r.text

    # ...while tenant-a's rows stay invisible to it.
    r = _upload(client)
    assert r.status_code == 202, r.text
    foreign_artifact = r.json()["artifact_id"]

    r = client.get(
        "/v1/workspaces/ws-b/audit", params={"limit": 1000}, headers={"X-API-Key": KEY_B}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"items", "next"}
    assert body["next"] is None
    for item in body["items"]:
        assert set(item) == AUDIT_FIELDS
        assert item["object_id"] != foreign_artifact, (
            "tenant-b saw a tenant-a audit row: RLS leak on audit_log"
        )

    own = [i for i in body["items"] if i["action"] == "upload.reject"]
    assert own, "tenant-b cannot read back its own denied attempt"
    assert all(i["outcome"] == "denied" for i in own)
    assert all(i["principal"] != "00000000-0000-7000-8000-000000000001" for i in own)


def test_audit_reader_filters_by_action(client, app_settings):
    r = _upload(client)
    assert r.status_code == 202, r.text

    r = client.get(
        "/v1/workspaces/default/audit",
        params={"action": "upload.accept", "limit": 5},
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert len(items) >= 1
    assert all(i["action"] == "upload.accept" for i in items)
    assert all(i["outcome"] == "ok" for i in items)


def test_audit_reader_rejects_a_bad_timestamp(client, app_settings):
    r = client.get(
        "/v1/workspaces/default/audit",
        params={"since": "not-a-timestamp"},
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 400, r.text
    assert r.json()["code"] == "BAD_REQUEST"


def test_audit_reader_rejects_an_out_of_range_limit(client, app_settings):
    r = client.get(
        "/v1/workspaces/default/audit",
        params={"limit": 0},
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 400, r.text
    assert r.json()["code"] == "BAD_REQUEST"


def test_audit_reader_denies_a_foreign_workspace(client, app_settings):
    r = client.get(
        "/v1/workspaces/default/audit", headers={"X-API-Key": KEY_B}
    )
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "GATE_TENANT_MISMATCH"


def test_audit_reader_requires_authentication(client, app_settings):
    r = client.get("/v1/workspaces/default/audit")
    assert r.status_code == 401, r.text
    assert r.json()["code"] == "GATE_UNAUTHENTICATED"


def test_denied_operator_retry_is_audited(client, app_settings, migrated):
    """§6.5's operator action is a mutating call, so §5.4 covers it too."""
    from sentinel_storage import repos_jobs

    key = f"audit-retry:{uuid.uuid4().hex}"
    with tx(migrated.database_worker_url) as conn:
        job_id = repos_jobs.enqueue(
            conn,
            tenant_id="default",
            workspace_id="default",
            job_type="noop",
            payload={},
            idempotency_key=key,
            max_attempts=1,
        )
        conn.commit()
        [job] = repos_jobs.claim(
            conn, worker_id="audit-retry", limit=1, job_types=("noop",)
        )
        conn.commit()
        repos_jobs.finish(conn, job, success=False, error="boom")
        conn.commit()

    def denied() -> int:
        return _count(
            app_settings,
            "tenant-b",
            "ws-b",
            action="job.retry",
            outcome="denied",
            requested_workspace="default",
        )

    before = denied()
    r = client.post(
        f"/v1/workspaces/default/jobs/{job_id}", headers={"X-API-Key": KEY_B}
    )
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "GATE_TENANT_MISMATCH"
    assert denied() == before + 1, "denied operator retry left no audit row"

    with tx(migrated.database_worker_url) as conn:
        row = conn.execute(
            "SELECT status FROM jobs WHERE job_id = %s", (job_id,)
        ).fetchone()
        conn.execute("DELETE FROM jobs WHERE job_id = %s", (job_id,))
        conn.commit()
    assert row[0] == "dead", "a denied retry must not requeue the job"
