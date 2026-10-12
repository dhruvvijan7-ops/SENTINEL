"""Stage-6 §5.2 metrics: the four named families are exposed, move on traffic,
and keep the label cardinality bounded (route *template*, not raw path)."""
from __future__ import annotations

import re

from sentinel_core.db import tx

from ..keys import KEY_A

_SAMPLE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>.*)\})?\s+"
    r"(?P<value>[-+0-9.eE]+|NaN|[-+]?Inf)$"
)
_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

FAMILIES = (
    "sentinel_http_requests_total",
    "sentinel_http_request_duration_seconds",
    "sentinel_jobs_queued",
    "sentinel_jobs_running",
)


def scrape(client) -> dict:
    r = client.get("/metrics")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/plain")
    assert "version=0.0.4" in r.headers["content-type"]
    helps, types, samples = set(), set(), {}
    for line in r.text.splitlines():
        if line.startswith("# HELP "):
            helps.add(line.split()[2])
            continue
        if line.startswith("# TYPE "):
            parts = line.split()
            types.add((parts[2], parts[3]))
            continue
        if not line or line.startswith("#"):
            continue
        m = _SAMPLE.match(line)
        if m is None:
            continue
        labels = {
            k: v.replace('\\"', '"').replace("\\\\", "\\")
            for k, v in _LABEL.findall(m.group("labels") or "")
        }
        samples.setdefault(m.group("name"), []).append(
            (labels, float(m.group("value")))
        )
    return {"help": helps, "types": types, "samples": samples, "text": r.text}


def value(s: dict, name: str, **want) -> float:
    for labels, val in s["samples"].get(name, []):
        if all(labels.get(k) == v for k, v in want.items()):
            return val
    return 0.0


def test_metrics_exposes_every_spec_5_2_family(client, app_settings):
    client.get("/health")
    s = scrape(client)
    for family in FAMILIES:
        assert family in s["help"], f"{family} has no # HELP line"
    assert ("sentinel_http_requests_total", "counter") in s["types"]
    assert ("sentinel_http_request_duration_seconds", "histogram") in s["types"]
    assert ("sentinel_jobs_queued", "gauge") in s["types"]
    assert ("sentinel_jobs_running", "gauge") in s["types"]


def test_latency_buckets_match_the_spec_5_2_proposed_set(client, app_settings):
    client.get("/health")
    s = scrape(client)
    les = {
        labels["le"]
        for labels, _ in s["samples"].get(
            "sentinel_http_request_duration_seconds_bucket", []
        )
    }
    assert "+Inf" in les, "histogram must expose the +Inf bucket"
    buckets = {float(le) for le in les if le != "+Inf"}
    assert buckets >= {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}, (
        f"latency buckets drifted from the spec §5.2 PROPOSED set: {sorted(buckets)}"
    )
    assert value(
        s, "sentinel_http_request_duration_seconds_count", route="/health", method="GET"
    ) >= 1


def test_request_counter_uses_the_route_template(client, app_settings):
    template = "/v1/workspaces/{workspaceId}/uploads"
    before = scrape(client)
    r = client.get(
        "/v1/workspaces/default/uploads", headers={"X-API-Key": KEY_A}
    )
    assert r.status_code == 200, r.text
    after = scrape(client)

    delta = value(
        after,
        "sentinel_http_requests_total",
        route=template,
        method="GET",
        status="200",
    ) - value(
        before,
        "sentinel_http_requests_total",
        route=template,
        method="GET",
        status="200",
    )
    assert delta >= 1, (
        "route-labelled request counter did not move; the label must be the "
        f"matched route template {template!r}, not the raw path"
    )
    assert value(
        after,
        "sentinel_http_requests_total",
        route="/v1/workspaces/default/uploads",
        method="GET",
        status="200",
    ) == 0.0, "raw path leaked into the route label"

    # Raw paths (ids, hashes) must never reach the label set: unbounded
    # cardinality.  Every recorded route is a template or a fixed surface.
    for name in ("sentinel_http_requests_total", "sentinel_http_request_duration_seconds_bucket"):
        for labels, _ in after["samples"].get(name, []):
            route = labels.get("route", "")
            assert not re.search(r"[0-9a-f]{32}", route), (
                f"{name} recorded a raw identifier as a route label: {route!r}"
            )
            assert route.startswith("/")


def test_health_requests_are_counted(client, app_settings):
    before = scrape(client)
    assert client.get("/health").status_code == 200
    after = scrape(client)
    delta = value(
        after, "sentinel_http_requests_total", route="/health", method="GET", status="200"
    ) - value(before, "sentinel_http_requests_total", route="/health", method="GET", status="200")
    assert delta >= 1


def test_rejected_upload_increments_the_rejection_counter(client, app_settings):
    before = scrape(client)
    r = client.post(
        "/v1/workspaces/default/uploads",
        files={"file": ("probe.bin", b"MZ", "application/octet-stream")},
        data={"note": "x" * 9000},  # > ingest.max_field_bytes (8192)
        headers={"X-API-Key": KEY_A},
    )
    assert r.status_code == 400, r.text
    assert r.json()["code"] == "GATE_FIELD_TOO_LARGE"
    after = scrape(client)
    delta = value(
        after, "sentinel_uploads_rejected_total", code="GATE_FIELD_TOO_LARGE"
    ) - value(before, "sentinel_uploads_rejected_total", code="GATE_FIELD_TOO_LARGE")
    assert delta >= 1, "gate rejection did not move sentinel_uploads_rejected_total"


def test_queue_gauges_reflect_the_real_depth(client, app_settings, migrated):
    import uuid as _uuid

    from sentinel_storage import repos_jobs

    key = f"metrics-probe:{_uuid.uuid4().hex}"
    with tx(migrated.database_worker_url) as conn:
        job_id = repos_jobs.enqueue(
            conn,
            tenant_id="default",
            workspace_id="default",
            job_type="noop",
            payload={},
            idempotency_key=key,
        )
        conn.commit()
    try:
        s = scrape(client)
        assert value(s, "sentinel_jobs_queued", type="noop") >= 1, (
            "sentinel_jobs_queued{type=...} missing after enqueue"
        )

        with tx(migrated.database_worker_url) as conn:
            jobs = repos_jobs.claim(
                conn, worker_id="metrics-probe", limit=1, job_types=("noop",)
            )
            conn.commit()
        assert [j.job_id for j in jobs] == [job_id]

        s = scrape(client)
        assert value(s, "sentinel_jobs_running", type="noop") >= 1, (
            "sentinel_jobs_running{type=...} missing while a lease is held"
        )
    finally:
        with tx(migrated.database_worker_url) as conn:
            conn.execute(
                "DELETE FROM jobs WHERE idempotency_key = %s", (key,)
            )
            conn.commit()
