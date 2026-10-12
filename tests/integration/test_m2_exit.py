"""M2 exit gates — spec §9 (milestone M2), one test per circled criterion.

Exit ①  planted EVTX → exactly one finding carrying the manifest's
        ``fingerprint``, ``detection_path`` and rule identity (§6.3).
Exit ②  the evidence snapshot survives the raw object being purged (§1.5,
        reject-condition R1) and still carries everything §1.5 requires.
Exit ③  timeline p95 under the 2 s budget at 10⁵ events (§6.6); ``slow``,
        because it runs ``tools/bench/timeline_bench.py`` end to end.
Exit ④  cold-start is never silent: ``BASELINE_MISSING`` / ``BASELINE_WARMUP``
        account for a statistical rule that has no valid baseline (§4.8).

The golden values live in ``tests/planted/manifest.json`` and are regenerated
by ``python -m tests.m2_drill`` — never edited by hand.  The drill itself is
shared (``tests/m2_drill.py``) so the golden block and the assertions are
produced by the same code path.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import uuid
from typing import Any

import pytest

from sentinel_core.db import tx

from .. import m2_drill
from ..keys import KEY_B

ROOT = m2_drill.ROOT
PLANTED_RULE = (
    m2_drill.PLANTED_DIR / "rules" / "windows" / "process_creation"
    / "proc_creation_win_susp_whoami_as_param.yml"
)
PINNED_PACK = ROOT / "configs" / "rule_pack.json"

#: A committed, schema-valid ``kind: statistical`` rule with no baseline rows
#: anywhere — the §4.8 cold-start subject.
COLD_START_RULE = (
    ROOT / "tests" / "fixtures" / "rules" / "stage5"
    / "5e6f7a8b_9c0d_4e1f_2a3b_4c5d6e7f8a5f.yaml"
)


@pytest.fixture
def manifest() -> dict[str, Any]:
    return m2_drill.load_manifest()


@pytest.fixture
def drill(app_settings, client, manifest):
    """The full planted drill (purges on entry and on exit)."""
    result = m2_drill.run_drill(app_settings, client)
    yield result
    m2_drill.purge(app_settings)


# ---------------------------------------------------------------------------
# Fixture integrity — the bytes the golden block was measured against
# ---------------------------------------------------------------------------
def test_planted_fixture_is_the_recorded_bytes(manifest):
    fixture = ROOT / manifest["fixture"]["path"]
    assert fixture.is_file(), f"planted fixture missing: {fixture}"
    data = fixture.read_bytes()
    assert len(data) == manifest["fixture"]["bytes"]
    assert hashlib.sha256(data).hexdigest() == manifest["fixture"]["sha256"]
    assert m2_drill.PLANTED_EVTX == fixture


def test_planted_fixture_parses_to_the_planted_command_line(manifest):
    from sentinel_ingest.evtx_parser import ParseStats, iter_envelopes

    stats = ParseStats()
    planted = None
    for envelope in iter_envelopes(
        str(m2_drill.PLANTED_EVTX),
        tenant_id="tenant-b",
        workspace_id="ws-b",
        run_id="parse-probe",
        file_id="f" * 32,
        file_sha256="0" * 64,
        stats=stats,
    ):
        record = envelope["source"]["record"]
        if record.get("record_id") == m2_drill.PLANT_RECORD_ID:
            planted = envelope
    assert planted is not None, "record 1742 is not in the committed fixture"
    assert f"<Data Name=\"CommandLine\">{m2_drill.PLANTED_CMDLINE}</Data>" in planted["raw"]
    assert stats.parse_errors == 0
    assert stats.records_total == manifest["fixture"]["records"]
    assert stats.events_mapped == manifest["fixture"]["events_mapped"]
    assert stats.unmapped_eid == manifest["fixture"]["unmapped_eid"]


def test_committed_rule_is_byte_identical_to_the_pinned_pack_entry(manifest):
    """The fixture cannot drift away from ``configs/rule_pack.json``."""
    text = PLANTED_RULE.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert digest == manifest["rule"]["sha256"]
    assert digest == manifest["rule"]["pinned_pack"]["entry_sha256"]

    pinned = json.loads(PINNED_PACK.read_text(encoding="utf-8"))
    entry = [r for r in pinned["rules"] if r["path"] == manifest["rule"]["path"]]
    assert len(entry) == 1, "planted rule is no longer a member of the pinned pack"
    assert entry[0]["sha256"] == digest
    assert pinned["pack_sha256"] == manifest["rule"]["pinned_pack"]["pack_sha256"]
    assert pinned["source"]["commit"] == manifest["rule"]["upstream"]["commit"]


def test_planted_pack_manifest_is_self_consistent(manifest):
    from sentinel_detect.sigma_import import load_pack_manifest

    pack = load_pack_manifest(m2_drill.PACK_PATH)
    assert pack.count == manifest["pack"]["count"] == 1
    assert pack.pack_sha256 == manifest["pack"]["pack_sha256"]
    assert pack.source_commit == manifest["rule"]["upstream"]["commit"]
    assert pack.paths() == [manifest["rule"]["path"]]


def test_plant_tool_reproduces_the_committed_fixture(manifest):
    """``tools/plant_fixture.py --check`` is the drift gate for the plant.

    It needs the (gitignored) source corpus, so it only runs where the corpus
    has been fetched — the committed bytes themselves are pinned by
    ``test_planted_fixture_is_the_recorded_bytes`` either way.
    """
    corpus = ROOT / ".corpus" / "evtx-rs" / "sysmon.evtx"
    if not corpus.is_file():
        pytest.skip("source corpus not fetched (tools/corpus_fetch.py)")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "plant_fixture.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0, f"{proc.stdout}{proc.stderr}"


# ---------------------------------------------------------------------------
# Exit ① — planted EVTX ⇒ the manifest's finding
# ---------------------------------------------------------------------------
def test_m2_exit_1_planted_finding_matches_the_manifest(app_settings, drill, manifest):
    expected = manifest["expected"]
    finding = drill["finding"]

    assert finding["rule_id"] == expected["rule_id"] == manifest["rule"]["rule_id"]
    assert finding["fingerprint"] == expected["fingerprint"]
    assert finding["detection_path"] == expected["detection_path"] == "sql"
    assert finding["severity"] == expected["severity"]
    assert finding["level_original"] == expected["level_original"]
    assert finding["time_utc"] == expected["time_utc"]
    assert finding["host_hostname"] == expected["host_hostname"]
    assert finding["user_name"] == expected["user_name"]
    assert finding["occurrence_count"] == expected["occurrence_count"]
    assert finding["reason_codes"] == expected["reason_codes"] == []
    assert finding["event_uids"] == expected["event_uids"]
    assert finding["event_uids"] == [str(m2_drill.planted_event_uid())]
    assert finding["triage_state"] == "new"

    # The run that produced it: declared config, and a clean (no-warnings) status.
    with tx(app_settings.database_worker_url) as conn:
        row = conn.execute(
            "SELECT encode(config_hash, 'hex'), status FROM detection_runs WHERE run_id = %s",
            (finding["run_id"],),
        ).fetchone()
    assert row is not None
    assert row[0] == expected["config_hash"]
    assert row[1] == "completed"


def test_m2_exit_1_finding_is_served_by_the_api(app_settings, client, drill, manifest):
    expected = manifest["expected"]
    headers = {"X-API-Key": KEY_B}

    listing = client.get("/v1/workspaces/ws-b/findings", headers=headers)
    assert listing.status_code == 200, listing.text
    items = listing.json()["items"]
    assert len(items) == 1, f"expected one finding, got {len(items)}"
    body = items[0]
    assert body["fingerprint"] == expected["fingerprint"]
    assert body["detection_path"] == "sql"
    assert body["event_uids"] == expected["event_uids"]
    assert body["run_id"] == drill["detect_run_id"]

    detail = client.get(
        f"/v1/workspaces/ws-b/findings/{body['finding_uid']}", headers=headers
    )
    assert detail.status_code == 200
    assert detail.json()["fingerprint"] == expected["fingerprint"]
    assert detail.json()["evidence_snapshot"]["rule"]["source_sha256"] == (
        expected["rule_source_sha256"]
    )


# ---------------------------------------------------------------------------
# Exit ② — evidence survives the raw object
# ---------------------------------------------------------------------------
def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _evidence(client, finding_uid: str) -> dict[str, Any]:
    response = client.get(
        f"/v1/workspaces/ws-b/evidence/{finding_uid}",
        headers={"X-API-Key": KEY_B},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_m2_exit_2_evidence_outlives_the_raw_object(app_settings, client, drill, manifest):
    expected = manifest["expected"]
    finding_uid = drill["finding"]["finding_uid"]
    sha_bytes = m2_drill.planted_sha256_bytes()

    # Before: the raw object is hot and rides along with the snapshot.
    hot = _evidence(client, finding_uid)
    assert hot["finding_uid"] == finding_uid
    assert hot["raw_state"] == "hot"
    assert hot["raw_object"]["sha256"] == sha_bytes.hex()
    snapshot = hot["evidence_snapshot"]

    with tx(app_settings.database_worker_url) as conn:
        conn.execute(
            "UPDATE raw_objects SET state = 'purged', purged_at = now(), refcount = 0"
            " WHERE sha256 = %s",
            (sha_bytes,),
        )
        conn.commit()

    # After: the object is gone, the snapshot is not (§1.5 / R1).
    purged = _evidence(client, finding_uid)
    assert purged["raw_state"] == "purged"
    assert "raw_object" not in purged
    assert purged["evidence_snapshot"] == snapshot, "purging the raw object changed the snapshot"

    # And the snapshot still carries every §1.5 element, pinned to the manifest.
    assert snapshot["schema_version"] == expected["evidence_schema_version"]
    rule = snapshot["rule"]
    assert rule["source_sha256"] == expected["rule_source_sha256"]
    assert rule["source_sha256"] == manifest["rule"]["sha256"]
    assert rule["source_ref"].endswith(f":{manifest['rule']['path']}")
    assert snapshot["run"]["config_hash"] == expected["config_hash"]
    assert [event["event_uid"] for event in snapshot["events"]] == expected["event_uids"]
    finding = snapshot["finding"]
    assert finding["fingerprint"] == expected["fingerprint"]
    assert finding["detection_path"] == "sql"
    assert finding["rule_id"] == expected["rule_id"]

    # The two digests that cannot be golden (they cover ``provenance`` and the
    # per-run ids) are instead recomputed from the stored rows: that is the
    # property the snapshot exists for.
    from sentinel_detect.evidence import canonical_json

    with tx(app_settings.database_worker_url) as conn:
        document = conn.execute(
            "SELECT document FROM rules WHERE tenant_id = %s AND workspace_id = %s"
            "   AND rule_id = %s",
            (m2_drill.TENANT_ID, m2_drill.WORKSPACE_ID, expected["rule_id"]),
        ).fetchone()[0]
        events = conn.execute(
            "SELECT event_uid, document FROM events WHERE tenant_id = %s"
            "   AND workspace_id = %s",
            (m2_drill.TENANT_ID, m2_drill.WORKSPACE_ID),
        ).fetchall()
    assert rule["document_sha256"] == _digest(canonical_json(document))
    stored = {str(uid): doc for uid, doc in events}
    for event in snapshot["events"]:
        assert event["event_uid"] in stored, event
        assert event["sha256"] == _digest(canonical_json(stored[event["event_uid"]]))

    # Last stage of R1: the events themselves are gone too — the snapshot is
    # then the whole evidence of record, and the bundle simply has no raw arm.
    with tx(app_settings.database_worker_url) as conn:
        conn.execute(
            "DELETE FROM events WHERE tenant_id = %s AND workspace_id = %s",
            (m2_drill.TENANT_ID, m2_drill.WORKSPACE_ID),
        )
        conn.commit()
    orphan = _evidence(client, finding_uid)
    assert "raw_object" not in orphan
    assert "raw_state" not in orphan
    assert orphan["evidence_snapshot"] == snapshot


def test_m2_exit_2_triage_update_keeps_the_snapshot(app_settings, client, drill, manifest):
    finding_uid = drill["finding"]["finding_uid"]
    before = _evidence(client, finding_uid)["evidence_snapshot"]

    response = client.patch(
        f"/v1/workspaces/ws-b/findings/{finding_uid}",
        json={"triage_state": "acknowledged", "note": "M2 exit 2 drill"},
        headers={"X-API-Key": KEY_B},
    )
    assert response.status_code == 200, response.text
    assert response.json()["triage_state"] == "acknowledged"
    assert response.json()["evidence_snapshot"] == before
    assert _evidence(client, finding_uid)["evidence_snapshot"] == before


# ---------------------------------------------------------------------------
# Exit ④ — cold start is accounted for, never silent (§4.8)
# ---------------------------------------------------------------------------
def _import_cold_start_rule(app_settings) -> dict[str, Any]:
    """Load the committed ``kind: statistical`` rule into the drill workspace."""
    import yaml

    from sentinel_detect.sigma_import import (
        IMPORTED,
        CompiledRule,
        insert_rule,
        validate_document,
    )

    text = COLD_START_RULE.read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    validate_document(document)
    document["provenance"] = {
        "pack_id": m2_drill.PACK_ID,
        "pack_version": m2_drill.load_manifest()["pack"]["pack_version"],
        "repo_commit": "",
        "imported_by": "test",
    }
    rule = CompiledRule(
        document=document,
        compile_block=dict(document.get("compile") or {}),
        outcome=IMPORTED,
        reason_codes=(),
        source_text=text,
        source_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )
    with tx(app_settings.database_worker_url) as conn:
        insert_rule(conn, m2_drill.TENANT_ID, m2_drill.WORKSPACE_ID, rule)
        conn.commit()
    return document


def _run_statistical_rule(app_settings, harvest_run_id: str, rule_id: str) -> dict[str, Any]:
    """One detect run scoped to a single rule over the planted harvest run."""
    from sentinel_detect.runner import run_detection
    from sentinel_storage import repos_detect

    scope = {"harvest_run_id": harvest_run_id, "rule_ids": [rule_id]}
    with tx(app_settings.database_worker_url) as conn:
        run_id = repos_detect.create_run(
            conn,
            tenant_id=m2_drill.TENANT_ID,
            workspace_id=m2_drill.WORKSPACE_ID,
            requested_by="test:m2-exit-4",
            scope=scope,
            config_hash=b"\x00" * 32,
        )
        result = run_detection(
            conn,
            run_id=run_id,
            tenant_id=m2_drill.TENANT_ID,
            workspace_id=m2_drill.WORKSPACE_ID,
            requested_by="test:m2-exit-4",
            scope=scope,
        )
        conn.commit()
    return result


def _rule_runs(app_settings, run_id: str) -> list[dict[str, Any]]:
    from sentinel_storage.repos_detect import list_rule_runs

    with tx(app_settings.database_worker_url) as conn:
        return list_rule_runs(conn, uuid.UUID(run_id))


def test_m2_exit_4_missing_baseline_is_reported(app_settings, drill):
    document = _import_cold_start_rule(app_settings)
    rule_id = str(document["id"])

    result = _run_statistical_rule(app_settings, drill["run_id"], rule_id)

    assert result["status"] == "completed_with_warnings", result
    assert result["rules_suppressed"] == 1, result
    assert result["findings"] == 0, result
    assert "BASELINE_MISSING" in result["reason_codes"], result

    runs = _rule_runs(app_settings, result["run_id"])
    assert len(runs) == 1, runs
    assert runs[0]["outcome"] == "skipped", runs
    assert "BASELINE_MISSING" in list(runs[0]["reason_codes"] or []), runs
    assert int(runs[0]["findings"]) == 0


def test_m2_exit_4_warmup_baseline_is_reported(app_settings, drill):
    document = _import_cold_start_rule(app_settings)
    rule_id = str(document["id"])
    min_observations = int(document["statistical"]["baseline"]["min_observations"])

    # A baseline exists but has not observed enough buckets yet (§4.8 / §9.3).
    with tx(app_settings.database_worker_url) as conn:
        conn.execute(
            "INSERT INTO rule_baseline (tenant_id, workspace_id, rule_id,"
            " baseline_key, bucket_start, bucket_span, observations)"
            " VALUES (%s, %s, %s, %s, %s, interval '1 day', %s)",
            (
                m2_drill.TENANT_ID,
                m2_drill.WORKSPACE_ID,
                rule_id,
                json.dumps({"host.agent_id": "*"}),
                "2026-10-12T00:00:00+00:00",
                min_observations - 1,
            ),
        )
        conn.commit()

    result = _run_statistical_rule(app_settings, drill["run_id"], rule_id)

    assert result["status"] == "completed_with_warnings", result
    assert result["rules_suppressed"] == 1, result
    assert "BASELINE_WARMUP" in result["reason_codes"], result
    assert "BASELINE_MISSING" not in result["reason_codes"], result

    runs = _rule_runs(app_settings, result["run_id"])
    assert runs[0]["outcome"] == "skipped", runs
    assert "BASELINE_WARMUP" in list(runs[0]["reason_codes"] or []), runs


def test_m2_exit_4_a_valid_baseline_lifts_the_suppression(app_settings, drill):
    """§4.8/§9.3: once the baseline is valid the cold-start gate opens.

    This pins the *classification* layer only.  Executing a statistical rule
    (the §9.1 window engine) is outside M2 — no ``date_bin``/bucket evaluator
    exists yet — so the rule is deliberately never handed to ``run_detection``
    here; what exit ④ claims is that suppression is governed by the baseline,
    not that the window query itself has been implemented.
    """
    from sentinel_detect.runner import _prepare
    from sentinel_detect.store import DbRuleStore

    document = _import_cold_start_rule(app_settings)
    rule_id = str(document["id"])
    min_observations = int(document["statistical"]["baseline"]["min_observations"])

    with tx(app_settings.database_worker_url) as conn:
        rules = [r for r in DbRuleStore(conn).load(m2_drill.TENANT_ID, m2_drill.WORKSPACE_ID)
                 if str(r["rule_id"]) == rule_id]
        assert len(rules) == 1, rules

        runnable, suppressed = _prepare(
            conn, rules, m2_drill.TENANT_ID, m2_drill.WORKSPACE_ID
        )
        assert runnable == [], suppressed
        assert [str(r[0]) for r in suppressed] == [rule_id]
        assert suppressed[0][1] == ["BASELINE_MISSING"]

        conn.execute(
            "INSERT INTO rule_baseline (tenant_id, workspace_id, rule_id,"
            " baseline_key, bucket_start, bucket_span, observations)"
            " VALUES (%s, %s, %s, %s, %s, interval '1 day', %s)",
            (
                m2_drill.TENANT_ID,
                m2_drill.WORKSPACE_ID,
                rule_id,
                json.dumps({"host.agent_id": "*"}),
                "2026-10-12T00:00:00+00:00",
                min_observations,
            ),
        )
        conn.commit()

        runnable, suppressed = _prepare(
            conn, rules, m2_drill.TENANT_ID, m2_drill.WORKSPACE_ID
        )
        assert suppressed == [], suppressed
        assert [str(r["rule_id"]) for r in runnable] == [rule_id]


# ---------------------------------------------------------------------------
# Exit ③ — the timeline stays inside its render budget (§6.6)
# ---------------------------------------------------------------------------
@pytest.mark.slow
def test_m2_exit_3_timeline_budget(tmp_path):
    out = tmp_path / "timeline_m2.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "bench" / "timeline_bench.py"),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert out.is_file(), f"bench wrote no artifact: {proc.stdout}{proc.stderr}"
    artifact = json.loads(out.read_text(encoding="utf-8"))

    assert proc.returncode == 0, proc.stderr
    assert artifact["pass"] is True, artifact
    assert artifact["p95_ms"] < artifact["budget_ms"], artifact
    assert artifact["rows_rendered"] >= 100_000, artifact
    assert artifact["scale"]["events"] == 100_000, artifact["scale"]
    assert artifact["cleanup"]["events"] == 100_000, artifact["cleanup"]
    # The environment stanza must be populated, not a null-filled placeholder.
    assert artifact["environment"]["ram_bytes"], artifact["environment"]
    assert artifact["database"]["server_version"].startswith("PostgreSQL"), artifact
