"""CSV -> canonical `network_connection`: zero drops, schema-valid documents,
ground truth excluded, and the fast validator agrees with the schema gate
(spec §6.3a, M2 exit ⑥).

The corpus itself never enters this module — these are the committed synthetic
rows (§6.2: "the flow parser and the scoring harness are developed and
unit-tested against a committed synthetic fixture first"), so the mapper's
contract is enforced in every CI job, offline. `test_unsw_nb15_scoring.py`
then applies the same contract to all 257 673 real rows.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from sentinel_ingest.unsw_nb15 import (
    EXPECTED_COLUMNS,
    GROUND_TRUTH_COLUMNS,
    UnswRowError,
    count_rows,
    ground_truth,
    read_flows,
    row_to_document,
)
from tools.evaluate_unsw_nb15 import SCHEMA_PATH, _validator

SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
JSONSCHEMA = Draft202012Validator(SCHEMA)
FASTJSONSCHEMA = _validator()


def _row(**overrides: str) -> dict[str, str]:
    """A complete 45-column UNSW-NB15 row, as `csv.DictReader` yields it."""
    row = {column: "0" for column in EXPECTED_COLUMNS}
    row.update(
        {
            "id": "1",
            "dur": "0.000002",
            "proto": "tcp",
            "service": "http",
            "state": "FIN",
            "spkts": "2",
            "dpkts": "0",
            "sbytes": "200",
            "dbytes": "0",
            "rate": "111111.1111",
            "sttl": "254",
            "dttl": "0",
            "ct_state_ttl": "2",
            "ct_dst_src_ltm": "4",
            "attack_cat": "DoS",
            "label": "1",
        }
    )
    row.update(overrides)
    return row


def _document(row: dict[str, str], row_number: int = 1) -> dict[str, Any]:
    return row_to_document(
        row,
        row_number=row_number,
        tenant_id="tenant-b",
        workspace_id="ws-b",
        run_id="synthetic",
        file_id="synthetic.csv",
    )


# ---------------------------------------------------------------------------
# both validators agree, on acceptance and rejection
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({}, id="typical-attack-row"),
        pytest.param(
            {"service": "-", "dur": "0.000002", "rate": "100000.0025"},
            id = "dash-service + sub-microsecond duration",
        ),
        pytest.param(
            {"proto": "unas", "state": "REQ", "sbytes": "0", "dbytes": "-",
             "attack_cat": "Backdoor"},
            id="zero bytes",
        ),
        pytest.param(
            {"dur": "not-a-number", "attack_cat": "Normal", "label": "0"},
            id="corrupt numeric",
        ),
        pytest.param(
            {"service": "dns", "proto": "udp", "state": "INT",
             "attack_cat": "Generic"},
            id="dns flood shape",
        ),
    ],
)
def test_every_synthetic_row_maps_to_a_document_both_validators_accept(overrides):
    document = _document(_row(**overrides))
    JSONSCHEMA.validate(document)  # the authoritative gate (contract CI)
    FASTJSONSCHEMA(document)  # the 257k-row speed path must agree
    assert not ({entry["name"] for entry in document["unmapped"]} &
                set(GROUND_TRUTH_COLUMNS)), "ground truth leaked into unmapped[]"
    assert document["raw"]["label"] in ("0", "1")
    assert document["event"]["category"] == "network"
    assert document["event"]["type"] == "network_connection"


def test_both_validators_reject_the_same_document():
    """Agreement is checked in both directions, not only on the happy path."""
    document = _document(_row())
    document["label"] = "1"  # ground truth as a document key: additionalProperties
    assert list(JSONSCHEMA.iter_errors(document)), "jsonschema accepted a leak"
    with pytest.raises(Exception):
        FASTJSONSCHEMA(document)


def test_ground_truth_never_disagrees_with_itself():
    assert ground_truth(_row(label="1", attack_cat="Exploits")) == (1, "Exploits")
    assert ground_truth(_row(label="0", attack_cat="Normal")) == (0, "Normal")
    with pytest.raises(UnswRowError, match="label 0 with attack_cat"):
        ground_truth(_row(label="0", attack_cat="DoS"))
    with pytest.raises(UnswRowError, match="attack_cat Normal"):
        ground_truth(_row(label="1", attack_cat="Normal"))
    with pytest.raises(UnswRowError, match="label column"):
        ground_truth(_row(label="yes", attack_cat="DoS"))


# ---------------------------------------------------------------------------
# zero-drop contract: a row that cannot be mapped raises, it is never skipped
# ---------------------------------------------------------------------------
def test_a_missing_canonical_column_is_a_drop_not_a_skip():
    row = _row()
    del row["sbytes"]
    with pytest.raises(UnswRowError, match="missing column sbytes"):
        _document(row)


def test_a_row_without_a_flow_id_is_a_drop():
    with pytest.raises(UnswRowError, match="missing id"):
        _document(_row(id=""))


def test_invalid_numbers_become_state_objects_not_drops():
    """Unparseable *and* non-finite values are state objects, not JSON killers."""
    document = _document(_row(dur="NaN", sbytes="abc"))
    assert document["network"]["duration"]["$state"] == "invalid"
    assert document["network"]["bytes_sent"]["$state"] == "invalid"
    JSONSCHEMA.validate(document)
    FASTJSONSCHEMA(document)
    # A bare float NaN would serialise as `NaN` — invalid JSON that PostgreSQL
    # rejects on insert. allow_nan=False raises instead of hiding it.
    json.dumps(document, allow_nan=False)


# ---------------------------------------------------------------------------
# the reader enforces the pinned header and rejects ragged input
# ---------------------------------------------------------------------------
def _csv_text(rows: list[dict[str, str]], header: tuple[str, ...] | None = None) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=list(header or EXPECTED_COLUMNS), extrasaction="ignore"
    )
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def _read(tmp_path, text: str):
    path = tmp_path / "rows.csv"
    # newline="" : csv.writer already emitted \r\n, and text-mode write would
    # translate it again into \r\r\n (splitting every row into two records).
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    return path


def test_two_synthetic_rows_yield_two_documents(tmp_path):
    path = _read(tmp_path, _csv_text([_row(id="1"), _row(id="2", label="0",
                                                          attack_cat="Normal")]))
    records = list(read_flows(path, tenant_id="t", workspace_id="w", run_id="r",
                              file_id="f"))
    assert [record.row for record in records] == [1, 2]
    assert [record.label for record in records] == [1, 0]
    assert count_rows(path) == 2
    for record in records:
        JSONSCHEMA.validate(record.document)
        FASTJSONSCHEMA(record.document)


def test_a_foreign_header_is_refused(tmp_path):
    path = _read(tmp_path, _csv_text([_row()], header=("srcip", "dstip", "label")))
    with pytest.raises(UnswRowError, match="45-column header"):
        list(read_flows(path, tenant_id="t", workspace_id="w", run_id="r", file_id="f"))


def test_a_ragged_row_is_a_drop(tmp_path):
    """More values than the header: refuse the row, never shift fields."""
    extra = ",".join(str(index) for index in range(len(EXPECTED_COLUMNS) + 1))
    path = _read(tmp_path, _csv_text([_row()]) + extra + "\n")
    with pytest.raises(UnswRowError, match="ragged"):
        list(read_flows(path, tenant_id="t", workspace_id="w", run_id="r", file_id="f"))


def test_a_short_row_is_a_drop(tmp_path):
    """Too few columns: still a counted drop, never a partial document."""
    path = _read(tmp_path, _csv_text([_row()]) + "1,2\n")
    with pytest.raises(UnswRowError, match="label column"):
        list(read_flows(path, tenant_id="t", workspace_id="w", run_id="r", file_id="f"))


def test_an_empty_csv_is_a_drop(tmp_path):
    path = _read(tmp_path, "")
    with pytest.raises(UnswRowError, match="empty CSV"):
        list(read_flows(path, tenant_id="t", workspace_id="w", run_id="r", file_id="f"))


# ---------------------------------------------------------------------------
# the committed synthetic fixture (§6.3a): four rows the harness can score
# offline, so this contract never depends on a fetched corpus
# ---------------------------------------------------------------------------
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "synthetic_flows.csv"


def test_the_committed_synthetic_fixture_parses_with_zero_drops():
    assert FIXTURE.exists(), "the committed fixture is part of the contract"
    assert count_rows(FIXTURE) == 4
    records = list(
        read_flows(FIXTURE, tenant_id="tenant-b", workspace_id="ws-b",
                   run_id="synthetic", file_id=FIXTURE.name)
    )
    assert [record.row for record in records] == [1, 2, 3, 4]
    assert [record.label for record in records] == [1, 0, 1, 1]
    assert [record.attack_cat for record in records] == [
        "DoS", "Normal", "Generic", "Fuzzers",
    ]
    for record in records:
        JSONSCHEMA.validate(record.document)
        FASTJSONSCHEMA(record.document)
        assert not ({entry["name"] for entry in record.document["unmapped"]} &
                    set(GROUND_TRUTH_COLUMNS)), "ground truth leaked into unmapped[]"
    # row 1 carries the sub-microsecond duration that regressed once: the
    # committed bytes must round-trip to the plain decimal jsonb would hold.
    assert records[0].document["network"]["duration"] == 2e-06
    json.dumps(records[0].document, allow_nan=False)
