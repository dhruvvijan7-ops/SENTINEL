"""Scored run against the real UNSW-NB15 corpus — M2 exit ⑥ gate
(spec §9b row ⑥, §6.3a "run summary reports F1 + per-category recall").

The corpus is fetched out-of-tree (D6-009) and sha-pinned; `conftest.py`
fails — never skips — when it is absent. Thresholds below are the numbers
**measured** on 2026-10-12 with the pack frozen at `tests/scoring/rules/*`:
thresholds were chosen on the *training* split, and the *testing* split is
what the gate reports (§6.3a: "thresholds chosen on the training split; the
scored run reports the testing split"). A regression below a floor fails the
gate; a rule change that moves the numbers upward is allowed and the floor
is then re-pinned from the new report.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from tools.evaluate_unsw_nb15 import (
    CITATION_TOKEN,
    DEFAULT_REPORT,
    MANIFEST,
    PINNED,
    verify_corpus,
)

ATTACK_CATEGORIES = {
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
}

#: (metric key) -> floor (f1/precision/recall) or ceiling (fpr/per-category).
#: train was tuned, test is reported; see the module docstring.
BASELINES: dict[str, dict[str, float]] = {
    "train": {"f1": 0.90, "precision": 0.94, "recall": 0.87, "fpr": 0.10,
              "min_category_recall": 0.50},
    "test": {"f1": 0.86, "precision": 0.82, "recall": 0.92, "fpr": 0.25,
             "min_category_recall": 0.70},
}


# ---------------------------------------------------------------------------
# pins + attribution are part of the gate (§6.3a)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("split", ["train", "test"])
def test_corpus_is_pinned_and_attributed(split: str):
    path, expected = verify_corpus(split)
    assert path.exists()
    assert expected["rows"] == PINNED[path.name]["rows"]


def test_the_fetch_manifest_carries_the_citation():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert CITATION_TOKEN in manifest["citation"], "attribution is part of the gate"
    assert manifest["files"], "manifest lists no files"


# ---------------------------------------------------------------------------
# zero-drop contract over every real row (§6.3a)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("split", ["train", "test"])
def test_every_row_became_a_schema_valid_document(scoring_run, split: str):
    result = scoring_run["splits"][split]
    assert result["rows"] == PINNED[_name(split)]["rows"], "row count != pin"
    assert result["dropped"] == 0, f"{split}: {result['dropped']} rows dropped"
    assert result["invalid_documents"] == 0, (
        f"{split}: {result['invalid_documents']} documents failed "
        f"canonical_event_v1.schema.json: {result.get('first_error')}"
    )
    assert result["documents"] == result["rows"]


def _name(split: str) -> str:
    return "UNSW_NB15_training-set.csv" if split == "train" else "UNSW_NB15_testing-set.csv"


# ---------------------------------------------------------------------------
# the measured baseline: F1, precision, recall, FPR and per-category recall
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("split", sorted(BASELINES))
def test_scored_run_meets_the_measured_baseline(scoring_run, split: str):
    result = scoring_run["splits"][split]
    binary = result["binary"]
    floors = BASELINES[split]
    assert binary["f1"] >= floors["f1"], (
        f"{split}: F1 {binary['f1']:.4f} < {floors['f1']} (pack regression)"
    )
    assert binary["precision"] >= floors["precision"], (
        f"{split}: precision {binary['precision']:.4f} < {floors['precision']}"
    )
    assert binary["recall"] >= floors["recall"], (
        f"{split}: recall {binary['recall']:.4f} < {floors['recall']}"
    )
    assert binary["fpr"] <= floors["fpr"], (
        f"{split}: FPR {binary['fpr']:.4f} > {floors['fpr']} "
        "(false positives on the Normal class went over budget)"
    )
    assert 0.0 <= binary["f1"] <= 1.0 and round(binary["f1"], 6) == binary["f1"]


@pytest.mark.parametrize("split", sorted(BASELINES))
def test_every_attack_category_is_scored_against_the_baseline(scoring_run, split: str):
    result = scoring_run["splits"][split]
    per_category = result["per_category_recall"]
    assert set(per_category) == ATTACK_CATEGORIES, (
        f"{split}: scored categories {sorted(per_category)}"
    )
    floor = BASELINES[split]["min_category_recall"]
    worst = min(per_category, key=per_category.__getitem__)
    assert per_category[worst] >= floor, (
        f"{split}: {worst} recall {per_category[worst]:.4f} < {floor} "
        f"(per-category: {per_category})"
    )
    assert result["normal_rows"] > 0, "FPR needs a Normal baseline"


# ---------------------------------------------------------------------------
# evidence artefact the audit cites (§6.6: numbers ship MEASURED)
# ---------------------------------------------------------------------------
def test_the_evidence_report_is_written_and_attributed(scoring_run):
    report = DEFAULT_REPORT
    assert report.exists(), f"missing scored-run report {report}"
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["dataset"] == "UNSW-NB15"
    assert CITATION_TOKEN in (payload["citation"] or "")
    assert payload["pack"]["rule_count"] >= 6
    assert set(payload["splits"]) == {"train", "test"}
    for split, result in payload["splits"].items():
        assert result["sha256"] == PINNED[_name(split)]["sha256"]
        assert result["dropped"] == 0 and result["invalid_documents"] == 0
        assert set(result["per_category_recall"]) == ATTACK_CATEGORIES
        assert "seconds" in result and result["seconds"] > 0
    assert payload["environment"]["python"]


def test_every_rule_fired_and_the_pack_is_not_dead_weight(scoring_run: dict[str, Any]):
    """A rule that never fires is not coverage — each one must earn its place."""
    fires = scoring_run["splits"]["test"]["per_rule_fires"]
    assert fires, "no rule fired on the testing split"
    for source_id in scoring_run["pack"]["rules"]:
        assert fires.get(source_id, 0) > 0, f"{source_id} never fired"
    per_rule = scoring_run["splits"]["test"]["per_rule_attack_vs_normal"]
    # every rule must catch at least some attacks (precision alone is not a rule)
    for source_id, counts in per_rule.items():
        assert counts["on_attack"] > 0, f"{source_id} only ever fired on Normal"
