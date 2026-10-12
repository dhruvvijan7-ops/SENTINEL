"""Pack lint: the scored rules must be engine-compilable and must never be
able to read the ground truth they are scored against (spec §6.3a).

A rule that matched `label`/`attack_cat` — or the verbatim `raw` row, which is
where those two columns live inside a document — would score itself. The lint
fails the pack instead, so the reported precision is a property of the
*detection logic*, not of a leak.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

RULES_DIR = Path(__file__).resolve().parent / "rules"
RULE_PATHS = sorted(RULES_DIR.glob("*.yml"))

#: Document keys carrying ground truth; `raw` is the verbatim CSV row.
FORBIDDEN_FIELDS = {"label", "attack_cat", "raw"}
#: The only non-fatal reason code a scoring rule may carry: the feature
#: columns with no canonical home are read through `unmapped[]` by design.
ALLOWED_CODES = {"UNMAPPED_FIELD"}


def _raw(path: Path) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{path.name}: rule is not a mapping"
    return doc


def _field_names(node: Any) -> set[str]:
    """Every Sigma field name used anywhere under a detection subtree."""
    names: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key not in ("condition",):
                names.add(key.split("|", 1)[0])
            names |= _field_names(value)
    elif isinstance(node, list):
        for item in node:
            names |= _field_names(item)
    return names


def test_the_pack_is_the_scored_pack():
    assert RULE_PATHS, "no rules in tests/scoring/rules"
    assert len(RULE_PATHS) >= 6, (
        "the scored pack shrank below its measured size: "
        + ", ".join(p.name for p in RULE_PATHS)
    )


def test_source_ids_are_unique(pack):
    ids = [source_id for source_id, _doc, _codes in pack]
    assert len(ids) == len(set(ids)), f"duplicate source_id in pack: {ids}"
    assert len(ids) == len(RULE_PATHS)


def test_every_rule_targets_the_unsw_pipeline():
    for path in RULE_PATHS:
        raw = _raw(path)
        assert raw.get("logsource") == {
            "category": "network_connection",
            "product": "unsw-nb15",
        }, f"{path.name}: logsource must select the unsw_nb15_network_flow pipeline"


def test_detection_never_reads_ground_truth(pack):
    for source_id, document, _codes in pack:
        fields = _field_names(document.get("detection", {}))
        leaked = fields & FORBIDDEN_FIELDS
        assert not leaked, (
            f"{source_id}: detection reads ground-truth fields {sorted(leaked)}"
        )


def test_no_rule_reads_the_verbatim_row_in_the_source_yaml():
    for path in RULE_PATHS:
        raw = _raw(path)
        fields = _field_names(raw.get("detection", {}))
        leaked = fields & FORBIDDEN_FIELDS
        assert not leaked, f"{path.name}: detection reads {sorted(leaked)}"


def test_only_unmapped_field_reason_codes(pack):
    for source_id, _document, codes in pack:
        unexpected = {code["code"] for code in codes} - ALLOWED_CODES
        assert not unexpected, (
            f"{source_id}: unexpected reason codes {sorted(unexpected)} — a "
            "scoring rule must compile on the SQL path too"
        )


def test_every_rule_compiles_on_the_sql_path(pack):
    """`load_pack` already ran `plan()`; re-assert it here as the gate."""
    from sentinel_detect.compile import plan

    for source_id, document, codes in pack:
        block, params = plan(document, unsupported=list(codes))
        assert block["sql"], f"{source_id}: no SQL emitted"
        assert block["detection_path"] in ("sql", "native")


@pytest.mark.parametrize("path", RULE_PATHS, ids=lambda p: p.name)
def test_rule_metadata_is_present(path: Path):
    raw = _raw(path)
    for key in ("title", "id", "status", "description", "author", "license",
                "date", "logsource", "detection", "falsepositives", "level",
                "tags"):
        assert key in raw, f"{path.name}: missing `{key}`"
    assert raw["level"] in ("informational", "low", "medium", "high", "critical")
    assert any(str(tag).startswith("attack.") for tag in raw["tags"]), (
        f"{path.name}: tags must carry the attack class it scores"
    )
    assert "condition" in raw["detection"]
