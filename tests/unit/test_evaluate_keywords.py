"""Native evaluator fast paths (spec §4.5 keyword sets, §4.6 cost budget).

Both fast paths exist for throughput only, so every test here pins the fast
answer against the slow, obviously-correct answer — a fast path that drifts
from the token-stream matcher would silently desynchronise the SQL and native
paths and destroy the §12.1 conformance oracle.
"""
from __future__ import annotations

import pytest

import sentinel_detect.evaluate as evaluate
from sentinel_detect.compile import MAX_SQL_BYTES, plan, scan_pattern
from sentinel_detect.evaluate import (
    _KEYWORD_AC_THRESHOLD,
    _core,
    _eval_identifier,
    _eval_predicate_map,
    _keywords_present,
    _match_with_mode,
    _matches,
)


def _reference_matches(text: str, value: str, modifiers: set[str]) -> bool:
    """Equality semantics as the token-stream scanner computes them."""
    left, right = (text, value) if "cased" in modifiers else (text.lower(), value.lower())
    return _core(left, scan_pattern(right), 0, 0, True)


def _reference_with_mode(text: str, value: str, modifiers: set[str]) -> bool:
    """Mode semantics as the token-stream scanner computes them."""
    left, right = (text, value) if "cased" in modifiers else (text.lower(), value.lower())
    if "contains" in modifiers:
        tokens = scan_pattern(right)
        return any(_core(left, tokens, 0, s, False) for s in range(len(left) + 1))
    if "startswith" in modifiers:
        return _core(left, scan_pattern(right), 0, 0, False)
    if "endswith" in modifiers:
        tokens = scan_pattern(right)
        return any(_core(left, tokens, 0, s, True) for s in range(len(left) + 1))
    return _core(left, scan_pattern(right), 0, 0, True)


# ---------------------------------------------------------------------------
# §4.5 keyword sets — Aho–Corasick above the threshold, plain scan below
# ---------------------------------------------------------------------------
HAYSTACK = "C:\\Windows\\System32\\cmd.exe /c whoami & powershell.exe -enc SQBFAFgA"
PLAIN_NEEDLES = [f"needle{i:02d}" for i in range(_KEYWORD_AC_THRESHOLD - 4)]
BIG_NEEDLES = [f"needle{i:02d}" for i in range(_KEYWORD_AC_THRESHOLD + 8)]
PRESENT = ["cmd.exe", "powershell", "System32", "whoami"]


def _expected(haystack: str, needles: list[str]) -> list[bool]:
    lower = haystack.lower()
    return [n.lower() in lower for n in needles]


def test_below_the_threshold_uses_the_plain_scan():
    assert len(PLAIN_NEEDLES) < _KEYWORD_AC_THRESHOLD
    assert _keywords_present(HAYSTACK, PLAIN_NEEDLES) == _expected(HAYSTACK, PLAIN_NEEDLES)


def test_above_the_threshold_uses_aho_corasick_and_agrees():
    needles = BIG_NEEDLES + PRESENT + ["definitely-absent"]
    assert len(needles) > _KEYWORD_AC_THRESHOLD
    assert _keywords_present(HAYSTACK, needles) == _expected(HAYSTACK, needles)


def test_duplicate_needles_all_report_present():
    needles = ["cmd.exe"] * (_KEYWORD_AC_THRESHOLD + 3)
    assert _keywords_present(HAYSTACK, needles) == [True] * len(needles)


def test_empty_needle_is_present_and_never_reaches_the_automaton():
    needles = [""] + [f"n{i:02d}" for i in range(_KEYWORD_AC_THRESHOLD + 2)]
    got = _keywords_present("", needles)
    assert got[0] is True
    assert got[1:] == _expected("", needles[1:])


def test_keywords_present_is_case_folded_like_the_sql_path():
    needles = ["PoWeRsHeLl"] + [f"n{i:02d}" for i in range(_KEYWORD_AC_THRESHOLD)]
    assert _keywords_present(HAYSTACK, needles)[0] is True


def test_eval_identifier_accepts_keywords_and_predicate_maps():
    doc = {"raw": "cmd.exe /c net user", "process": {"command_line": "cmd.exe /c net user"}}
    assert _eval_identifier(["cmd.exe", "net user"], doc) is True
    assert _eval_identifier(["nope", "cmd.exe"], doc) is True
    assert _eval_identifier(["nope", "nada"], doc) is False
    assert _eval_identifier([{"process.command_line|contains": "cmd"}], doc) is True
    assert _eval_identifier([{"process.command_line|contains": "nope"}], doc) is False


def test_eval_identifier_rejects_non_string_non_map_items():
    with pytest.raises(ValueError, match="keyword strings"):
        _eval_identifier([42], {"raw": "x"})


def test_all_modifier_over_a_large_keyword_set():
    doc = {"raw": " ".join(PRESENT)}
    mapping = {"|all": PRESENT + [f"n{i:02d}" for i in range(_KEYWORD_AC_THRESHOLD)]}
    assert _eval_predicate_map(mapping, doc) is False  # the nNN needles are absent
    mapping = {"|all": PRESENT}
    assert _eval_predicate_map(mapping, doc) is True


# ---------------------------------------------------------------------------
# literal fast path — must be exactly what the token stream would answer
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("text", "value", "modifiers"),
    [
        ("C:\\Windows\\cmd.exe", "cmd.exe", set()),
        ("C:\\Windows\\cmd.exe", "cmd.exe", {"contains"}),
        ("C:\\Windows\\cmd.exe", "C:\\Windows", {"startswith"}),
        ("C:\\Windows\\cmd.exe", "cmd.exe", {"endswith"}),
        ("C:\\Windows\\cmd.exe", "CMD.EXE", {"contains"}),
        ("C:\\Windows\\cmd.exe", "CMD.EXE", {"contains", "cased"}),
        ("star * literal", "star * literal", {"contains"}),
        ("question ? literal", "question ? literal", {"contains"}),
        ("back\\slash", "back\\slash", {"contains"}),
        ("100", "100", set()),
        ("100%", "100%", {"contains"}),
        ("100%", "100", {"startswith"}),
        ("a_b", "a_b", set()),
        ("", "", set()),
        ("cmd.exe", "*.exe", {"contains"}),
        ("cmd.exe", "cmd.???", set()),
        ("cmd.exe", "cmd.*", {"startswith"}),
    ],
)
def test_literal_and_wildcard_paths_agree_with_the_token_stream(
    text: str, value: str, modifiers: set[str]
) -> None:
    assert _matches(text, value, modifiers) == _reference_matches(text, value, modifiers)
    assert _match_with_mode(text, value, modifiers) == _reference_with_mode(text, value, modifiers)


@pytest.mark.parametrize(
    ("modifiers", "expected"),
    [
        (set(), False),  # equality: the whole field must equal the value
        ({"contains"}, True),
        ({"startswith"}, False),
        ({"endswith"}, False),
        ({"contains", "cased"}, True),  # MIDDLE is already upper in the text
    ],
)
def test_wildcard_free_value_bypasses_the_token_stream(
    modifiers: set[str], expected: bool, monkeypatch
) -> None:
    """A literal value must be decidable without walking every start offset
    — the whole reason the fast path exists (the pack's 977-value ``contains``
    lists were costing seconds per rule)."""
    def boom(*_args, **_kwargs):
        raise AssertionError("token stream scanned for a wildcard-free value")

    monkeypatch.setattr(evaluate, "_core", boom)
    assert _match_with_mode("prefixMIDDLEsuffix", "MIDDLE", modifiers) is expected
    assert _matches("MIDDLE", "middle", set()) is True  # case-folded equality


# ---------------------------------------------------------------------------
# §4.6 cost budget — over-budget statements run natively but stay compiled
# ---------------------------------------------------------------------------
def _over_budget_document(value_count: int = 900) -> dict:
    return {
        "title": "A rule whose compiled statement is deliberately enormous",
        "id": "00000000-0000-4000-8000-000000000001",
        "status": "test",
        "level_original": "medium",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "CommandLine|contains": [f"marker{i:05d}" for i in range(value_count)],
            },
            "condition": "selection",
        },
    }


def test_over_budget_statement_flips_to_native_but_keeps_the_full_sql():
    block, params = plan(_over_budget_document())
    assert len(block["sql"]) > MAX_SQL_BYTES
    assert block["detection_path"] == "native"
    assert block["fallback_reason"] == "COST_BUDGET_EXCEEDED"
    # the statement is still the *complete* one, so the conformance oracle can
    # execute it — and its bind slots still line up with the returned params
    assert block["sql"].count("%s") == len(params)
    assert " AND (" in block["sql"]


def test_a_small_rule_stays_on_the_sql_path():
    block, params = plan(_over_budget_document(value_count=3))
    assert len(block["sql"]) < MAX_SQL_BYTES
    assert block["detection_path"] == "sql"
    assert block["fallback_reason"] is None
    assert block["sql"].count("%s") == len(params)


def test_compile_block_carries_no_unschemaed_keys():
    """``rule_schema.json`` freezes the ``compile`` object as
    ``additionalProperties: false`` — an extra key fails L1 validation."""
    allowed = {
        "detection_path", "sql", "fallback_reason", "cost_class", "prefilter",
        "compiled_at", "engine_version", "unsupported",
    }
    for doc in (_over_budget_document(), _over_budget_document(3)):
        block, _ = plan(doc)
        assert set(block) <= allowed, set(block) - allowed
