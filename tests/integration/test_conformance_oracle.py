"""M2 exit ⑤ - the dual-path conformance oracle gate (spec §9b).

Exit ⑤: *the conformance oracle runs on the golden corpus with zero
unexplained divergences*.  ``tools/conformance_oracle.py`` compiles every
corpus rule twice - through the SQL compiler and through the native
evaluator - runs both over the same events and requires identical finding
sets.  Two classes of difference are allowed and are asserted to be exactly
the registered ones: native-only rules (``re`` / ``fieldref`` / ``cidr`` /
bare keywords) and ``COST_BUDGET_EXCEEDED`` over-budget statements.

The corpus itself, its provenance and its DRL-1.1 licence obligations are in
``tests/conformance/ATTRIBUTION.md``; ``expected.json`` pins each rule file's
sha256 and its compiled classification so an accidental edit, an upstream
re-fetch or a compiler behaviour change fails here rather than silently.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from sentinel_core.db import tx

ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = ROOT / "tools" / "conformance_oracle.py"
CONFORMANCE_DIR = ROOT / "tests" / "conformance"

#: Floors measured on the committed corpus (16 of 19 comparable rules fire).
#: They are deliberately below the measurement so a new fixture or rule does
#: not flake the gate, while a synthesizer/compiler regression still fails it.
MIN_RULES = 23
MIN_COMPARABLE = 19
MIN_SQL_FIRED = 10
MIN_MATCHED_PAIRS = 50


def _load_oracle():
    spec = importlib.util.spec_from_file_location("sentinel_conformance_oracle", ORACLE_PATH)
    assert spec is not None and spec.loader is not None, f"oracle missing: {ORACLE_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def oracle():
    return _load_oracle()


# ---------------------------------------------------------------------------
# no-database gates (cheap, run in every job that collects this directory)
# ---------------------------------------------------------------------------
def test_attribution_record_names_the_licence_and_the_pin():
    attribution = CONFORMANCE_DIR / "ATTRIBUTION.md"
    assert attribution.is_file(), "tests/conformance/ATTRIBUTION.md is the licence record"
    text = attribution.read_text(encoding="utf-8")
    assert "DRL 1.1" in text and "DRL-1.1" in text
    assert "8a4813404ea3074890e0cda9272d4d1a8b2941d6" in text
    assert "SigmaHQ/sigma" in text


def test_corpus_and_expected_manifest_agree(oracle):
    rules = oracle.load_corpus()
    assert len(rules) >= MIN_RULES, "the committed corpus shrank"
    manifest = oracle.expected_manifest(rules)
    committed = oracle.load_expected()
    assert committed == manifest, (
        "tests/conformance/expected.json is stale - a rule file changed or the "
        "compiler's classification moved; regenerate with "
        "python tools/conformance_oracle.py --write-expected and review the diff"
    )


def test_every_corpus_rule_keeps_its_attribution(oracle):
    """DRL 1.1: attribution travels with the rule, so it may never be stripped."""
    manifest = oracle.load_expected()
    missing = [name for name, entry in manifest["rules"].items() if not entry["author"].strip()]
    assert not missing, f"rules without an author: {sorted(missing)}"


def test_comparable_and_native_only_split_is_registered(oracle):
    for rule in oracle.load_corpus():
        if rule.comparable:
            assert rule.reason in oracle.COMPARABLE_REASONS
        else:
            assert rule.reason in oracle.KNOWN_NATIVE_REASONS, (
                f"{rule.name} fell back for an unregistered reason {rule.reason!r}"
            )


# ---------------------------------------------------------------------------
# the oracle itself - needs PostgreSQL, rolls back
# ---------------------------------------------------------------------------
def test_conformance_oracle_reports_zero_divergences(app_settings):
    oracle = _load_oracle()
    rules = oracle.load_corpus()
    with tx(app_settings.database_worker_url) as conn:
        report = oracle.run_oracle(conn, rules=rules)

    assert report["divergences"] == [], (
        "SQL and native paths disagree:\n"
        + "\n".join(str(d) for d in report["divergences"])
    )
    assert report["pass"] is True
    assert report["rules"] >= MIN_RULES
    assert report["comparable"] >= MIN_COMPARABLE
    assert report["native_only"] == report["rules"] - report["comparable"]
    assert report["fired"]["sql"] >= MIN_SQL_FIRED, (
        "too few comparable rules matched - the event synthesizer lost signal:\n"
        + "\n".join(f"  {r['rule']}: sql={r['sql']}" for r in report["per_rule"])
    )
    assert report["fired"]["native"] >= MIN_SQL_FIRED
    assert report["matched_pairs"] >= MIN_MATCHED_PAIRS
    for item in report["intentional"]:
        assert item["reason"] in oracle.KNOWN_NATIVE_REASONS, item
        assert item["detection_path"], item
