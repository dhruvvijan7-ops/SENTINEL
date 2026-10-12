"""Native-path float text must equal what PostgreSQL extracts from jsonb
(spec §12.1 T-C conformance, §4.4 native evaluator).

The two paths decide the *same* comparison over the *same* document, so they
must see the same text: PostgreSQL stores ``document`` as ``jsonb`` and
extracts numbers as ``numeric``, whose output never uses exponent notation,
while Python's ``str(1e-05)`` is ``"1e-05"``.  Before this was pinned, a
numeric modifier against any sub-1e-4 value (a 2 µs flow duration against
``dur|lte: 5``) matched on the SQL path and silently failed on the native
path — found by the UNSW-NB15 scoring run (M2 exit ⑥).
"""
from __future__ import annotations

import pytest

from sentinel_detect.compile import plan
from sentinel_detect.evaluate import _as_text, _NUMERIC_RE, evaluate
from sentinel_detect.normalize import normalize_rule

CASES = [
    (1e-05, "0.00001"),
    (2e-06, "0.000002"),
    (0.121478, "0.121478"),
    (2.0, "2.0"),
    (1e21, "1000000000000000000000"),
    (0.0, "0.0"),
    (5, "5"),
    (100000, "100000"),
]


@pytest.mark.parametrize("value,expected", CASES, ids=[str(c[0]) for c in CASES])
def test_numeric_text_is_plain_decimal_like_jsonb(value, expected):
    assert _as_text(value) == expected
    assert _NUMERIC_RE.match(expected), (
        f"jsonb-style text {expected!r} must satisfy the shared numeric guard"
    )


def _duration_rule():
    return normalize_rule(
        {
            "title": "Sub-second flow",
            "id": "sentinel-unit-tiny-duration",
            "logsource": {"category": "network_connection", "product": "unsw-nb15"},
            "detection": {
                "sel_short": {"dur|lte": 5},
                "condition": "sel_short",
            },
        }
    )


def _document(duration: float):
    return {
        "event": {"category": "network", "type": "network_connection"},
        "network": {"duration": duration},
    }


def test_tiny_duration_satisfies_the_numeric_comparison():
    """The regression itself: 2 µs must satisfy ``dur|lte: 5``."""
    normalized = _duration_rule()
    matches = evaluate(normalized.document, [("row-16", _document(2e-06), "", "", None)])
    assert [m.event_uid for m in matches] == ["row-16"]
    assert _eval_matches(normalized, _document(1e-05))
    assert not _eval_matches(normalized, _document(5.5))


def _eval_matches(normalized, document):
    return bool(evaluate(normalized.document, [("u", document, "", "", None)]))


def test_the_sql_path_guards_the_same_text_the_native_path_compares():
    """The SQL side of the pair: jsonb text goes through the same regex."""
    normalized = _duration_rule()
    block, _params = plan(normalized.document)
    sql = block["sql"]
    assert "::numeric" in sql, "numeric modifiers compile to a ::numeric cast"
    assert _NUMERIC_RE.pattern in sql, (
        "the SQL guard is the very regex the native path applies to _as_text"
    )
