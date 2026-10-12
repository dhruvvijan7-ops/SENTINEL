"""Native-path evaluator (Stage-5 §4.4).

Pure Python over already-prefiltered rows.  It evaluates the *whole*
condition — not just the constructs PostgreSQL could not decide — so the
conformance oracle can hand the same row set to the SQL compiler and to this
evaluator and require identical results (spec §12.1, tier T-C).

Semantics deliberately mirror ``compile.py``:

* wildcards ``*``/``?`` (with the spec's escape table) go through one shared
  scanner, and matching is implemented directly over that token stream so the
  two paths cannot drift on ``%``/``_``/``.`` interpretation;
* case-insensitivity lowers *both* sides (PostgreSQL ``lower()`` vs Python
  ``str.lower()``, ASCII-equivalent under the container's C collation);
* ``re`` uses RE2 with the same inline ``(?i)(?m)(?s)`` prefixes the compiler
  validates, never PostgreSQL ``~``;
* an absent field never satisfies a comparison; JSON null / ``$state`` null
  and the ``unmapped`` dash sentinels do (and only for a rule-level ``null``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from datetime import datetime
from typing import Any, Mapping, Sequence

from .compile import _regex_prefix, scan_pattern
from .condition import matching_identifiers, parse_condition
from .normalize import UNMAPPED_ROOT

_NUMERIC_RE = re.compile(r"^-?[0-9]+([.][0-9]+)?$")


@dataclass(frozen=True)
class Match:
    """One (event, finding time) pair — the same shape the SQL path selects."""

    event_uid: Any
    event: Mapping[str, Any]
    finding_time: datetime
    host_hostname: str | None
    user_name: str | None


def evaluate(
    document: Mapping[str, Any],
    events: Sequence[Any],
    *,
    event_for: Any = None,
) -> list[Match]:
    """Evaluate ``document``'s detection over ``events``.

    ``event_for`` maps a row to ``(event_uid, event_document, host, user,
    finding_time)``; by default a row is assumed to be exactly that tuple with
    the document at index 1.
    """
    detection = document["detection"]
    identifiers = {k: v for k, v in detection.items() if k != "condition"}
    node = parse_condition(detection["condition"])
    out: list[Match] = []
    for row in events:
        uid, doc, host, user, when = (event_for(row) if event_for else row)
        if _eval(node, identifiers, doc):
            out.append(
                Match(
                    event_uid=uid,
                    event=doc,
                    finding_time=when,
                    host_hostname=host,
                    user_name=user,
                )
            )
    return out


# --------------------------------------------------------------------------
# condition
# --------------------------------------------------------------------------


def _eval(node: Any, identifiers: Mapping[str, Any], doc: Mapping[str, Any]) -> bool:
    kind = node[0]
    if kind == "and":
        return _eval(node[1], identifiers, doc) and _eval(node[2], identifiers, doc)
    if kind == "or":
        return _eval(node[1], identifiers, doc) or _eval(node[2], identifiers, doc)
    if kind == "not":
        return not _eval(node[1], identifiers, doc)
    if kind == "ident":
        return _eval_identifier(identifiers[node[1]], doc)
    if kind == "of":
        names = sorted(matching_identifiers(node, list(identifiers)))
        hits = sum(1 for n in names if _eval_identifier(identifiers[n], doc))
        want = len(names) if node[1] in ("all", 0) else int(node[1])
        return hits >= want
    raise ValueError(f"unknown condition node {kind!r}")


# --------------------------------------------------------------------------
# field access
# --------------------------------------------------------------------------


def field_value(doc: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    """``(present, value)`` for a canonical path or ``unmapped.<SigmaField>``."""
    if path.startswith(UNMAPPED_ROOT + "."):
        name = path[len(UNMAPPED_ROOT) + 1:]
        entries = doc.get(UNMAPPED_ROOT)
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, Mapping) and entry.get("name") == name:
                    return True, entry.get("value")
        return False, None
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return False, None
        cur = cur[part]
    return True, cur


def _null_like(path: str, value: Any) -> bool:
    """Does this *present* value count as SQL ``NULL`` for this path?"""
    if value is None:
        return True
    if isinstance(value, Mapping) and value.get("$state") == "null":
        return True
    if path.startswith(UNMAPPED_ROOT + ".") and isinstance(value, str):
        return value in ("", "-")
    return False


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # PostgreSQL stores the document as jsonb, whose numbers are `numeric`
        # and whose text form never uses exponent notation: jsonb renders
        # 1e-05 as "0.00001", so the SQL path's guard
        # ``txt ~ '^-?[0-9]+([.][0-9]+)?$'`` matches and the comparison runs.
        # Python's str(1e-05) is "1e-05" (Stage-5 §4.4); with that text the
        # same guard failed and *every* numeric comparison against a
        # sub-1e-4 value — e.g. a 2 us flow duration against ``dur|lte: 5`` —
        # silently returned False on the native path only. Mirror jsonb so the
        # two paths see the same text (found by the UNSW-NB15 scoring run).
        try:
            return format(Decimal(str(value)), "f")
        except (InvalidOperation, ValueError):
            return str(value)
    import json

    return json.dumps(value, sort_keys=True, separators=(", ", ": "))


# --------------------------------------------------------------------------
# wildcard matching (shared semantics with the SQL LIKE emitter)
# --------------------------------------------------------------------------

def _core(text: str, tokens: Sequence[tuple[str, str]], ti: int, si: int, consume_all: bool) -> bool:
    while ti < len(tokens):
        kind, value = tokens[ti]
        if kind == "star":
            for skip in range(len(text) - si + 1):
                if _core(text, tokens, ti + 1, si + skip, consume_all):
                    return True
            return False
        if kind == "any":
            if si >= len(text):
                return False
            si += 1
            ti += 1
            continue
        if not text.startswith(value, si):
            return False
        si += len(value)
        ti += 1
    return si == len(text) if consume_all else True


@lru_cache(maxsize=65536)
def _lower(s: str) -> str:
    """Case-fold with an LRU: the same event text is matched against every
    value of every rule, and ``value.lower()`` alone was ~2 M calls/run."""
    return s.lower()


def _prepare(text: str, value: str, modifiers: set[str]) -> tuple[str, str]:
    if "cased" in modifiers:
        return text, value
    return _lower(text), _lower(value)


@lru_cache(maxsize=8192)
def _literal_of(value: str, cased: bool) -> str | None:
    """``value`` with escapes resolved (case-folded unless ``cased``), or
    ``None`` when it contains a wildcard.

    The token stream for a wildcard-free pattern is a plain concatenation of
    ``lit`` tokens, so the fast path in ``_matches``/``_match_with_mode`` is
    *exactly* ``_core``'s answer for that stream — only faster (C-level
    ``in``/``startswith`` instead of a per-offset recursive scan).  The pinned
    pack's biggest rules are 977-value ``contains`` lists (emoji usage) and
    this is what keeps them off both the quadratic scanner and a per-call
    re-scan of the pattern.
    """
    tokens = scan_pattern(value if cased else value.lower())
    if any(kind != "lit" for kind, _ in tokens):
        return None
    return "".join(text for _, text in tokens)


@lru_cache(maxsize=8192)
def _pattern_tokens(value: str, cased: bool) -> tuple[tuple[str, str], ...]:
    """Cached wildcard token stream (``None``-free twin of ``_literal_of``)."""
    return tuple(scan_pattern(value if cased else value.lower()))


def _matches(text: str, value: str, modifiers: set[str]) -> bool:
    """Equality semantics — what the SQL path renders as ``LIKE <pattern>``."""
    cased = "cased" in modifiers
    literal = _literal_of(value, cased)
    left = text if cased else _lower(text)
    if literal is not None:
        return left == literal
    return _core(left, _pattern_tokens(value, cased), 0, 0, True)


def _match_with_mode(text: str, value: str, modifiers: set[str]) -> bool:
    if "lt" in modifiers or "lte" in modifiers or "gt" in modifiers or "gte" in modifiers:
        left, right = _prepare(text, value, modifiers)
        if not _NUMERIC_RE.match(left.strip()) or not _NUMERIC_RE.match(right.strip()):
            return False
        a, b = float(left.strip()), float(right.strip())
        if "lt" in modifiers:
            return a < b
        if "lte" in modifiers:
            return a <= b
        if "gt" in modifiers:
            return a > b
        return a >= b

    cased = "cased" in modifiers
    if "neq" in modifiers:
        # SQL: (txt IS NOT NULL AND NOT (lower(txt) LIKE lower(value))); the
        # numeric block above keeps precedence, mirroring compile._text_predicate.
        return not _match_with_mode(text, value, modifiers - {"neq"})
    left = text if cased else _lower(text)
    literal = _literal_of(value, cased)
    if literal is not None:
        if "contains" in modifiers:
            return literal in left
        if "startswith" in modifiers:
            return left.startswith(literal)
        if "endswith" in modifiers:
            return left.endswith(literal)
        return left == literal

    tokens = _pattern_tokens(value, cased)
    if "contains" in modifiers:
        return any(_core(left, tokens, 0, start, False) for start in range(len(left) + 1))
    if "startswith" in modifiers:
        return _core(left, tokens, 0, 0, False)
    if "endswith" in modifiers:
        return any(_core(left, tokens, 0, start, True) for start in range(len(left) + 1))
    return _core(left, tokens, 0, 0, True)


def _regex_match(text: str, pattern: str, modifiers: set[str]) -> bool:
    import re2

    return re2.search(_regex_prefix(modifiers) + pattern, text) is not None


def _cidr_match(text: str, value: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(text.strip()) in ipaddress.ip_network(
            value.strip(), strict=False
        )
    except ValueError:
        return False


# --------------------------------------------------------------------------
# identifier evaluation
# --------------------------------------------------------------------------


def _eval_identifier(value: Any, doc: Mapping[str, Any]) -> bool:
    items = value if isinstance(value, list) else [value]
    results: list[bool] = []
    keywords: list[str] = []
    for item in items:
        if isinstance(item, str):
            keywords.append(item)
        elif isinstance(item, Mapping):
            results.append(_eval_predicate_map(item, doc))
        else:
            raise ValueError("search identifier items must be maps or keyword strings")
    results.extend(_keywords_present(_keyword_haystack(doc), keywords))
    return any(results) if results else False


def _keyword_haystack(doc: Mapping[str, Any]) -> str:
    raw = doc.get("raw")
    return raw if isinstance(raw, str) else ""


#: §4.5: Aho–Corasick once a keyword set is above this many needles
#: (``PROPOSED: 32``); below it a plain ``in`` wins because ``any``/
#: ``all`` short-circuit per needle instead of always walking the haystack.
_KEYWORD_AC_THRESHOLD = 32


@lru_cache(maxsize=64)
def _ac_automaton(needles: tuple[tuple[str, tuple[int, ...]], ...]):
    import ahocorasick

    automaton = ahocorasick.Automaton()
    for needle, positions in needles:
        automaton.add_word(needle, positions)
    automaton.make_automaton()
    return automaton


def _keywords_present(haystack: str, needles: Sequence[str]) -> list[bool]:
    """Which of ``needles`` occur in ``haystack`` (both case-folded).

    Mirrors the SQL path's ``strpos(lower(raw), lower(needle)) > 0`` exactly;
    only the *number of passes over the haystack* differs.
    """
    if not needles:
        return []
    lowered = [_lower(n) for n in needles]
    hay = _lower(haystack)
    if len(lowered) < _KEYWORD_AC_THRESHOLD:
        return [n in hay for n in lowered]

    positions: dict[str, list[int]] = {}
    for idx, needle in enumerate(lowered):
        positions.setdefault(needle, []).append(idx)
    hits = [not n for n in lowered]  # the empty needle is always present
    keys = tuple((k, tuple(v)) for k, v in positions.items() if k)
    for _, idxs in _ac_automaton(keys).iter(hay):
        for idx in idxs:
            hits[idx] = True
    return hits


def _eval_predicate_map(mapping: Mapping[str, Any], doc: Mapping[str, Any]) -> bool:
    clauses: list[bool] = []
    for key, raw_value in mapping.items():
        if key == "|all":
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            clauses.append(
                all(_keywords_present(_keyword_haystack(doc), [str(v) for v in values]))
            )
            continue
        field, _, mods = key.partition("|")
        modifiers = set(mods.split("|")) if mods else set()
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        clauses.append(_eval_field(field, modifiers, values, doc))
    return all(clauses) if clauses else False


def _eval_field(
    field: str, modifiers: set[str], values: Sequence[Any], doc: Mapping[str, Any]
) -> bool:
    present, raw = field_value(doc, field)

    if "exists" in modifiers:
        wanted = True
        if values:
            wanted = str(values[0]).lower() != "false"
        return present is wanted

    if not present:
        return False

    if "fieldref" in modifiers:
        left = _as_text(raw)
        if left is None:
            return False
        outcomes = []
        for ref in values:
            other_present, other = field_value(doc, str(ref))
            if not other_present:
                outcomes.append(False)
                continue
            right = _as_text(other)
            outcomes.append(right is not None and _matches(left, right, modifiers))
        return _combine(values, modifiers, outcomes)

    null_like = _null_like(field, raw)
    outcomes = [_value_matches(field, raw, null_like, value, modifiers) for value in values]
    return _combine(values, modifiers, outcomes)


def _combine(values: Sequence[Any], modifiers: set[str], outcomes: Sequence[bool]) -> bool:
    if not outcomes:
        return False
    if "all" in modifiers:
        return all(outcomes)
    return any(outcomes)


def _value_matches(
    field: str, raw: Any, null_like: bool, value: Any, modifiers: set[str]
) -> bool:
    if value is None:
        return null_like
    text = _as_text(raw)
    if text is None:
        return False
    if "cidr" in modifiers:
        return _cidr_match(text, str(value))
    if "re" in modifiers:
        return _regex_match(text, str(value), modifiers)
    return _match_with_mode(text, str(value), modifiers)
