"""Rule document → SQL and native compile (Stage-5 L3).

The output is the engine-owned ``compile`` block stored on the rule:

* ``sql`` — a complete ``SELECT`` over ``events`` whose only bind slots are the
  three scope parameters (tenant, workspace, run ids) plus one ``%s`` per rule
  value.  Spec §4.4: *compiled SQL is parameterized — values bound as
  parameters, never string-interpolated* (invariant 7).  Stored as evidence
  and executed verbatim at runtime (never re-parsed);
* ``detection_path`` — ``sql`` unless some referenced search-identifier needs
  the native evaluator (``re`` / ``fieldref`` / ``cidr`` / keyword search);
* ``cost_class``, ``prefilter``, ``unsupported``, ``fallback_reason``.

``plan(document)`` returns both the block and the ordered parameter list; the
list is recomputed from the stored document at runtime by ``compile_params``,
so the evidence row needs nowhere to hide it.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from .condition import matching_identifiers, parse_condition
from .normalize import UNMAPPED_ROOT
from .store import ENGINE_VERSION

#: document-path → physical column (prefilter columns are stored in the
#: document-path form; only the SQL rendering knows the table alias).
_COLUMN_ALIASES: dict[str, str] = {
    "event.category": "e.event_category",
    "event.type": "e.event_type",
    "event.action": "e.event_action",
    "event.outcome": "e.event_outcome",
    "event.severity": "e.event_severity",
    "event.derived_by": "e.event_derived_by",
    "classification": "e.classification",
    "source.channel": "e.source_channel",
    "source.provider": "e.source_provider",
    "source.event_id": "e.source_event_id",
    "source.format": "e.source_format",
    "host.hostname": "e.host_hostname",
    "user.name": "e.user_name",
}

#: Paths whose scan cost is dominated by long text (§11 cost classes).
_HEAVY_MARKERS = ("script_block_text", "script_text")

_NUMERIC_RE = re.compile(r"^-?[0-9]+([.][0-9]+)?$")

#: §4.6 cost budget, expressed as compiled-statement size.  PostgreSQL must
#: parse and plan every distinct statement, and that cost is linear in the
#: statement text (~14 µs/byte MEASURED on the pinned pack: the four
#: emoji-usage rules emit 274–368 KiB and cost ~19 s of a 30 s detect run).
#: A statement over this budget still runs — but through the native evaluator
#: with ``COST_BUDGET_EXCEEDED``; the SQL itself stays in the compile block as
#: evidence and is what the conformance oracle executes (§4.6 never silently
#: drops a rule, and §12.1 still needs both paths comparable).
MAX_SQL_BYTES = 64 * 1024


class CompileError(ValueError):
    """The document cannot be compiled (importer records REJECTED)."""


# --------------------------------------------------------------------------
# pattern expansion (shared by the SQL emitter and the native evaluator)
# --------------------------------------------------------------------------

def scan_pattern(value: str) -> list[tuple[str, str]]:
    """Sigma value → ``[('lit', text) | ('any', '') | ('star', '')]``.

    Implements the spec's escape table: ``\\*``/``\\?``/``\\\\`` are literals,
    a lone ``\\`` before anything else stays a literal backslash, and the
    unescaped ``*``/``?`` become wildcards.
    """
    out: list[tuple[str, str]] = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == "\\" and i + 1 < n and value[i + 1] in "*?\\":
            out.append(("lit", value[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(("star", ""))
            i += 1
            continue
        if ch == "?":
            out.append(("any", ""))
            i += 1
            continue
        out.append(("lit", ch))
        i += 1
    return out


def like_pattern(value: str) -> str:
    """Sigma value → PostgreSQL ``LIKE`` body (``%``/``_``/``\\`` escaped)."""
    parts: list[str] = []
    for kind, text in scan_pattern(value):
        if kind == "star":
            parts.append("%")
        elif kind == "any":
            parts.append("_")
        else:
            for ch in text:
                parts.append("\\" + ch if ch in "\\%_" else ch)
    return "".join(parts)


def regex_pattern(value: str) -> str:
    """Sigma value → regular-expression body with ``*``/``?`` expanded."""
    import re as _re

    parts: list[str] = []
    for kind, text in scan_pattern(value):
        if kind == "star":
            parts.append(".*")
        elif kind == "any":
            parts.append(".")
        else:
            parts.append(_re.escape(text))
    return "".join(parts)


# --------------------------------------------------------------------------
# SQL fragments — every rule-derived string arrives through ``params``
# --------------------------------------------------------------------------

def _bind(params: list[Any], value: Any) -> str:
    if value is None:
        raise CompileError("cannot bind a NULL rule value as a SQL parameter")
    if isinstance(value, str) and "\x00" in value:
        raise CompileError("rule value contains a NUL byte")
    params.append(value)
    return "%s"


def _path_literal(path: str) -> str:
    """Structural JSON path.  Config-derived (``map_field`` output), never raw
    rule text, so it stays inline and the planner can constant-fold it."""
    inner = ",".join('"' + p.replace('"', '\\"') + '"' for p in path.split("."))
    return "'" + "{" + inner + "}" + "'"


def _unmapped_name(path: str) -> str:
    return path[len(UNMAPPED_ROOT) + 1:]


def _element_source(path: str) -> tuple[str, str]:
    """``(text expression, FROM fragment)`` for one path.

    The array/scalar CASE makes a single-valued field and a multi-valued field
    behave identically; an absent path yields one JSON-null element whose text
    is SQL NULL, so "absent" never satisfies a comparison.
    """
    if path.startswith(UNMAPPED_ROOT + "."):
        frm = (
            " FROM jsonb_array_elements(CASE WHEN jsonb_typeof(e.document->'unmapped') = 'array'"
            " THEN e.document->'unmapped' ELSE '[]'::jsonb END) AS t(el)"
        )
        return "t.el->>'value'", frm
    pl = _path_literal(path)
    frm = (
        f" FROM jsonb_array_elements(CASE WHEN jsonb_typeof(e.document #> {pl}) = 'array'"
        f" THEN e.document #> {pl} ELSE jsonb_build_array(e.document #> {pl}) END) AS t(el)"
    )
    txt = "(CASE WHEN jsonb_typeof(t.el) IN ('object','array') THEN t.el::text"
    txt += " ELSE t.el #>> '{}' END)"
    return txt, frm


def _element_extra(path: str, params: list[Any]) -> str:
    """Bind the ``unmapped.<Field>`` name predicate (empty for canonical paths)."""
    if path.startswith(UNMAPPED_ROOT + "."):
        return " AND t.el->>'name' = " + _bind(params, _unmapped_name(path))
    return ""


def _exists_sql(path: str, wanted: bool, params: list[Any]) -> str:
    if path.startswith(UNMAPPED_ROOT + "."):
        inner = (
            " EXISTS (SELECT 1 FROM jsonb_array_elements("
            "CASE WHEN jsonb_typeof(e.document->'unmapped') = 'array'"
            " THEN e.document->'unmapped' ELSE '[]'::jsonb END) AS t(el)"
            " WHERE t.el->>'name' = " + _bind(params, _unmapped_name(path)) + ")"
        )
    else:
        inner = f" (e.document #> {_path_literal(path)}) IS NOT NULL"
    return inner if wanted else "NOT " + inner


def _null_predicate(path: str) -> str:
    if path.startswith(UNMAPPED_ROOT + "."):
        return "(t.el->>'value' IS NULL OR t.el->>'value' IN ('','-'))"
    return (
        "(jsonb_typeof(t.el) = 'null'"
        " OR (jsonb_typeof(t.el) = 'object' AND t.el @> '{\"$state\":\"null\"}'::jsonb))"
    )


def _text_predicate(txt: str, value: Any, modifiers: set[str], params: list[Any]) -> str:
    cased = "cased" in modifiers
    if value is None:
        raise CompileError("null values are routed to the null predicate")
    if not isinstance(value, str):
        value = str(value)
    body = value if cased else value.lower()
    left = txt if cased else f"lower({txt})"

    if modifiers & {"lt", "lte", "gt", "gte"}:
        if not _NUMERIC_RE.match(value.strip()):
            raise CompileError(f"numeric modifier applied to non-numeric value {value!r}")
        op = next(
            o for m, o in (("lt", "<"), ("lte", "<="), ("gt", ">"), ("gte", ">=")) if m in modifiers
        )
        guard = f"{txt} ~ '{_NUMERIC_RE.pattern}'"
        return f"({guard} AND ({txt})::numeric {op} {_bind(params, float(value.strip()))})"

    pattern = like_pattern(body)
    if "neq" in modifiers:
        return f"({txt} IS NOT NULL AND NOT ({left} LIKE {_bind(params, pattern)}))"
    if "startswith" in modifiers:
        return f"({left} LIKE {_bind(params, pattern + '%')})"
    if "endswith" in modifiers:
        return f"({left} LIKE {_bind(params, '%' + pattern)})"
    if "contains" in modifiers:
        return f"({left} LIKE {_bind(params, '%' + pattern + '%')})"
    return f"({left} LIKE {_bind(params, pattern)})"


def _keyword_sql(value: str, params: list[Any]) -> str:
    return (
        "strpos(lower(COALESCE(e.document->>'raw','')), lower("
        + _bind(params, value)
        + ")) > 0"
    )


def _leaf_sql(path: str, modifiers: set[str], value: Any, params: list[Any]) -> str:
    if "exists" in modifiers:
        wanted = str(value).lower() != "false" if value is not None else True
        return _exists_sql(path, wanted, params)
    txt, frm = _element_source(path)
    if value is None:
        # The name predicate is load-bearing: without it a null value on one
        # unmapped Sigma field would match *any* unmapped entry holding '-'
        # (the dash sentinel), which the native path does not do.
        return (
            "EXISTS (SELECT 1"
            + frm
            + " WHERE "
            + _null_predicate(path)
            + _element_extra(path, params)
            + ")"
        )
    cond = _text_predicate(txt, value, modifiers, params)
    extra = _element_extra(path, params)
    return f"EXISTS (SELECT 1{frm} WHERE {cond}{extra})"


def _combine(parts: list[str], modifiers: set[str]) -> str:
    if not parts:
        raise CompileError("empty value list")
    if len(parts) == 1:
        return parts[0]
    joiner = " AND " if "all" in modifiers else " OR "
    return "(" + joiner.join(parts) + ")"


def _predicate_map_sql(mapping: Mapping[str, Any], params: list[Any]) -> str:
    parts: list[str] = []
    for key, value in mapping.items():
        if key == "|all":
            values = value if isinstance(value, list) else [value]
            parts.append(
                _combine(
                    [_keyword_sql(str(v), params) for v in values], {"all"}
                )
            )
            continue
        field, _, mods = key.partition("|")
        modifiers = set(mods.split("|")) if mods else set()
        values = value if isinstance(value, list) else [value]
        parts.append(
            _combine(
                [_leaf_sql(field, modifiers, v, params) for v in values], modifiers
            )
        )
    if not parts:
        raise CompileError("predicate map has no keys")
    if len(parts) == 1:
        return parts[0]
    return "(" + " AND ".join(parts) + ")"


def _identifier_sql(value: Any, params: list[Any]) -> str:
    items = value if isinstance(value, list) else [value]
    parts: list[str] = []
    for item in items:
        if isinstance(item, Mapping):
            parts.append(_predicate_map_sql(item, params))
        elif isinstance(item, str):
            parts.append(_keyword_sql(item, params))
        else:
            raise CompileError("search identifier items must be maps or keyword strings")
    if not parts:
        raise CompileError("empty search identifier")
    if len(parts) == 1:
        return parts[0]
    return "(" + " OR ".join(parts) + ")"


# --------------------------------------------------------------------------
# native-path detection & validation
# --------------------------------------------------------------------------

def _modifiers_of(key: str) -> set[str]:
    _, _, mods = key.partition("|")
    return set(mods.split("|")) if mods else set()


def identifier_needs_native(value: Any) -> bool:
    """True when the SQL path cannot decide this search-identifier alone."""
    items = value if isinstance(value, list) else [value]
    for item in items:
        if isinstance(item, str):
            return True  # keyword scan over the whole event
        if not isinstance(item, Mapping):
            continue
        for key in item:
            if key == "|all":
                return True
            if _modifiers_of(key) & {"re", "fieldref", "cidr"}:
                return True
    return False


def _regex_prefix(modifiers: set[str]) -> str:
    return (
        ("(?i)" if "i" in modifiers else "")
        + ("(?m)" if "m" in modifiers else "")
        + ("(?s)" if "s" in modifiers else "")
    )


#: The spec's restricted regex flavour (Stage-5 §4.7 L1) on top of RE2:
#: groups, classes, quantifiers, anchors and alternation — never back
#: references or look-around.
_FLAVOUR_BANNED = re.compile(r"\\[1-9]|\\k|\(\?<?[=!]|''\(\?P?<")


def validate_regexes(
    document: Mapping[str, Any], unsupported: list[dict[str, str]]
) -> None:
    """L1 regex lint: restricted flavour *and* RE2 must both accept."""
    import re2

    detection = document.get("detection") or {}
    for ident, value in detection.items():
        if ident == "condition":
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if not isinstance(item, Mapping):
                continue
            for key, raw in item.items():
                if key == "|all" or "re" not in _modifiers_of(key):
                    continue
                mods = _modifiers_of(key)
                prefix = _regex_prefix(mods)
                values = raw if isinstance(raw, list) else [raw]
                for pattern in values:
                    if not isinstance(pattern, str):
                        continue
                    if _FLAVOUR_BANNED.search(prefix + pattern):
                        unsupported.append(
                            {
                                "code": "UNSUPPORTED_REGEX_CONSTRUCT",
                                "detail": f"restricted flavour rejects {pattern!r}",
                                "selector": ident,
                            }
                        )
                        continue
                    try:
                        re2.compile(prefix + pattern)
                    except Exception as exc:  # noqa: BLE001 - re2 raises several types
                        unsupported.append(
                            {
                                "code": "UNSUPPORTED_REGEX_CONSTRUCT",
                                "detail": f"{pattern!r}: {exc}",
                                "selector": ident,
                            }
                        )


# --------------------------------------------------------------------------
# prefilter
# --------------------------------------------------------------------------

def _selector_sql(
    selector: Mapping[str, Any], params: list[Any]
) -> tuple[str, list[dict[str, Any]]]:
    clauses: list[str] = []
    entries: list[dict[str, Any]] = []
    for column, value in selector.items():
        values = value if isinstance(value, list) else [value]
        text_values = [str(v) for v in values]
        op = "in" if len(text_values) > 1 else "eq"
        entries.append({"column": str(column), "op": op, "values": text_values})
        target = _COLUMN_ALIASES.get(str(column))
        if target is None:
            target = "e.document #>> " + _path_literal(str(column))
        if op == "eq":
            clauses.append(f"{target} = {_bind(params, text_values[0])}")
        else:
            slots = ", ".join(_bind(params, v) for v in text_values)
            clauses.append(f"{target} IN ({slots})")
    if not clauses:
        return "", []
    return " AND " + " AND ".join(clauses), entries


def _cost_class(
    document: Mapping[str, Any], path: str, prefilter: list[dict[str, Any]]
) -> str:
    if document.get("kind") == "correlation":
        return "window"
    detection = document.get("detection") or {}
    for ident, value in detection.items():
        if ident == "condition":
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, str):
                return "heavy"
            if isinstance(item, Mapping):
                for key in item:
                    if key == "|all":
                        return "heavy"
                    field = key.split("|", 1)[0]
                    if any(marker in field for marker in _HEAVY_MARKERS):
                        return "heavy"
    if path == "sql" and prefilter:
        return "prefilter"
    return "standard"


def _pipeline_selector(document: Mapping[str, Any]) -> dict[str, Any]:
    from .pipelines import default_registry

    pipeline = default_registry().select(document.get("logsource"))
    return dict(pipeline.selector) if pipeline else {}


def _fallback_reason(identifiers: Mapping[str, Any], referenced: set[str]) -> str:
    have_re = have_fieldref = have_keyword = False
    for name in referenced:
        items = (
            identifiers[name] if isinstance(identifiers[name], list) else [identifiers[name]]
        )
        for item in items:
            if isinstance(item, str):
                have_keyword = True
                continue
            if not isinstance(item, Mapping):
                continue
            for key in item:
                if key == "|all":
                    have_keyword = True
                    continue
                mods = _modifiers_of(key)
                have_re |= "re" in mods
                have_fieldref |= "fieldref" in mods or "cidr" in mods
    if have_re:
        return "REGEX_NATIVE_ONLY"
    if have_fieldref:
        return "FIELDREF_NATIVE_ONLY"
    if have_keyword:
        return "KEYWORD_NATIVE_ONLY"
    return "NATIVE_BY_COMPILE"


# --------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------

def plan(
    document: Mapping[str, Any],
    *,
    unsupported: Iterable[Mapping[str, str]] = (),
    engine_version: str = ENGINE_VERSION,
) -> tuple[dict[str, Any], list[Any]]:
    """Build ``(compile block, ordered parameter list)`` for a rule document."""
    codes: list[dict[str, str]] = [dict(u) for u in unsupported]
    validate_regexes(document, codes)

    detection = document.get("detection")
    if not isinstance(detection, Mapping) or "condition" not in detection:
        raise CompileError("document has no detection.condition")
    condition = detection["condition"]
    try:
        node = parse_condition(condition)
    except Exception as exc:  # ConditionError
        raise CompileError(f"condition not parseable: {exc}") from exc

    identifiers = {k: v for k, v in detection.items() if k != "condition"}
    referenced = matching_identifiers(node, list(identifiers))
    missing = referenced - set(identifiers)
    if missing:
        raise CompileError(f"condition references undefined identifiers {sorted(missing)}")

    needs_native = any(identifier_needs_native(identifiers[name]) for name in referenced)
    detection_path = "native" if needs_native else "sql"

    # Bind order follows text order: scope, then selector, then predicate.
    selector_params: list[Any] = []
    selector_sql, prefilter = _selector_sql(_pipeline_selector(document), selector_params)

    _HEAD = (
        "SELECT e.event_uid, e.document, e.host_hostname, e.user_name,"
        " COALESCE(e.event_time_utc, e.ingest_time) AS finding_time"
        " FROM events e"
        " WHERE e.tenant_id = %s AND e.workspace_id = %s AND e.run_id = ANY(%s)"
    )

    predicate_params: list[Any] = []
    predicate_sql: str | None = None
    if detection_path == "sql":
        predicate_sql = _condition_sql(node, identifiers, predicate_params)
    sql = _HEAD + selector_sql + (f" AND ({predicate_sql})" if predicate_sql else "")

    # §4.6 budget: the statement is still *stored* as compile evidence and run
    # by the conformance oracle — only the engine's own path flips to native,
    # because parsing/planning it every run is what blows the detect budget.
    budget_exceeded = detection_path == "sql" and len(sql) > MAX_SQL_BYTES
    if budget_exceeded:
        detection_path = "native"

    params: list[Any] = ["__tenant__", "__workspace__", "__runs__"]
    params += selector_params + predicate_params

    if budget_exceeded:
        fallback_reason = "COST_BUDGET_EXCEEDED"
    elif needs_native:
        fallback_reason = _fallback_reason(identifiers, referenced)
    else:
        fallback_reason = None

    block: dict[str, Any] = {
        "detection_path": detection_path,
        "sql": _finalize_sql(sql),
        "fallback_reason": fallback_reason,
        "cost_class": _cost_class(document, detection_path, prefilter),
        "prefilter": prefilter,
        "compiled_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "engine_version": engine_version,
    }
    if codes:
        block["unsupported"] = codes
    return block, params


def compile_document(
    document: Mapping[str, Any],
    *,
    unsupported: Iterable[Mapping[str, str]] = (),
    engine_version: str = ENGINE_VERSION,
) -> dict[str, Any]:
    """Build the ``compile`` JSONB block for a normalized rule document."""
    return plan(document, unsupported=unsupported, engine_version=engine_version)[0]


def compile_params(document: Mapping[str, Any]) -> list[Any]:
    """Recompute the bind list for the stored ``compile.sql`` (deterministic)."""
    _, params = plan(document)
    return params


def bind_params(document: Mapping[str, Any], tenant_id: str, workspace_id: str, run_ids: Sequence[str]) -> list[Any]:
    """Full bind list: scope first, then the document-derived rule values."""
    params = compile_params(document)
    return [tenant_id, workspace_id, list(run_ids), *params[3:]]


def _finalize_sql(sql: str) -> str:
    i = 0
    while i < len(sql):
        if sql[i] == "%":
            if i + 1 >= len(sql) or sql[i + 1] != "s":
                raise CompileError(f"unexpected % at offset {i} in compiled SQL")
            i += 2
            continue
        i += 1
    return sql


def _condition_sql(node: Any, identifiers: Mapping[str, Any], params: list[Any]) -> str:
    kind = node[0]
    if kind == "and":
        return (
            "("
            + _condition_sql(node[1], identifiers, params)
            + " AND "
            + _condition_sql(node[2], identifiers, params)
            + ")"
        )
    if kind == "or":
        return (
            "("
            + _condition_sql(node[1], identifiers, params)
            + " OR "
            + _condition_sql(node[2], identifiers, params)
            + ")"
        )
    if kind == "not":
        return "(NOT " + _condition_sql(node[1], identifiers, params) + ")"
    if kind == "ident":
        return _identifier_sql(identifiers[node[1]], params)
    if kind == "of":
        names = sorted(matching_identifiers(node, list(identifiers)))
        if not names:
            raise CompileError(f"pattern {node[2]!r} matches no identifier")
        if node[1] == "all" or (isinstance(node[1], int) and node[1] >= len(names)):
            return "(" + " AND ".join(
                _identifier_sql(identifiers[n], params) for n in names
            ) + ")"
        if node[1] in (0, 1):
            return "(" + " OR ".join(
                _identifier_sql(identifiers[n], params) for n in names
            ) + ")"
        counter = " + ".join(
            "(CASE WHEN " + _identifier_sql(identifiers[n], params) + " THEN 1 ELSE 0 END)"
            for n in names
        )
        return f"(({counter}) >= {int(node[1])})"
    raise CompileError(f"unknown condition node {kind!r}")
