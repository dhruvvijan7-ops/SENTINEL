"""Sigma rule → ``sentinel-rule/v1`` document normalization (Stage-5 L0–L3).

Normalization is a *compile-time* step: it runs once at pack import and the
resulting document is what the runtime evaluates.  Everything that a rule
reader would call "compile-time value expansion" happens here so that both the
SQL compiler and the native evaluator consume the same, already-expanded
document:

* field keys are rewritten to canonical schema paths (``Image|endswith`` →
  ``process.exe|endswith``); a field the selected pipeline cannot map is
  rewritten to ``unmapped.<SigmaField>`` so the document stays unambiguous at
  runtime without any extra lookups, and is reported as ``UNMAPPED_FIELD``
  (a warning, never fatal);
* ``windash`` is expanded into explicit dash permutations (capped at 32 per
  §3.4 — over the cap the rule is ``UNSUPPORTED_MODIFIER`` and rejected);
* every other modifier outside the §3.4 SUPPORTED set makes the rule
  ``UNSUPPORTED_MODIFIER`` → rejected;
* YAML booleans become ``"true"``/``"false"`` strings (``sigma_value`` has no
  boolean arm) and dates become ISO strings.

The document is then schema-validated (L1) and its condition is re-parsed
(L2) by the importer — this module only guarantees structure.
"""
from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from itertools import product
from typing import Any, Mapping

from .condition import ConditionError, matching_identifiers, parse_condition
from .pipelines import Pipeline, PipelineRegistry, default_registry

SCHEMA_TAG = "sentinel-rule/v1"
UNMAPPED_ROOT = "unmapped"

#: The upstream contract we parse against (sigma-specification pinned copy).
SOURCE_SPEC = "sigma-spec/2.1.0"

_ID_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL


def derive_rule_id(source: str, source_id: str) -> str:
    """Our stable rule id (Stage-1 §6.2).

    Upstream ids are not guaranteed to be UUIDs (and must never be trusted as
    primary keys), so the id is namespaced per ``source`` and derived with
    UUIDv5: stable across reimports, distinct from any other source's id space.
    """
    return str(uuid.uuid5(_ID_NAMESPACE, f"sentinel:rule:{source}:{source_id}"))

#: Modifiers evaluated by the SQL compiler (Stage-5 §3.4 SUPPORTED row).
SQL_MODIFIERS = frozenset(
    {
        "contains", "startswith", "endswith", "exists", "all", "neq", "cased",
        "i", "lt", "lte", "gt", "gte",
    }
)
#: Modifiers only the native evaluator can honour: RE2 never crosses to
#: PostgreSQL ``~`` (§3.4), ``fieldref`` needs a second projection, and
#: ``cidr`` needs a guarded inet cast PostgreSQL cannot express in plain SQL
#: (recorded as M2-A9 in research/DEVIATION_REGISTER.md).
NATIVE_MODIFIERS = frozenset({"re", "fieldref", "cidr"})
#: Modifiers expanded into plain values while the document is built.
EXPANDING_MODIFIERS = frozenset({"windash", "base64", "base64offset"})

#: Spec constructs we deliberately do not ship, with their registered code
#: (§3.1).  ``expand`` must be rejected per spec; the UTF-16 family is
#: ``SUPPORTED_LATER`` in §3.4 and would otherwise be silently mis-evaluated.
REJECTED_MODIFIERS: dict[str, str] = {"expand": "UNSUPPORTED_PLACEHOLDER"}
for _m in ("utf16", "utf16le", "utf16be", "wide"):
    REJECTED_MODIFIERS[_m] = "UNSUPPORTED_ENCODING_TARGET"

#: §3.4 marks the time extractors SUPPORTED but they need a guarded timestamp
#: cast PostgreSQL cannot express; 0 corpus usage — rejected (M2-A7).
TIME_MODIFIERS = frozenset({"minute", "hour", "day", "week", "month", "year"})

SUPPORTED_MODIFIERS = SQL_MODIFIERS | NATIVE_MODIFIERS | EXPANDING_MODIFIERS

_DASHES = ("-", "/", "\u2013", "\u2014", "\u2015")
_WINDASH_CAP = 32

_SEVERITY_BY_LEVEL = {
    "informational": "LOW",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "HIGH",
}
DEFAULT_SEVERITY = "LOW"

#: rule_schema.json ``status`` enum — anything else upstream is dropped.
_STATUSES = frozenset({"stable", "test", "experimental", "deprecated", "unsupported"})

#: logsource keys whose values follow the lowercase/underscore convention;
#: ``definition`` is free text and is kept verbatim.
_LOGSOURCE_ENUM_KEYS = ("category", "product", "service")


class NormalizeError(ValueError):
    """Structural failure while turning upstream Sigma into our document."""


@dataclass(frozen=True)
class NormalizedRule:
    document: dict[str, Any]
    unsupported: tuple[dict[str, str], ...]
    fatal: bool
    pipeline: Pipeline | None


def _scalar(value: Any) -> Any:
    """YAML scalars the JSON schema accepts: str | number | null."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return value


def _windash_variants(value: str) -> list[str] | None:
    """Permute every dash in *value* across ``- / \u2013 \u2014 \u205f``.

    Returns ``None`` when the permutation count exceeds §3.4's cap of 32.
    """
    positions = [i for i, ch in enumerate(value) if ch in _DASHES]
    if not positions:
        return [value]
    if len(_DASHES) ** len(positions) > _WINDASH_CAP:
        return None
    out: list[str] = []
    for combo in product(_DASHES, repeat=len(positions)):
        chars = list(value)
        for pos, ch in zip(positions, combo):
            chars[pos] = ch
        out.append("".join(chars))
    return list(dict.fromkeys(out))


def _split_key(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0], [p for p in parts[1:] if p]


def has_unescaped_wildcard(value: str) -> bool:
    """True when the Sigma value carries a live ``*``/``?`` wildcard."""
    i = 0
    n = len(value)
    while i < n:
        c = value[i]
        if c == "\\" and i + 1 < n and value[i + 1] in "*?\\":
            i += 2
            continue
        if c in "*?":
            return True
        i += 1
    return False


def unescaped_literal(value: str) -> str:
    """Apply the spec's escape table (``\\*``, ``\\?``, ``\\\\``) to get the
    literal text a value denotes."""
    out: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        c = value[i]
        if c == "\\" and i + 1 < n and value[i + 1] in "*?\\":
            out.append(value[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _base64_expand(value: str, *, offset: bool) -> list[str]:
    """``base64`` / ``base64offset`` compile-time expansion.

    Byte layout mirrors pySigma's ``SigmaBase64OffsetModifier`` (pinned
    ``50708bae``): three variants, offsets ``(0, 2, 3)`` start and
    ``(None, -3, -2)`` end indexed by ``(len(data) + i) % 3``.
    """
    if has_unescaped_wildcard(value):
        raise ValueError("base64 encoding of strings with wildcards is not allowed")
    data = unescaped_literal(value).encode("utf-8")
    if not offset:
        return [base64.b64encode(data).decode("ascii")]
    starts = (0, 2, 3)
    ends: tuple[int | None, ...] = (None, -3, -2)
    out: list[str] = []
    for i in range(3):
        encoded = base64.b64encode(i * b" " + data)
        out.append(encoded[starts[i] : ends[(len(data) + i) % 3]].decode("ascii"))
    return out


def _expand_values(
    values: list[Any], modifiers: list[str], selector: str, unsupported: list[dict[str, str]]
) -> list[Any] | None:
    """Apply compile-time value expansion; ``None`` ⇒ rule is rejected."""
    if not (EXPANDING_MODIFIERS & set(modifiers)):
        return values
    out: list[Any] = []
    for value in values:
        if not isinstance(value, str):
            unsupported.append(
                {
                    "code": "UNSUPPORTED_MODIFIER",
                    "detail": "transformation modifier on a non-string value",
                    "selector": selector,
                }
            )
            return None
        try:
            if "base64offset" in modifiers:
                variants = _base64_expand(value, offset=True)
            elif "base64" in modifiers:
                variants = _base64_expand(value, offset=False)
            else:
                variants = _windash_variants(value)
        except ValueError as exc:
            unsupported.append(
                {"code": "UNSUPPORTED_MODIFIER", "detail": str(exc), "selector": selector}
            )
            return None
        if variants is None:
            unsupported.append(
                {
                    "code": "UNSUPPORTED_MODIFIER",
                    "detail": f"windash permutations exceed {_WINDASH_CAP}",
                    "selector": selector,
                }
            )
            return None
        out.extend(variants)
    return list(dict.fromkeys(out))


def _resolve_fieldrefs(
    values: list[Any],
    registry: PipelineRegistry,
    pipeline: Pipeline | None,
    identifier: str,
    unsupported: list[dict[str, str]],
) -> list[Any]:
    """``fieldref`` values name *fields*, not literals — map them like keys."""
    out: list[Any] = []
    for value in values:
        if not isinstance(value, str):
            unsupported.append(
                {
                    "code": "UNSUPPORTED_MODIFIER",
                    "detail": "fieldref value must be a field name",
                    "selector": identifier,
                }
            )
            out.append(value)
            continue
        target = registry.map_field(pipeline, value)
        if target is not None:
            out.append(target)
        elif "." in value:
            out.append(value)  # already written as a canonical path
        else:
            out.append(f"{UNMAPPED_ROOT}.{value}")
            unsupported.append(
                {"code": "UNMAPPED_FIELD", "detail": value, "selector": identifier}
            )
    return out


def _rewrite_predicate_map(
    mapping: Mapping[str, Any],
    registry: PipelineRegistry,
    pipeline: Pipeline | None,
    identifier: str,
    unsupported: list[dict[str, str]],
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, raw_value in mapping.items():
        if not isinstance(key, str) or not key:
            raise NormalizeError(f"identifier {identifier!r}: empty field name")
        sigma_field, modifiers = _split_key(key)
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        values = [_scalar(v) for v in values]
        if not sigma_field:
            # Sigma's `|all` bare key (rules-spec §6.11): a keyword search with
            # AND instead of OR.  The key is schema-legal and is re-emitted
            # verbatim so both evaluators see the same instruction.
            if modifiers == ["all"]:
                out["|all"] = values
                continue
            raise NormalizeError(f"identifier {identifier!r}: empty field name in {key!r}")
        for mod in modifiers:
            if mod in REJECTED_MODIFIERS:
                unsupported.append(
                    {
                        "code": REJECTED_MODIFIERS[mod],
                        "detail": f"modifier {mod!r} is not implemented",
                        "selector": identifier,
                    }
                )
            elif mod in TIME_MODIFIERS or mod not in SUPPORTED_MODIFIERS:
                unsupported.append(
                    {
                        "code": "UNSUPPORTED_MODIFIER",
                        "detail": f"modifier {mod!r} is outside the supported set",
                        "selector": identifier,
                    }
                )
        if any(v is None for v in values) and len(values) > 1:
            raise NormalizeError(
                f"identifier {identifier!r}: null may not be mixed into a value list ({key!r})"
            )
        if "fieldref" in modifiers:
            expanded = _resolve_fieldrefs(values, registry, pipeline, identifier, unsupported)
        else:
            expanded = _expand_values(values, modifiers, f"{identifier}:{key}", unsupported)
            if expanded is None:
                # Rule is already fatal; keep the raw values so the document
                # stays structurally valid for the schema check that follows.
                expanded = values
        target = registry.map_field(pipeline, sigma_field)
        if target is None:
            new_field = f"{UNMAPPED_ROOT}.{sigma_field}"
            unsupported.append(
                {
                    "code": "UNMAPPED_FIELD",
                    "detail": sigma_field,
                    "selector": identifier,
                }
            )
        else:
            new_field = target
        new_key = new_field if not modifiers else new_field + "|" + "|".join(modifiers)
        out[new_key] = expanded if isinstance(raw_value, list) else expanded[0]
    if not out:
        raise NormalizeError(f"identifier {identifier!r} has no predicates after normalization")
    return out


def _rewrite_value(
    value: Any,
    registry: PipelineRegistry,
    pipeline: Pipeline | None,
    identifier: str,
    unsupported: list[dict[str, str]],
) -> Any:
    if isinstance(value, Mapping):
        return _rewrite_predicate_map(value, registry, pipeline, identifier, unsupported)
    if isinstance(value, list):
        out: list[Any] = []
        for item in value:
            if isinstance(item, str):
                out.append(item)  # keyword (bare-string) search, kept verbatim
            elif isinstance(item, Mapping):
                out.append(
                    _rewrite_predicate_map(item, registry, pipeline, identifier, unsupported)
                )
            else:
                raise NormalizeError(
                    f"identifier {identifier!r}: list items must be maps or keyword strings"
                )
        if not out:
            raise NormalizeError(f"identifier {identifier!r} has an empty value list")
        return out
    raise NormalizeError(
        f"identifier {identifier!r}: search identifier must be a map or a list"
    )


def _check_condition(condition: Any, detection_keys: list[str]) -> Any:
    if not isinstance(condition, str) or not condition.strip():
        raise NormalizeError("detection.condition must be a non-empty string")
    try:
        node = parse_condition(condition)
    except ConditionError as exc:
        raise NormalizeError(f"condition not parseable: {exc}") from exc
    known = set(detection_keys)

    def walk(n: Any) -> None:
        if not isinstance(n, tuple) or not n:
            return
        if n[0] == "ident":
            if n[1] not in known:
                raise NormalizeError(f"condition references undefined identifier {n[1]!r}")
        elif n[0] == "of":
            if not matching_identifiers(n, detection_keys):
                raise NormalizeError(f"condition pattern {n[2]!r} matches no identifier")
        elif n[0] in ("and", "or"):
            walk(n[1])
            walk(n[2])
        elif n[0] == "not":
            walk(n[1])

    walk(node)
    return node


def _severity(level: Any) -> str:
    if not isinstance(level, str):
        return DEFAULT_SEVERITY
    return _SEVERITY_BY_LEVEL.get(level.strip().lower(), DEFAULT_SEVERITY)


def normalize_rule(
    raw: Mapping[str, Any],
    *,
    registry: PipelineRegistry | None = None,
    rule_id: str | None = None,
    source_ref: str | None = None,
    provenance: Mapping[str, Any] | None = None,
) -> NormalizedRule:
    """Turn one upstream Sigma document into a ``sentinel-rule/v1`` document.

    Returns the document plus every non-fatal reason code raised while
    rewriting it.  ``fatal`` is True when the rule must not be executed.
    """
    if not isinstance(raw, Mapping):
        raise NormalizeError("rule document must be a mapping")
    title = raw.get("title")
    if not isinstance(title, str) or not title.strip():
        raise NormalizeError("rule has no title")
    logsource = raw.get("logsource")
    if not isinstance(logsource, Mapping) or not logsource:
        raise NormalizeError(f"{title}: rule has no logsource")
    logsource_out: dict[str, str] = {}
    for k, v in logsource.items():
        if v is None:
            continue
        text = str(v)
        logsource_out[str(k)] = (
            text.strip().lower().replace(" ", "_")
            if str(k) in _LOGSOURCE_ENUM_KEYS
            else text.strip()
        )
    if not logsource_out:
        raise NormalizeError(f"{title}: logsource has no usable keys")

    detection = raw.get("detection")
    if not isinstance(detection, Mapping) or len(detection) < 2:
        raise NormalizeError(f"{title}: detection needs condition plus >=1 identifier")
    if "condition" not in detection:
        raise NormalizeError(f"{title}: detection has no condition")

    registry = registry or default_registry()
    pipeline = registry.select(logsource_out)

    unsupported: list[dict[str, str]] = []
    rewritten: dict[str, Any] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if not isinstance(key, str) or not key.strip():
            raise NormalizeError(f"{title}: detection identifier names must be strings")
        if key in ("condition", UNMAPPED_ROOT):
            raise NormalizeError(f"{title}: detection identifier {key!r} is reserved")
        rewritten[key] = _rewrite_value(value, registry, pipeline, key, unsupported)

    condition = detection["condition"]
    if isinstance(condition, list):
        if not condition:
            raise NormalizeError(f"{title}: condition list is empty")
        # sigma-spec condition-as-list = OR across items; the stored document
        # keeps a single string (rule_schema.json types condition as string).
        condition_str = " or ".join(f"({c})" for c in condition)
    elif isinstance(condition, str):
        condition_str = condition
    else:
        raise NormalizeError(f"{title}: condition must be a string or a list of strings")
    try:
        _check_condition(condition_str, list(rewritten.keys()))
    except NormalizeError as exc:
        code = (
            "UNSUPPORTED_CONDITION_FORM"
            if "not parseable" in str(exc)
            else "EMPTY_SELECTION"
        )
        unsupported.append({"code": code, "detail": str(exc), "selector": "condition"})
    rewritten["condition"] = condition_str

    sigma_id = raw.get("id")
    if not isinstance(sigma_id, str) or not sigma_id.strip():
        raise NormalizeError(f"{title}: upstream rule has no id")

    tags = [str(t) for t in (raw.get("tags") or []) if t is not None]
    fields = [str(f) for f in (raw.get("fields") or []) if f is not None]
    falsepositives = [str(f) for f in (raw.get("falsepositives") or []) if f is not None]
    references = [str(r) for r in (raw.get("references") or []) if r is not None]

    document: dict[str, Any] = {
        "schema": SCHEMA_TAG,
        "id": rule_id or derive_rule_id("sigma", sigma_id),
        "kind": "sigma",
        "source": "sigma",
        "source_id": sigma_id.strip(),
        "source_spec": SOURCE_SPEC,
        "license": str(raw.get("license") or "DRL-1.1"),
        "author": str(raw.get("author") or "unknown"),
        "name": title.strip(),
        "title": title.strip(),
        "severity": _severity(raw.get("level")),
        "enabled": True,
        "logsource": logsource_out,
        "detection": rewritten,
    }
    if source_ref:
        document["source_ref"] = source_ref
    if isinstance(raw.get("description"), str):
        document["description"] = raw["description"]
    if isinstance(raw.get("status"), str) and raw["status"] in _STATUSES:
        document["status"] = raw["status"]
    if isinstance(raw.get("level"), str):
        document["level_original"] = raw["level"]
    if isinstance(raw.get("modified"), (str, date, datetime)):
        document["modified"] = _scalar(raw["modified"])
    if isinstance(raw.get("date"), (str, date, datetime)):
        document["date"] = _scalar(raw["date"])
    if tags:
        document["tags"] = tags
    if fields:
        document["fields"] = fields
    if falsepositives:
        document["falsepositives"] = falsepositives
    if references:
        document["references"] = references
    if provenance:
        document["provenance"] = dict(provenance)

    fatal = any(u["code"] != "UNMAPPED_FIELD" for u in unsupported)
    if fatal:
        document["enabled"] = False
    return NormalizedRule(
        document=document,
        unsupported=tuple(unsupported),
        fatal=fatal,
        pipeline=pipeline,
    )
