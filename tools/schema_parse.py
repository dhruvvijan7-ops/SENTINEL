#!/usr/bin/env python3
"""Shared, dependency-free parser for the ``schema.sql`` storage contract.

Used by:

  * ``tests/contract/test_rls_lint.py``   — the DB-free static RLS gate (exit ④)
  * ``tools/schema_lint.py``               — the psql + catalog-diff gate (exit ①)
  * ``tests/integration/test_schema_lint.py``

It is deliberately a *text* parser, not a real SQL parser: the contract file is
machine-normative and authored to a fixed shape (one statement per statement
block, no dollar-quoted bodies, no ``CREATE TABLE AS``).  Anything the parser
cannot understand should raise rather than silently under-count — the gates
built on it are counting contracts, and a wrong count is worse than a crash.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SQL = ROOT / "schema.sql"

_COMMENT = re.compile(r"--[^\n]*")
_CREATE_TABLE_HEAD = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_]\w*)\b",
    re.I,
)
_PARTITION_OF_HEAD = re.compile(
    r"\s*PARTITION\s+OF\s+([A-Za-z_]\w*)",
    re.I,
)
_PARTITION_BY = re.compile(r"\s*PARTITION\s+BY\s+RANGE\s*\(", re.I)
_ENABLE_RLS = re.compile(
    r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?([A-Za-z_]\w*)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
    re.I,
)
_CREATE_POLICY = re.compile(
    r"CREATE\s+POLICY\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_]\w*)\s+ON\s+([A-Za-z_]\w*)",
    re.I,
)
_FOR_CMD = re.compile(r"\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b", re.I)
_USING = re.compile(r"\bUSING\s*\(", re.I)
_WITH_CHECK = re.compile(r"\bWITH\s+CHECK\s*\(", re.I)
_CREATE_INDEX = re.compile(
    r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
    r"([A-Za-z_]\w*)\s+ON\s+([A-Za-z_]\w*)",
    re.I,
)
_PRIMARY_KEY_COL = re.compile(r"^\s*PRIMARY\s+KEY\s*\(([^)]*)\)", re.I | re.M)


class SchemaParseError(RuntimeError):
    """Raised when schema.sql contains a statement the parser cannot model."""


def _strip_comments(text: str) -> str:
    # Keep newlines so line numbers survive the substitution.
    return _COMMENT.sub("", text)


def _scan_paren_block(text: str, open_idx: int) -> tuple[str, int]:
    """Return (body, index_after_closing_paren) for the '(' at ``open_idx``."""
    if open_idx >= len(text) or text[open_idx] != "(":
        raise SchemaParseError(f"expected '(' at offset {open_idx}")
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i + 1
        i += 1
    raise SchemaParseError(f"unbalanced '(' at offset {open_idx}")


def _split_columns(body: str) -> dict[str, str]:
    """Split a CREATE TABLE body into {column: definition} + table constraints."""
    cols: dict[str, str] = {}
    depth = 0
    start = 0
    parts: list[str] = []
    for i, ch in enumerate(body):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(body[start:i])
            start = i + 1
    parts.append(body[start:])
    for part in parts:
        part = part.strip()
        if not part:
            continue
        m = re.match(r"([A-Za-z_]\w*)\s+(.*)", part, re.S)
        if not m:
            continue
        name, rest = m.group(1).lower(), " ".join(part.split()[1:])
        cols[name] = rest
    return cols


@dataclass
class Table:
    name: str
    columns: dict[str, str]
    parent: str | None = None  # set for PARTITION OF children
    partitioned_by: str | None = None  # set for partition parents

    @property
    def is_partition_child(self) -> bool:
        return self.parent is not None

    @property
    def is_partition_parent(self) -> bool:
        return self.partitioned_by is not None

    @property
    def is_base_table(self) -> bool:
        """A user-visible table: everything except a PARTITION OF child.

        Partition *parents* count as base tables — they are what spec §10.1
        indexes (events, findings, audit_log, rule_baseline are all listed
        there); the monthly/yearly children are an implementation detail of
        §1.4 and are counted separately.
        """
        return self.parent is None

    def has_column(self, name: str) -> bool:
        return name in self.columns


@dataclass
class Policy:
    name: str
    table: str
    cmd: str | None
    using: str
    with_check: str | None

    def uses_setting(self, setting: str) -> bool:
        return setting in self.using or (
            self.with_check is not None and setting in self.with_check
        )


@dataclass
class Index:
    name: str
    table: str
    unique: bool
    partial: bool
    definition: str


@dataclass
class Schema:
    tables: dict[str, Table] = field(default_factory=dict)
    rls_enabled: set[str] = field(default_factory=set)
    policies: list[Policy] = field(default_factory=list)
    indexes: dict[str, Index] = field(default_factory=dict)

    @property
    def base_tables(self) -> dict[str, Table]:
        return {n: t for n, t in self.tables.items() if t.is_base_table}

    @property
    def partition_parents(self) -> dict[str, Table]:
        return {n: t for n, t in self.tables.items() if t.is_partition_parent}

    @property
    def partition_children(self) -> dict[str, Table]:
        return {n: t for n, t in self.tables.items() if t.is_partition_child}

    def partitions_of(self, parent: str) -> list[str]:
        return sorted(n for n, t in self.tables.items() if t.parent == parent)

    def policies_on(self, table: str) -> list[Policy]:
        return [p for p in self.policies if p.table == table]


def parse_schema(text: str) -> Schema:
    clean = _strip_comments(text)
    schema = Schema()

    for m in _CREATE_TABLE_HEAD.finditer(clean):
        name = m.group(1).lower()
        rest = clean[m.end() :]
        om = _PARTITION_OF_HEAD.match(rest)
        if om:
            # CREATE TABLE <child> PARTITION OF <parent> FOR VALUES FROM …
            if name in schema.tables:
                raise SchemaParseError(f"duplicate CREATE TABLE for {name}")
            schema.tables[name] = Table(
                name=name,
                columns={},
                parent=om.group(1).lower(),
                partitioned_by=None,
            )
            continue
        stripped = rest.lstrip()
        if not stripped.startswith("("):
            raise SchemaParseError(
                f"CREATE TABLE {name} has neither a column list nor PARTITION OF"
            )
        open_idx = clean.index("(", m.end())
        body, after = _scan_paren_block(clean, open_idx)
        trailer = clean[after : after + 400]
        parent = None
        partitioned_by = None
        if _PARTITION_BY.match(trailer):
            bm = re.match(r"\s*PARTITION\s+BY\s+RANGE\s*\(([^)]*)\)", trailer, re.I)
            partitioned_by = bm.group(1).strip() if bm else "?"
        if name in schema.tables:
            raise SchemaParseError(f"duplicate CREATE TABLE for {name}")
        schema.tables[name] = Table(
            name=name,
            columns=_split_columns(body),
            parent=parent,
            partitioned_by=partitioned_by,
        )

    for m in _ENABLE_RLS.finditer(clean):
        schema.rls_enabled.add(m.group(1).lower())

    for m in _CREATE_POLICY.finditer(clean):
        tail = clean[m.end() :]
        end = m.end()
        # A policy statement ends at the next ';' at depth 0 relative to its start.
        depth = 0
        j = m.end()
        while j < len(clean):
            ch = clean[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == ";" and depth == 0:
                break
            j += 1
        stmt = clean[m.start() : j]
        fm = _FOR_CMD.search(stmt)
        um = _USING.search(stmt)
        wm = _WITH_CHECK.search(stmt)
        using = ""
        with_check = None
        if um:
            using, after_u = _scan_paren_block(stmt, stmt.index("(", um.start()))
        if wm:
            with_check, _ = _scan_paren_block(stmt, stmt.index("(", wm.start()))
        schema.policies.append(
            Policy(
                name=m.group(1).lower(),
                table=m.group(2).lower(),
                cmd=fm.group(1).upper() if fm else None,
                using=using or "",
                with_check=with_check,
            )
        )
        _ = end, tail

    for m in _CREATE_INDEX.finditer(clean):
        start = m.start()
        depth = 0
        j = m.end()
        while j < len(clean):
            ch = clean[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == ";" and depth == 0:
                break
            j += 1
        stmt = clean[start:j]
        definition = " ".join(stmt.split())
        schema.indexes[m.group(1).lower()] = Index(
            name=m.group(1).lower(),
            table=m.group(2).lower(),
            unique=bool(re.search(r"\bUNIQUE\b", stmt, re.I)),
            partial=bool(re.search(r"\bWHERE\b", stmt, re.I)),
            definition=definition,
        )

    # integrity: every partition child's parent must exist, then inherit the
    # parent's column list (a partition child has exactly the parent's columns;
    # recording them lets the tenant-column gates see children without
    # re-deriving inheritance at every call site).
    for name, table in schema.tables.items():
        if table.parent is not None:
            if table.parent not in schema.tables:
                raise SchemaParseError(
                    f"partition {name} references unknown parent {table.parent}"
                )
            table.columns = dict(schema.tables[table.parent].columns)
    return schema


def load_schema(path: Path | None = None) -> Schema:
    p = path or SCHEMA_SQL
    return parse_schema(p.read_text(encoding="utf-8"))
