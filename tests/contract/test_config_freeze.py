"""Freezes the configuration key inventory (spec §4 + M0-A2 extensions).

Three artifacts must agree, in both directions:

  1. the ``### 4. Configuration Reference`` table in
     ``research/SENTINEL_IMPLEMENTATION_SPEC.md``;
  2. ``CONFIG_KEYS`` / ``Settings`` in ``sentinel_core/config.py``;
  3. ``configs/config_keys.json`` — the committed, diff-able manifest.

Adding a key to ``Settings`` without either a spec §4 row or an entry in the
manifest (``origin: "M0-A2"``) fails here, and so does editing the spec table
without updating the code.
"""
from __future__ import annotations

import json
import re
from dataclasses import fields
from pathlib import Path

from sentinel_core.config import CONFIG_KEYS, Settings

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "research" / "SENTINEL_IMPLEMENTATION_SPEC.md"
MANIFEST = ROOT / "configs" / "config_keys.json"

_SPEC_HEADING = "### 4. Configuration Reference"
_NEXT_HEADING = "### 5. Observability Spec"


def spec_table_keys() -> list[str]:
    """Expand every backticked cell-1 token of the §4 table to a TOML path.

    The table packs several keys into one row and writes the later ones
    relative to the first (``| `database.pool_min` / `pool_max` |``), so a
    token without a dot inherits the leading section of its row.
    """
    text = SPEC.read_text(encoding="utf-8")
    lines = text.splitlines()
    start = lines.index(_SPEC_HEADING)
    paths: list[str] = []
    for line in lines[start:]:
        if line.startswith(_NEXT_HEADING):
            break
        if not line.startswith("|"):
            continue
        cells = line.split("|")
        if len(cells) < 3:
            continue
        first = cells[1].strip()
        if not first.startswith("`"):
            continue  # header or separator row
        tokens = re.findall(r"`([^`]+)`", first)
        section = tokens[0].split(".")[0]
        for token in tokens:
            paths.append(token if "." in token else f"{section}.{token}")
    return paths


def manifest_keys() -> list[dict]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["keys"]


def _toml_path(k) -> str:
    return f"{k.section}.{k.key}"


def test_spec_table_has_the_expected_shape():
    """The §4 table is the rank-4 source of truth; if it stops parsing, the
    freeze is no longer being enforced and this must fail loudly."""
    paths = spec_table_keys()
    assert len(paths) == 34, (
        f"spec §4 table yielded {len(paths)} keys, expected 34: {paths}"
    )
    assert len(set(paths)) == len(paths), f"duplicate rows in spec §4: {paths}"


def test_spec_rows_match_code_spec_entries():
    spec_paths = sorted(spec_table_keys())
    code_paths = sorted(_toml_path(k) for k in CONFIG_KEYS if k.origin == "spec §4")
    assert code_paths == spec_paths, (
        f"code-only: {sorted(set(code_paths) - set(spec_paths))}; "
        f"spec-only: {sorted(set(spec_paths) - set(code_paths))}"
    )


def test_manifest_is_current():
    """``configs/config_keys.json`` is a snapshot of ``CONFIG_KEYS``; regenerating
    it must be a no-op."""
    expected = [
        {
            "field": k.field,
            "section": k.section,
            "key": k.key,
            "toml": _toml_path(k),
            "kind": k.kind,
            "default": list(k.default) if isinstance(k.default, tuple) else k.default,
            "origin": k.origin,
            "note": k.note,
        }
        for k in CONFIG_KEYS
    ]
    assert manifest_keys() == expected


def test_every_settings_field_is_frozen():
    field_names = {f.name for f in fields(Settings)}
    key_names = {k.field for k in CONFIG_KEYS}
    assert field_names == key_names, (
        f"Settings-only: {sorted(field_names - key_names)}; "
        f"inventory-only: {sorted(key_names - field_names)}"
    )


def test_a2_keys_are_declared_in_the_deviation_register():
    """Every non-spec key must be justified in research/DEVIATION_REGISTER.md,
    otherwise it is an undeclared contract change."""
    register = (ROOT / "research" / "DEVIATION_REGISTER.md").read_text(
        encoding="utf-8"
    )
    a2 = [k for k in CONFIG_KEYS if k.origin == "M0-A2"]
    assert len(a2) == 7, f"expected 7 M0-A2 extension keys, found {len(a2)}"
    for k in a2:
        assert _toml_path(k) in register, (
            f"{_toml_path(k)} is an M0-A2 key but is not documented in "
            "research/DEVIATION_REGISTER.md"
        )


def test_inventory_covers_every_spec_kind():
    """Kinds in the manifest must be one of the types the loader understands."""
    allowed = {"str", "int", "bool", "opt_str", "enum", "table", "dev_keys"}
    bad = sorted({k.kind for k in CONFIG_KEYS} - allowed)
    assert bad == [], f"unknown ConfigKey.kind values: {bad}"


def test_example_file_exercises_every_spec_section():
    """config.example.toml must actually set at least one key per spec section,
    so a typo in a section name is caught rather than silently ignored."""
    toml_text = (ROOT / "configs" / "config.example.toml").read_text(
        encoding="utf-8"
    )
    sections = sorted({k.section for k in CONFIG_KEYS if k.origin == "spec §4"})
    missing = [s for s in sections if f"[{s}]" not in toml_text]
    assert missing == [], f"config.example.toml is missing sections: {missing}"
