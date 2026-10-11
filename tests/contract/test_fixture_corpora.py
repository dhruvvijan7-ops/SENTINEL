"""Exit criterion M0-③: the committed example corpora validate against the
machine-normative JSON Schemas, the fixture counts match the manifest, and the
manifest matches the authored source documents (drift => explicit failure).

Fixtures are produced by ``tools/extract_examples.py`` (re-runnable, idempotent);
this module is the gate, the extractor is the writer.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))

EXPECTED_COUNTS = {
    "canonical_events": 121,
    "stage5_rules": 25,
    "stage3_af_rules": 5,
}

SCHEMAS = {
    "canonical_event_v1.schema.json": json.loads(
        (ROOT / "canonical_event_v1.schema.json").read_text(encoding="utf-8")
    ),
    "rule_schema.json": json.loads((ROOT / "rule_schema.json").read_text(encoding="utf-8")),
}
_VALIDATORS = {
    name: Draft202012Validator(schema) for name, schema in SCHEMAS.items()
}


def _corpus(name: str) -> dict:
    return MANIFEST["corpora"][name]


def _fixture_paths(name: str) -> list[Path]:
    return [FIXTURES / f["file"] for f in _corpus(name)["files"]]


def _params(name: str) -> list:
    return [
        pytest.param(FIXTURES / f["file"], id=f["file"])
        for f in _corpus(name)["files"]
    ]


# ---------------------------------------------------------------------------
# the schemas themselves are valid Draft 2020-12
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("schema_name", sorted(SCHEMAS))
def test_schema_is_valid_draft202012(schema_name: str):
    Draft202012Validator.check_schema(SCHEMAS[schema_name])


# ---------------------------------------------------------------------------
# every fixture validates
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", _params("canonical_events"))
def test_canonical_event_fixture_validates(path: Path):
    obj = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = sorted(_VALIDATORS["canonical_event_v1.schema.json"].iter_errors(obj))
    assert not errors, (
        f"{path.relative_to(ROOT)} fails canonical_event_v1.schema.json: "
        + "; ".join(f"{'/'.join(map(str, e.path))}: {e.message[:200]}" for e in errors[:5])
    )


@pytest.mark.parametrize("path", _params("stage5_rules") + _params("stage3_af_rules"))
def test_rule_fixture_validates(path: Path):
    obj = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = sorted(_VALIDATORS["rule_schema.json"].iter_errors(obj))
    assert not errors, (
        f"{path.relative_to(ROOT)} fails rule_schema.json: "
        + "; ".join(f"{'/'.join(map(str, e.path))}: {e.message[:200]}" for e in errors[:5])
    )


# ---------------------------------------------------------------------------
# counts == manifest == spec-mandated corpora sizes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("corpus,expected", sorted(EXPECTED_COUNTS.items()))
def test_corpus_count_matches_manifest(corpus: str, expected: int):
    files = _fixture_paths(corpus)
    manifest_count = _corpus(corpus)["count"]
    assert manifest_count == expected, (
        f"{corpus}: manifest says {manifest_count}, M0 contract requires {expected}"
    )
    assert len(files) == manifest_count, (
        f"{corpus}: manifest lists {manifest_count} files, {len(files)} exist on disk"
    )
    for f in _corpus(corpus)["files"]:
        assert (FIXTURES / f["file"]).exists(), f"missing committed fixture {f['file']}"


def test_total_fixture_file_count():
    on_disk = sorted(FIXTURES.rglob("*.yaml"))
    listed = sum(len(_corpus(c)["files"]) for c in EXPECTED_COUNTS)
    assert len(on_disk) == listed, (
        f"{len(on_disk)} yaml fixtures on disk, manifest lists {listed}"
    )


# ---------------------------------------------------------------------------
# manifest provenance: sha256 of each source document is still the one the
# fixtures were extracted from (drift -> re-run tools/extract_examples.py)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("corpus", sorted(EXPECTED_COUNTS))
def test_manifest_source_sha256_matches_current_doc(corpus: str):
    man = _corpus(corpus)
    doc = ROOT / man["source_doc"]
    assert doc.exists(), f"source document {man['source_doc']} is gone"
    actual = hashlib.sha256(doc.read_bytes()).hexdigest()
    assert actual == man["source_sha256"], (
        f"{man['source_doc']} changed since the fixtures were extracted "
        f"(manifest sha256 {man['source_sha256'][:16]}…, current {actual[:16]}…). "
        "Re-run: python tools/extract_examples.py"
    )


def test_manifest_provenance_lines_are_within_source_doc():
    for corpus in sorted(EXPECTED_COUNTS):
        man = _corpus(corpus)
        total = len((ROOT / man["source_doc"]).read_text(encoding="utf-8").splitlines())
        assert 1 <= man["source_section_line_start"] <= total
        assert man["source_section_line_start"] <= man["source_section_line_end"] <= total
        for f in man["files"]:
            assert man["source_section_line_start"] <= f["source_line_start"], (
                f"{f['file']}: provenance line {f['source_line_start']} is outside "
                f"{man['source_section']}"
            )


def test_fixtures_are_not_stale():
    """Full re-extraction check: committed fixtures == what the extractor emits."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "extract_examples.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0, (
        "committed fixtures drifted from their source documents; "
        "re-run `python tools/extract_examples.py` and commit the result.\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
