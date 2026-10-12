"""Sigma field-mapping pipelines (Stage-2 D2-014).

``configs/sigma_field_mapping_pipelines.yaml`` is configuration data, not code:
it carries the Sigma field name -> canonical schema path map plus the logsource
selector that tells the compiler which envelope columns to prefilter on.

Pipeline selection (documented rule, enforced by ``select``):

* a pipeline is *eligible* for a rule when every key in ``pipeline.logsource``
  is present in ``rule.logsource`` with an equal value (pipeline.logsource ⊆
  rule.logsource) — so a pipeline that demands ``service: sysmon`` never claims
  a source-agnostic rule;
* the eligible pipeline with the most logsource keys wins (most specific).

An unmapped Sigma field is represented by the literal target ``unmapped`` (or
by its absence) and is reported by the compiler as ``UNMAPPED_FIELD``.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping

PIPELINES_RELPATH = Path("configs") / "sigma_field_mapping_pipelines.yaml"


def repo_root() -> Path:
    """Locate the repository root by walking up to a marker file.

    ``migrations/versions/0001_init.py`` resolves ``schema.sql`` the same way;
    walking (rather than a fixed ``parents[n]``) keeps the answer right whether
    the package is imported from the source tree or from an installed layout.
    """
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        if (parent / "openapi.yaml").is_file() and (parent / "rule_schema.json").is_file():
            return parent
    raise RuntimeError("sentinel repository root not found from " + str(here))


@dataclass(frozen=True)
class Pipeline:
    id: str
    title: str
    logsource: Mapping[str, str]
    selector: Mapping[str, Any]
    field_mapping: Mapping[str, str]
    value_transform: tuple[Any, ...] = ()

    @property
    def specificity(self) -> int:
        return len(self.logsource)


@dataclass(frozen=True)
class ValueTransform:
    source_shape: str
    target: tuple[str, ...]
    rule_action: str


class PipelineRegistry:
    def __init__(self, pipelines: Iterable[Pipeline]) -> None:
        self.pipelines: tuple[Pipeline, ...] = tuple(pipelines)
        if not self.pipelines:
            raise ValueError("sigma_field_mapping_pipelines.yaml declares no pipelines")

    @classmethod
    def load(cls, path: Path | None = None) -> "PipelineRegistry":
        import yaml

        target = path or (repo_root() / PIPELINES_RELPATH)
        doc = yaml.safe_load(target.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or doc.get("version") != 1:
            raise ValueError(f"{target}: expected 'version: 1' mapping at top level")
        raw = doc.get("pipelines")
        if not isinstance(raw, list):
            raise ValueError(f"{target}: 'pipelines' must be a list")
        out: list[Pipeline] = []
        for entry in raw:
            if not isinstance(entry, dict) or "id" not in entry:
                raise ValueError(f"{target}: every pipeline needs an id")
            transforms = tuple(
                ValueTransform(
                    source_shape=str(t.get("source_shape", "")),
                    target=tuple(t.get("target") or ()),
                    rule_action=str(t.get("rule_action", "")),
                )
                for t in (entry.get("value_transform") or [])
                if isinstance(t, dict)
            )
            out.append(
                Pipeline(
                    id=str(entry["id"]),
                    title=str(entry.get("title", entry["id"])),
                    logsource=dict(entry.get("logsource") or {}),
                    selector=dict(entry.get("selector") or {}),
                    field_mapping=dict(entry.get("field_mapping") or {}),
                    value_transform=transforms,
                )
            )
        return cls(out)

    def select(self, logsource: Mapping[str, Any] | None) -> Pipeline | None:
        """Most specific eligible pipeline, or None when nothing matches."""
        ls = {k: v for k, v in (logsource or {}).items() if v is not None}
        best: Pipeline | None = None
        for pipe in self.pipelines:
            if not pipe.logsource:
                continue
            if all(k in ls and ls[k] == v for k, v in pipe.logsource.items()):
                if best is None or pipe.specificity > best.specificity:
                    best = pipe
        return best

    def map_field(self, pipeline: Pipeline | None, sigma_field: str) -> str | None:
        """Sigma field -> canonical dotted path, or None when unmapped."""
        if pipeline is None:
            return None
        target = pipeline.field_mapping.get(sigma_field)
        if target is None:
            return None
        if str(target) == "unmapped":
            return None
        return str(target)

    def selector_prefilter(self, pipeline: Pipeline | None) -> list[dict[str, Any]]:
        """Translate a pipeline's ``selector`` into indexable prefilter entries."""
        if pipeline is None:
            return []
        out: list[dict[str, Any]] = []
        for column, value in pipeline.selector.items():
            values = value if isinstance(value, list) else [value]
            out.append(
                {
                    "column": str(column),
                    "op": "in" if len(values) > 1 else "eq",
                    "values": [str(v) for v in values],
                }
            )
        return out


@lru_cache(maxsize=8)
def default_registry() -> PipelineRegistry:
    return PipelineRegistry.load()
