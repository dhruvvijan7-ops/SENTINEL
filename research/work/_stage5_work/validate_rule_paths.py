#!/usr/bin/env python3
"""D8-14 CI gate: cross-validate rule predicate field paths against
canonical_event_v1.schema.json.

Collects every dot-joined property path reachable from the canonical schema
(envelope + each category payload object, $ref-resolved), then checks each
rule example's `fields[]` and `detection` predicate `field` values (with
`|modifier` suffixes stripped) resolve to a real path. A non-resolving field
would compile + validate against rule_schema.json yet silently match nothing.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CANON = ROOT / "canonical_event_v1.schema.json"
STAGE5 = ROOT / "stage-5-dynamic-rule-engine.md"


def resolve(node: dict, root: dict):
    if isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if ref.startswith("#/"):
            cur = root
            for part in ref[2:].split("/"):
                cur = cur[part]
            return resolve(cur, root)
    return node


def collect_paths(node: dict, root: dict, prefix: str, out: set[str]):
    node = resolve(node, root)
    if not isinstance(node, dict) or node.get("type") != "object":
        return
    props = node.get("properties") or {}
    for name, sub in props.items():
        path = f"{prefix}.{name}" if prefix else name
        out.add(path)
        collect_paths(sub, root, path, out)


def main() -> int:
    canon = json.loads(CANON.read_text(encoding="utf-8"))
    paths: set[str] = set()

    # envelope-level properties
    for name, sub in (canon.get("properties") or {}).items():
        paths.add(name)
        collect_paths(sub, canon, name, paths)

    # also collect from every $defs object (category payloads live here)
    for defname, sub in (canon.get("$defs") or {}).items():
        if defname in ("state_object",):
            continue
        collect_paths(sub, canon, defname if defname not in (
            "str_or_state", "int_or_state", "num_or_state", "bool_or_state",
            "severity_or_state", "hashes", "signature", "process_ref",
        ) else "", paths)
        # hashes/signature/process_ref are embedded, not top-level; keep their
        # inner paths without a prefix so process.hashes.sha256 still resolves
        # via the process recursion above.

    text = STAGE5.read_text(encoding="utf-8")
    m = re.search(r"## 11\. Worked Rule Examples.*?(?=\n---\n\n## 12\.)", text, re.S)
    if not m:
        m = re.search(r"## 11\..*?(?=\n## 12\.)", text, re.S)
    blocks = re.findall(r"```yaml\n(.*?)```", m.group(0), re.S)

    failures: list[dict] = []
    total_fields = 0
    for i, b in enumerate(blocks, 1):
        try:
            obj = yaml.safe_load(b)
        except Exception as exc:  # noqa: BLE001
            failures.append({"index": i, "error": f"yaml: {exc}"})
            continue
        rid = (obj or {}).get("id")
        fields: list[str] = list((obj or {}).get("fields") or [])

        # Predicates live in a kind-specific container: detection (sigma),
        # correlation / ioc / fim / sca / statistical (native), when (artifact).
        containers = [
            obj.get(k) for k in (
                "detection", "correlation", "ioc", "fim", "sca",
                "statistical", "when",
            ) if isinstance(obj.get(k), (dict, list))
        ]

        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "field" and isinstance(v, str):
                        fields.append(v)
                    else:
                        # Sigma-style predicate key: "registry.path|endswith"
                        # (selection names never contain '.' or '|')
                        if isinstance(k, str) and ("." in k or "|" in k):
                            fields.append(k)
                        walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        for c in containers:
            walk(c)
        for f in fields:
            total_fields += 1
            base = f.split("|", 1)[0].strip()
            if base not in paths:
                failures.append({
                    "index": i,
                    "id": rid,
                    "field": f,
                    "resolved_base": base,
                    "error": "does not resolve to a canonical_event_v1 property path",
                })

    out = ROOT / "_stage5_work" / "rule_path_validation.json"
    report = {
        "canonical_paths_collected": len(paths),
        "rules_checked": len(blocks),
        "fields_checked": total_fields,
        "failures": failures,
        "fail_count": len([f for f in failures if "field" in f]),
    }
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    print(f"rules={len(blocks)} fields={total_fields} non_resolving={report['fail_count']}")
    for f in failures:
        print("  FAIL", f)
    return 1 if report["fail_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
