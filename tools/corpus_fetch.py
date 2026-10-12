#!/usr/bin/env python3
"""Pin + fetch the out-of-tree corpora (D6-009: nothing here is committed).

Pinned sources (Apache-2.0 unless noted):
  - `evtx-rs` sample EVTX files (https://github.com/omerbenamram/evtx,
    Apache-2.0): synthetic Sysmon/Security captures used for mapping tests.
  - Local harvest via `wevtutil epl` (this machine's own System channel) is
    the primary e2e fixture; this tool is the reproducible cross-machine
    fallback and CI corpus.
  - UNSW-NB15 (§6.3a, M2 exit ⑥): academic-use only, commercial prohibited
    (V-6-035, VERIFIED 2026-10-12). sha256 + row counts are pinned in
    `tools/evaluate_unsw_nb15.py:PINNED`; the citation manifest it writes is
    part of the scoring gate — a run without attribution fails.

Everything lands in `.corpus/` (gitignored).  Each file's sha256 is printed so
the pinned digests can be recorded in the run report.  Network access is
required only when the digest cache is cold.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CORPUS_DIR = ROOT / ".corpus"

# (relative path, url, expected sha256 or None=record-only)
# URLs pinned to a full commit SHA (master tip 7479d02, verified via GitHub
# API 2026-10-10), never a branch.
_PINNED: list[tuple[str, str, str | None]] = [
    (
        "evtx-rs/sysmon.evtx",
        "https://raw.githubusercontent.com/omerbenamram/evtx"
        "/7479d02dfaa3bdeb41c5ea87195e84116a032cfc/samples/sysmon.evtx",
        "e1817fd7241ad2b5b9660e179adec878d157f1fa25333e52aef263c69bcd970b",
    ),
    (
        "evtx-rs/security.evtx",
        "https://raw.githubusercontent.com/omerbenamram/evtx"
        "/7479d02dfaa3bdeb41c5ea87195e84116a032cfc/samples/security.evtx",
        "5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d",
    ),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def harvest_local_system(dest: Path) -> Path | None:
    """Best-effort local harvest: export mapped System EIDs via wevtutil."""
    import shutil
    import subprocess

    wevtutil = shutil.which("wevtutil")
    if wevtutil is None:
        return None
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    query = "*[System[(EventID=7036 or 7045 or 7040 or 7034 or 7043)]]"
    proc = subprocess.run(
        [wevtutil, "epl", "System", str(dest), f"/q:{query}"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not dest.exists():
        print(f"local harvest skipped: {proc.stderr.strip()}", file=sys.stderr)
        return None
    return dest


def fetch_unsw_nb15() -> int:
    """UNSW-NB15: pinned CSVs + the citation manifest the scoring gate reads.

    Unlike the best-effort EVTX harvest above, every failure here is fatal
    (non-zero exit): the M2 exit ⑥ gate depends on this corpus, and a silent
    skip would turn "no data" into "no detections".
    """
    from tools.evaluate_unsw_nb15 import CITATION, CORPUS_DIR, MANIFEST, PINNED

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    existing = (
        json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {}
    )
    files: dict = dict(existing.get("files") or {})
    fetched = False
    for name, spec in PINNED.items():
        dest = CORPUS_DIR / name
        if not dest.exists():
            print(f"fetching {spec['url']}")
            fetched = True
            try:
                with urllib.request.urlopen(spec["url"], timeout=120) as resp:
                    with dest.open("wb") as out:
                        shutil.copyfileobj(resp, out)
            except OSError as exc:
                print(f"FAIL: could not fetch {name}: {exc}", file=sys.stderr)
                return 2
        digest = sha256_file(dest)
        if digest != spec["sha256"]:
            print(f"DRIFT: {name} sha256 {digest} != pinned {spec['sha256']}",
                  file=sys.stderr)
            return 2
        size = dest.stat().st_size
        if size != spec["bytes"]:
            print(f"DRIFT: {name} {size} bytes != pinned {spec['bytes']}",
                  file=sys.stderr)
            return 2
        entry = dict(files.get(name) or {})
        entry.update({"url": spec["url"], "sha256": digest, "bytes": size,
                      "rows": spec["rows"]})
        files[name] = entry
        print(f"{digest}  {size:>10}  unsw-nb15/{name}")

    manifest = {
        "dataset": "UNSW-NB15",
        "citation": CITATION,  # §6.3a: attribution is part of the gate
        "fetched_at": existing.get("fetched_at")
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": files,
    }
    if fetched or MANIFEST.read_text(encoding="utf-8") != json.dumps(manifest, indent=2) + "\n":
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"manifest: {MANIFEST.relative_to(ROOT)} (citation present)")
    return 0


def main() -> int:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []
    for rel, url, pinned in _PINNED:
        dest = CORPUS_DIR / rel
        if not dest.exists():
            print(f"fetching {url}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                with urllib.request.urlopen(url, timeout=60) as resp:
                    dest.write_bytes(resp.read())
            except OSError as exc:
                print(f"  skipped ({exc})", file=sys.stderr)
                continue
        digest = sha256_file(dest)
        if pinned and pinned != digest:
            print(f"DRIFT: {rel} sha256 {digest} != pinned {pinned}", file=sys.stderr)
            return 2
        manifest.append((rel, dest.stat().st_size, digest))
        print(f"{digest}  {dest.stat().st_size:>10}  {rel}")

    local = harvest_local_system(Path.home() / "AppData" / "Local" / "Temp" / "opencode" / "sentinel_local_system.evtx")
    if local is not None:
        digest = sha256_file(local)
        manifest.append((str(local), local.stat().st_size, digest))
        print(f"{digest}  {local.stat().st_size:>10}  {local}")

    print(f"\ncorpus directory: {CORPUS_DIR}")

    status = fetch_unsw_nb15()
    if status:
        return status
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
