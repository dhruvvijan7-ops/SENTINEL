"""Local content-addressed object store (hot tier, file:// URIs)."""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import BinaryIO

from sentinel_core.errors import GateEmptyFile, GateFileTooLarge, GateStoreWriteFailed

_CHUNK = 1024 * 1024


class LocalObjectStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, sha256_hex: str) -> Path:
        return self.root / sha256_hex[:2] / sha256_hex

    def uri_for(self, sha256_hex: str) -> str:
        return self.path_for(sha256_hex).resolve().as_uri()

    def write_stream(
        self, src: BinaryIO, *, max_bytes: int
    ) -> tuple[str, int, str, str, str]:
        """Stream `src` to the store.  Returns (sha256, size, storage_uri,
        sha1, md5).  Raises GATE_EMPTY_FILE / GATE_FILE_TOO_LARGE /
        GATE_STORE_WRITE_FAILED."""
        tmp = tempfile.NamedTemporaryFile(
            mode="wb", dir=self.root, prefix=".incoming-", delete=False
        )
        sha = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()
        size = 0
        try:
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise GateFileTooLarge(
                        f"file exceeds max_file_bytes={max_bytes}",
                        details={"max_file_bytes": max_bytes},
                    )
                sha.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)
                tmp.write(chunk)
            tmp.flush()
            os.fsync(tmp.fileno())
        finally:
            tmp.close()
        if size == 0:
            os.unlink(tmp.name)
            raise GateEmptyFile("uploaded file is empty")
        sha_hex = sha.hexdigest()
        dest = self.path_for(sha_hex)
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(tmp.name, dest)
        except OSError as exc:
            os.unlink(tmp.name)
            raise GateStoreWriteFailed(f"object store write failed: {exc}") from exc
        return sha_hex, size, dest.resolve().as_uri(), sha1.hexdigest(), md5.hexdigest()
