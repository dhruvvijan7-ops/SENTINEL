"""M1 content bullets: "API boots" and "worker boots".

Both are proven by starting the real processes as separate processes — an
import-only check would not prove the entry points, the config loader, the
lifespan bootstrap and the logging wiring actually come up.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "config.example.toml"


def _env(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("SENTINEL_CONFIG", str(CONFIG))
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra)
    return env


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for(url: str, proc: subprocess.Popen, read_log, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(
                f"process exited {proc.returncode} before {url} answered.\n{read_log()}"
            )
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    return
                last = f"HTTP {resp.status}"
        except (urllib.error.URLError, OSError) as exc:
            last = str(exc)
        time.sleep(0.5)
    raise AssertionError(f"{url} never returned 200 ({last}).\n{read_log()}")


def test_api_process_boots_and_serves_health(tmp_path):
    port = _free_port()
    log = tmp_path / "api.log"
    url = f"http://127.0.0.1:{port}"

    def read_log() -> str:
        return log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""

    with log.open("wb") as fh:
        proc = subprocess.Popen(
            [sys.executable, "-m", "sentinel_api.main"],
            cwd=str(ROOT),
            env=_env(
                SENTINEL_SERVER__PORT=str(port),
                SENTINEL_STORAGE__ROOT=str(tmp_path / "objects"),
            ),
            stdout=fh,
            stderr=subprocess.STDOUT,
        )
        try:
            _wait_for(f"{url}/health", proc, read_log)

            with urllib.request.urlopen(f"{url}/metrics", timeout=5) as resp:
                assert resp.status == 200
                metrics_body = resp.read().decode()
            assert "sentinel_http_requests_total" in metrics_body

            try:
                with urllib.request.urlopen(f"{url}/ready", timeout=5) as resp:
                    ready_status, ready_body = resp.status, resp.read().decode()
            except urllib.error.HTTPError as exc:
                ready_status, ready_body = exc.code, exc.read().decode()
            # /ready is 503 whenever a check degrades (e.g. a stale queued job);
            # the process booted either way, so only the shape is asserted here.
            assert ready_status in (200, 503), ready_body
            for check in ("database", "object_store", "queue"):
                assert f'"{check}"' in ready_body, ready_body
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=20)

    text = read_log()
    assert "principal_bootstrap_failed" not in text, text


def test_worker_process_boots_and_exits_zero(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel_worker.main", "--once"],
        cwd=str(ROOT),
        env=_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
    )
    text = proc.stdout.decode("utf-8", errors="replace")
    (tmp_path / "worker.log").write_text(text, encoding="utf-8")
    assert proc.returncode == 0, text
    assert "worker.once_done" in text, text
    assert "Traceback (most recent call last)" not in text, text
