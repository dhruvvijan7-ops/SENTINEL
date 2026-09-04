"""
Batch upload CHASE-LB traces to Sentinel.

Splits the converted JSON into individual traces and uploads each
via POST /api/analysis-runs/host-traces (multipart form upload).

Usage:
  1. Start the backend: cd backend && uvicorn app.main:app --reload
  2. python scripts/batch_upload_chase_lb.py --email X --password Y
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

API_BASE = "http://127.0.0.1:8000/api"


def login(email: str, password: str) -> str:
    data = json.dumps({"email": email, "password": password}).encode()
    req = Request(f"{API_BASE}/auth/login", data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req) as resp:
        body = json.loads(resp.read())
        return body.get("token") or body.get("access_token")


def upload_trace(token: str, system_calls: list[str]) -> dict:
    boundary = "----SentinelBatchUpload"
    body_lines = []
    body_lines.append(f"--{boundary}")
    body_lines.append('Content-Disposition: form-data; name="file"; filename="trace.json"')
    body_lines.append("Content-Type: application/json")
    body_lines.append("")
    body_lines.append(json.dumps({"sequences": [{"system_calls": system_calls}]}))
    body_lines.append(f"--{boundary}--")
    body = "\r\n".join(body_lines).encode("utf-8")

    req = Request(
        f"{API_BASE}/analysis-runs/host-traces",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urlopen(req) as resp:
        return json.loads(resp.read())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--json", default="C:/Users/dhruv/converted/chase_lb.json")
    parser.add_argument("--limit", type=int, default=0, help="Max traces to upload (0=all)")
    parser.add_argument("--delay", type=float, default=0.1, help="Seconds between uploads")
    args = parser.parse_args()

    token = login(args.email, args.password)
    print(f"Logged in as {args.email}")

    with open(args.json, encoding="utf-8") as f:
        data = json.load(f)

    sequences = data["sequences"]
    if args.limit > 0:
        sequences = sequences[: args.limit]

    print(f"Uploading {len(sequences)} traces to Sentinel...")
    print()

    success = 0
    failed = 0
    start = time.time()

    for i, seq in enumerate(sequences):
        calls = seq["system_calls"]
        try:
            result = upload_trace(token, calls)
            success += 1
            elapsed = time.time() - start
            rate = success / elapsed if elapsed > 0 else 0
            print(f"  [{i + 1}/{len(sequences)}] OK — {len(calls)} calls, run={result['id'][:8]}... ({rate:.1f}/s)")
            time.sleep(args.delay)
        except HTTPError as e:
            failed += 1
            body = e.read().decode() if e.fp else ""
            print(f"  [{i + 1}/{len(sequences)}] FAIL — {e.code}: {body[:120]}")
            if e.code == 401:
                print("  Token expired. Re-run with fresh credentials.")
                sys.exit(1)
        except Exception as e:
            failed += 1
            print(f"  [{i + 1}/{len(sequences)}] ERROR — {e}")

    elapsed = time.time() - start
    print()
    print(f"Done in {elapsed:.1f}s — {success} uploaded, {failed} failed")
    print("Check the Monitoring page for detections.")


if __name__ == "__main__":
    main()
