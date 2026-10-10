from __future__ import annotations

from sentinel_ingest.envelope import (
    basename_windows,
    hex_pid,
    parse_evtx_time,
    parse_sysmon_time,
    split_domain_user,
    split_hashes,
    state_inferred,
    state_invalid,
    state_null,
    state_unknown,
)


def test_evtx_time_truncates_to_microseconds_keeps_original():
    t = parse_evtx_time("2026-01-02T03:04:05.1234567Z")
    assert t["utc"] == "2026-01-02T03:04:05.123456Z"
    assert t["original"] == "2026-01-02T03:04:05.1234567Z"
    assert t["state"] == "ok"
    assert t["timezone_source"] == "source_explicit"


def test_evtx_time_missing_is_unknown():
    t = parse_evtx_time(None)
    assert t["utc"] is None
    assert t["state"] == "unknown"
    assert "original" not in t


def test_evtx_time_offset_rejected_invalid():
    t = parse_evtx_time("2026-01-02T03:04:05.1+02:00")
    assert t["state"] == "invalid"
    assert t["utc"] is None


def test_sysmon_time_inferred_documented_utc():
    t = parse_sysmon_time("2026-01-02 03:04:05.123")
    assert t["utc"] == "2026-01-02T03:04:05.123Z"
    assert t["state"] == "inferred"
    assert t["timezone_source"] == "source_documented_utc"


def test_hex_pid_state_object():
    p = hex_pid("0x4c8")
    assert p == {"$state": "inferred", "$note": "hex 0x4c8→int", "$raw": "0x4c8"}
    bad = hex_pid("zzz")
    assert bad["$state"] == "invalid"


def test_state_helpers_shapes():
    assert state_null() == {"$state": "null"}
    assert state_null("x") == {"$state": "null", "$raw": "x"}
    assert state_unknown() == {"$state": "unknown"}
    assert state_unknown("why") == {"$state": "unknown", "$note": "why"}
    inv = state_invalid("abc", "not an int")
    assert inv == {"$state": "invalid", "$note": "not an int", "$raw": "abc"}
    inf = state_inferred("mapped", raw="1")
    assert inf == {"$state": "inferred", "$note": "mapped", "$raw": "1"}


def test_basename_windows():
    assert basename_windows("C:\\Windows\\System32\\cmd.exe") == "cmd.exe"
    assert basename_windows("cmd.exe") == "cmd.exe"


def test_split_domain_user():
    out, unmapped = split_domain_user("NT AUTHORITY\\SYSTEM")
    assert out == {"domain": "NT AUTHORITY", "name": "SYSTEM"}
    out2, _ = split_domain_user("SYSTEM")
    assert out2 == {"name": "SYSTEM"}
    out3, _ = split_domain_user("S-1-5-18")
    assert out3 == {}


def test_split_hashes():
    raw = "SHA256=AAA,MD5=BBB,IMPHASH=CCC"
    out, _ = split_hashes(raw)
    assert out["sha256"] == "AAA"
    assert out["md5"] == "BBB"
