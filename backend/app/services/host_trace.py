from __future__ import annotations

import csv
import io
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from fastapi import HTTPException, status


SYSCALL_MAP: dict[int, str] = {
    1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect",
    11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
    15: "rt_sigreturn", 16: "ioctl", 17: "pread64", 18: "pwrite64",
    19: "readv", 20: "writev", 21: "access", 22: "pipe", 23: "select",
    24: "sched_yield", 25: "mremap", 26: "msync", 27: "mincore",
    28: "madvise", 29: "shmget", 30: "shmat", 31: "shmctl",
    32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep", 36: "getitimer",
    37: "alarm", 38: "setitimer", 39: "getpid", 40: "sendfile",
    41: "socket", 42: "connect", 43: "accept", 44: "sendto",
    45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 48: "shutdown",
    49: "bind", 50: "listen", 51: "getsockname", 52: "getpeername",
    53: "socketpair", 54: "setsockopt", 55: "getsockopt", 56: "clone",
    57: "fork", 58: "vfork", 59: "execve", 60: "exit", 61: "wait4",
    62: "kill", 63: "uname", 64: "semget", 65: "semop", 66: "semctl",
    67: "shmdt", 68: "msgget", 69: "msgsnd", 70: "msgrcv", 71: "msgctl",
    72: "fcntl", 73: "flock", 74: "fsync", 75: "fdatasync",
    76: "truncate", 77: "ftruncate", 78: "getdents", 79: "getcwd",
    80: "chdir", 81: "fchdir", 82: "rename", 83: "mkdir", 84: "rmdir",
    85: "creat", 86: "link", 87: "unlink", 88: "symlink", 89: "readlink",
    90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown",
    95: "umask", 96: "gettimeofday", 97: "getrlimit", 98: "getrusage",
    99: "sysinfo", 100: "clock_gettime", 101: "clock_getres",
    102: "clock_nanosleep", 103: "exit_group", 104: "epoll_wait",
    105: "epoll_ctl", 106: "tgkill", 107: "utimes", 108: "vserver",
    109: "mbind", 110: "set_mempolicy", 111: "get_mempolicy",
    112: "mq_open", 113: "mq_unlink", 114: "mq_timedsend",
    115: "mq_timedreceive", 116: "mq_notify", 117: "mq_getsetattr",
    118: "kexec_load", 119: "waitid", 120: "add_key", 121: "request_key",
    122: "keyctl", 123: "ioprio_set", 124: "ioprio_get", 125: "inotify_init",
    126: "inotify_add_watch", 127: "inotify_rm_watch", 128: "migrate_pages",
    129: "openat", 130: "mkdirat", 131: "mknodat", 132: "fchownat",
    133: "futimesat", 134: "newfstatat", 135: "unlinkat", 136: "renameat",
    137: "linkat", 138: "symlinkat", 139: "readlinkat", 140: "fchmodat",
    141: "faccessat", 142: "pselect6", 143: "ppoll", 144: "unshare",
    145: "set_robust_list", 146: "get_robust_list", 147: "splice",
    148: "tee", 149: "sync_file_range", 150: "vmsplice",
    151: "move_pages", 152: "utimensat", 153: "epoll_pwait",
    154: "signalfd", 155: "timerfd_create", 156: "eventfd",
    157: "fallocate", 158: "timerfd_settime", 159: "timerfd_gettime",
    160: "accept4", 161: "signalfd4", 162: "eventfd2",
    163: "epoll_create1", 164: "dup3", 165: "pipe2", 166: "inotify_init1",
    167: "preadv", 168: "pwritev", 169: "rt_tgsigqueueinfo",
    170: "perf_event_open", 171: "recvmmsg", 172: "fanotify_init",
    173: "fanotify_mark", 174: "prlimit64", 175: "name_to_handle_at",
    176: "open_by_handle_at", 177: "clock_adjtime", 178: "syncfs",
    179: "sendmmsg", 180: "setns", 181: "getcpu", 182: "process_vm_readv",
    183: "process_vm_writev", 184: "kcmp", 185: "finit_module",
    186: "sched_setattr", 187: "sched_getattr", 188: "renameat2",
    189: "seccomp", 190: "getrandom", 191: "memfd_create",
    192: "kexec_file_load", 193: "bpf", 194: "execveat",
    195: "userfaultfd", 196: "membarrier", 197: "mlock2",
    198: "copy_file_range", 199: "preadv2", 200: "pwritev2",
    201: "pkey_mprotect", 202: "pkey_alloc", 203: "pkey_free",
    204: "statx", 205: "io_pgetevents", 206: "rseq",
    207: "kexec_file_load", 208: "pidfd_send_signal", 209: "io_uring_setup",
    210: "io_uring_enter", 211: "io_uring_register", 212: "open_tree",
    213: "move_mount", 214: "fsopen", 215: "fsconfig", 216: "fsmount",
    217: "fspick", 218: "pidfd_open", 219: "clone3", 220: "close_range",
    221: "openat2", 222: "pidfd_getfd", 223: "faccessat2",
    224: "process_madvise", 225: "epoll_pwait2", 226: "mount_setattr",
    227: "quotactl_fd", 228: "landlock_create_ruleset",
    229: "landlock_add_rule", 230: "landlock_restrict_self",
    231: "memfd_secret", 232: "process_mrelease", 233: "futex_waitv",
    234: "set_mempolicy_home_node", 235: "cachestat", 236: "fchmodat2",
}


def _resolve_syscall(syscall_id_str: str, syscall_name: str) -> str:
    name = syscall_name.strip() if syscall_name else ""
    if name:
        return name
    try:
        sid = int(syscall_id_str)
        return SYSCALL_MAP.get(sid, f"syscall_{sid}")
    except (ValueError, TypeError):
        return "unknown"


@dataclass(frozen=True)
class NetworkEventData:
    timestamp: datetime | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    connection_id: str | None
    syscall_name: str | None
    sequence_index: int
    event_index: int
    description: str | None = None


@dataclass(frozen=True)
class TraceSummary:
    event_count: int
    sequence_count: int
    unique_system_calls: int
    all_calls: list[str] = field(default_factory=list)
    network_events: list[NetworkEventData] = field(default_factory=list)


def _parse_timestamp(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        s = raw.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _parse_int(raw: object) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


def _parse_json(content: bytes) -> TraceSummary:
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Upload UTF-8 JSON containing a `sequences` array.",
        ) from error

    sequences = payload.get("sequences") if isinstance(payload, dict) else payload
    if not isinstance(sequences, list) or not sequences:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A trace must contain at least one sequence.",
        )

    calls: set[str] = set()
    all_calls: list[str] = []
    network_events: list[NetworkEventData] = []
    event_count = 0

    for seq_idx, sequence in enumerate(sequences):
        system_calls = sequence.get("system_calls") if isinstance(sequence, dict) else None
        if not isinstance(system_calls, list) or not system_calls:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Sequence {seq_idx} needs a non-empty `system_calls` array.",
            )
        if not all(isinstance(call, str) and call.strip() for call in system_calls):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Sequence {seq_idx} contains an invalid system call.",
            )
        event_count += len(system_calls)
        stripped = [call.strip() for call in system_calls]
        calls.update(stripped)
        all_calls.extend(stripped)

        raw_net = sequence.get("network_events") if isinstance(sequence, dict) else None
        if isinstance(raw_net, list):
            for evt_idx, evt in enumerate(raw_net):
                if not isinstance(evt, dict):
                    continue
                network_events.append(NetworkEventData(
                    timestamp=_parse_timestamp(evt.get("timestamp")),
                    source_ip=evt.get("source_ip") or evt.get("src_ip"),
                    destination_ip=evt.get("destination_ip") or evt.get("dst_ip"),
                    source_port=_parse_int(evt.get("source_port") or evt.get("src_port")),
                    destination_port=_parse_int(evt.get("destination_port") or evt.get("dst_port")),
                    protocol=evt.get("protocol"),
                    connection_id=evt.get("connection_id") or evt.get("conn_id"),
                    syscall_name=evt.get("syscall_name") or (stripped[evt_idx] if evt_idx < len(stripped) else None),
                    sequence_index=seq_idx,
                    event_index=evt_idx,
                    description=evt.get("description"),
                ))

    return TraceSummary(
        event_count=event_count,
        sequence_count=len(sequences),
        unique_system_calls=len(calls),
        all_calls=all_calls,
        network_events=network_events,
    )


def _parse_csv(content: bytes) -> TraceSummary:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="CSV file must be UTF-8 encoded.",
        ) from error

    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="CSV file appears to be empty.",
        )

    has_syscall_name = "syscall_name" in reader.fieldnames
    has_syscall_id = "syscall_id" in reader.fieldnames

    if not has_syscall_name and not has_syscall_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="CSV must contain a `syscall_name` or `syscall_id` column.",
        )

    has_network_cols = any(
        col in reader.fieldnames
        for col in ("source_ip", "src_ip", "destination_ip", "dst_ip")
    )

    traces: dict[str, list[str]] = defaultdict(list)
    network_events: list[NetworkEventData] = []
    row_count = 0
    trace_event_idx: dict[str, int] = defaultdict(int)
    trace_seq_idx: dict[str, int] = defaultdict(int)

    for row in reader:
        row_count += 1
        trace_id = row.get("trace_id", "0").strip()
        syscall_name = row.get("syscall_name", "").strip() if has_syscall_name else ""
        syscall_id = row.get("syscall_id", "").strip() if has_syscall_id else ""

        resolved = _resolve_syscall(syscall_id, syscall_name)
        traces[trace_id].append(resolved)

        if has_network_cols:
            src_ip = row.get("source_ip") or row.get("src_ip") or ""
            dst_ip = row.get("destination_ip") or row.get("dst_ip") or ""
            if src_ip.strip() or dst_ip.strip():
                evt_idx = trace_event_idx[trace_id]
                seq_idx = trace_seq_idx[trace_id]
                network_events.append(NetworkEventData(
                    timestamp=_parse_timestamp(row.get("timestamp")),
                    source_ip=src_ip.strip() or None,
                    destination_ip=dst_ip.strip() or None,
                    source_port=_parse_int(row.get("source_port") or row.get("src_port")),
                    destination_port=_parse_int(row.get("destination_port") or row.get("dst_port")),
                    protocol=(row.get("protocol") or "").strip() or None,
                    connection_id=(row.get("connection_id") or row.get("conn_id") or "").strip() or None,
                    syscall_name=resolved if resolved != "unknown" else None,
                    sequence_index=seq_idx,
                    event_index=evt_idx,
                    description=None,
                ))
                trace_event_idx[trace_id] = evt_idx + 1
                if trace_event_idx[trace_id] % 500 == 0:
                    trace_seq_idx[trace_id] = seq_idx + 1

    if not traces:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="CSV contains no data rows.",
        )

    calls: set[str] = set()
    all_calls: list[str] = []
    event_count = 0

    for trace_calls in traces.values():
        event_count += len(trace_calls)
        calls.update(trace_calls)
        all_calls.extend(trace_calls)

    return TraceSummary(
        event_count=event_count,
        sequence_count=len(traces),
        unique_system_calls=len(calls),
        all_calls=all_calls,
        network_events=network_events,
    )


def summarize_host_trace(content: bytes, *, max_upload_mb: int) -> TraceSummary:
    if len(content) > max_upload_mb * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Trace files must be {max_upload_mb} MB or smaller.",
        )

    stripped = content.lstrip()
    if stripped[:1] in (b"{", b"["):
        return _parse_json(content)
    return _parse_csv(content)
