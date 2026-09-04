"""
Convert CHASE-LB dataset to Sentinel host-trace format.

Directory structure:
  chase-lb/
    Attack_Trace/
      CVE_xxx_Trace/
        *.csv          (label=1)
    Normal_Trace/
      *.csv            (label=0)

Sentinel format:
  { "sequences": [ { "system_calls": ["read", "write", ...] }, ... ] }

Usage:
  python scripts/convert_kaggle_chase_lb.py
  (reads from C:/Users/dhruv/chase-lb, writes to C:/Users/dhruv/converted)
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

# x86_64 Linux syscall ID -> name (numbers 1-300 used by CHASE-LB)
# Source: linux/arch/x86/entry/syscalls/syscall_64.tbl
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
    237: "fcachestat", 238: "faccess", 239: "process_advise",
    240: "epoll_wait2", 241: "io_uring_enter2", 242: "io_register",
    243: "io_setup2", 244: "io_submit", 245: "io_cancel",
    246: "io_getevents", 247: "io_destroy", 248: "io_set_fsync",
    249: "io_read", 250: "io_write", 251: "io_stat", 252: "io_fsync",
    253: "io_rdma", 254: "io_close", 255: "io_cancel2", 256: "io_restart",
    257: "open", 258: "stat", 259: "fstat", 260: "lstat",
    261: "access", 262: "chmod", 263: "chown", 264: "link",
    265: "unlink", 266: "rename", 267: "mkdir", 268: "rmdir",
    269: "readlink", 270: "symlink", 271: "mknod", 272: "truncate",
    273: "ftruncate", 274: "creat", 275: "getdents", 276: "fcntl2",
    277: "socket2", 278: "connect2", 279: "accept2", 280: "sendto2",
    281: "recvfrom2", 282: "sendmsg2", 283: "recvmsg2", 284: "shutdown2",
    285: "bind2", 286: "listen2", 287: "getsockname2", 288: "getpeername2",
    289: "socketpair2", 290: "setsockopt2", 291: "getsockopt2",
    292: "clone2", 293: "execve2", 294: "wait4", 295: "kill2",
    296: "uname2", 297: "semget2", 298: "semop2", 299: "semctl2",
    300: "shmdt2",
}


def resolve_syscall(syscall_id_str: str, syscall_name: str) -> str:
    name = syscall_name.strip() if syscall_name else ""
    if name:
        return name
    try:
        sid = int(syscall_id_str)
        return SYSCALL_MAP.get(sid, f"syscall_{sid}")
    except (ValueError, TypeError):
        return "unknown"


def convert_csv(csv_path: Path, default_label: int) -> list[dict]:
    traces: dict[str, list[str]] = defaultdict(list)
    labels: dict[str, str] = {}

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            trace_id = row["trace_id"].strip()
            syscall_name = row.get("syscall_name", "")
            syscall_id = row.get("syscall_id", "")
            label = int(row.get("label", str(default_label)).strip())

            resolved = resolve_syscall(syscall_id, syscall_name)
            traces[trace_id].append(resolved)
            labels[trace_id] = "attack" if label == 1 else "normal"

    results = []
    for trace_id, calls in traces.items():
        if calls:
            results.append({
                "trace_id": trace_id,
                "label": labels[trace_id],
                "system_calls": calls,
            })
    return results


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("C:/Users/dhruv/chase-lb")
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("C:/Users/dhruv/converted")
    out_dir.mkdir(parents=True, exist_ok=True)

    all_traces = []
    file_count = 0

    attack_dir = root / "Attack_Trace"
    if attack_dir.is_dir():
        for csv_path in sorted(attack_dir.rglob("*.csv")):
            traces = convert_csv(csv_path, default_label=1)
            all_traces.extend(traces)
            file_count += 1
            print(f"  [attack] {csv_path.parent.name}/{csv_path.name}: {len(traces)} traces")

    normal_dir = root / "Normal_Trace"
    if normal_dir.is_dir():
        for csv_path in sorted(normal_dir.rglob("*.csv")):
            traces = convert_csv(csv_path, default_label=0)
            all_traces.extend(traces)
            file_count += 1
            print(f"  [normal] {csv_path.name}: {len(traces)} traces")

    sequences = [{"system_calls": t["system_calls"]} for t in all_traces]
    labels = {f"trace_{i}_{t['trace_id']}": t["label"] for i, t in enumerate(all_traces)}

    output = {
        "source": "CHASE-LB",
        "labels": labels,
        "sequences": sequences,
    }

    out_path = out_dir / "chase_lb.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f)

    total_calls = sum(len(s["system_calls"]) for s in sequences)
    print(f"\nDone: {file_count} CSV files -> {len(sequences)} traces, {total_calls} total calls")
    print(f"Output: {out_path}")
    print(f"Upload {out_path} via the Sentinel Analysis page.")


if __name__ == "__main__":
    main()
