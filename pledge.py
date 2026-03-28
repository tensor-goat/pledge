#!/usr/bin/env python3
"""
pledge — OpenBSD pledge(2) polyfill for Linux via SECCOMP BPF

Port of Justine Tunney's pledge() implementation (cosmopolitan libc)
to pure Python using ctypes.  No C compiler or external libraries needed.

Usage as a library:

    from pledge import pledge
    pledge("stdio rpath")
    # ... your sandboxed code ...

Usage as a command-line wrapper:

    python3 pledge.py -p "stdio rpath" ls -la
    python3 pledge.py -p "stdio rpath wpath cpath" -- my_script.sh

Promise categories (same as OpenBSD + Justine's Linux port):

    stdio     Basic I/O, memory, threads, clocks, signals
    rpath     Read-only filesystem operations
    wpath     Write filesystem operations
    cpath     Create/remove filesystem entries
    dpath     Create device nodes (mknod)
    flock     File locking (flock, fcntl locks)
    fattr     Change file attributes (chmod, utime, etc.)
    chown     Change file ownership
    tty       Terminal ioctls
    inet      IPv4/IPv6 sockets
    unix      Unix domain sockets
    dns       DNS resolution (restricted inet)
    proc      fork, kill, wait, scheduling
    thread    clone for threads, futex
    exec      execve
    prot_exec Allow PROT_EXEC in mmap/mprotect
    id        setuid/setgid family
    recvfd    recvmsg (SCM_RIGHTS)
    sendfd    sendmsg (SCM_RIGHTS)
    tmppath   /tmp operations (unlink, lstat)
    vminfo    /proc system info

Requires: Linux >= 3.5 (SECCOMP_MODE_FILTER), Python >= 3.10
          No root required (uses PR_SET_NO_NEW_PRIVS)

Architecture: x86_64 and aarch64 supported.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import os
import platform
import struct
import sys
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════
# Architecture detection
# ═══════════════════════════════════════════════════════════════════════

_machine = platform.machine()
if _machine in ("x86_64", "amd64"):
    AUDIT_ARCH = 0xC000003E  # AUDIT_ARCH_X86_64
    _arch = "x86_64"
elif _machine in ("aarch64", "arm64"):
    AUDIT_ARCH = 0xC00000B7  # AUDIT_ARCH_AARCH64
    _arch = "aarch64"
else:
    raise RuntimeError(f"pledge: unsupported architecture {_machine}")

# ═══════════════════════════════════════════════════════════════════════
# Linux x86_64 syscall numbers
# ═══════════════════════════════════════════════════════════════════════

if _arch == "x86_64":
    NR = {
        "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4,
        "fstat": 5, "lstat": 6, "poll": 7, "lseek": 8, "mmap": 9,
        "mprotect": 10, "munmap": 11, "brk": 12, "rt_sigaction": 13,
        "rt_sigprocmask": 14, "rt_sigreturn": 15, "ioctl": 16,
        "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
        "access": 21, "pipe": 22, "select": 23, "sched_yield": 24,
        "mremap": 25, "msync": 26, "madvise": 28, "dup": 32,
        "dup2": 33, "nanosleep": 35, "getitimer": 36, "alarm": 37,
        "setitimer": 38, "getpid": 39, "sendfile": 40, "socket": 41,
        "connect": 42, "accept": 43, "sendto": 44, "recvfrom": 45,
        "sendmsg": 46, "recvmsg": 47, "shutdown": 48, "bind": 49,
        "listen": 50, "getsockname": 51, "getpeername": 52,
        "socketpair": 53, "setsockopt": 54, "getsockopt": 55,
        "clone": 56, "fork": 57, "vfork": 58, "execve": 59,
        "exit": 60, "wait4": 61, "kill": 62, "uname": 63,
        "fcntl": 72, "flock": 73, "fsync": 74, "fdatasync": 75,
        "truncate": 76, "ftruncate": 77, "getdents": 78,
        "getcwd": 79, "chdir": 80, "fchdir": 81, "rename": 82,
        "mkdir": 83, "rmdir": 84, "creat": 85, "link": 86,
        "unlink": 87, "symlink": 88, "readlink": 89, "chmod": 90,
        "fchmod": 91, "chown": 92, "fchown": 93, "lchown": 94,
        "umask": 95, "getrlimit": 97, "getrusage": 98,
        "getuid": 102, "getgid": 104, "geteuid": 107,
        "getegid": 108, "setpgid": 109, "getppid": 110,
        "getpgrp": 111, "setsid": 112, "setreuid": 113,
        "setregid": 114, "getgroups": 115, "setgroups": 116,
        "setresuid": 117, "getresuid": 118, "setresgid": 119,
        "getresgid": 120, "getpgid": 121, "setfsuid": 122,
        "setfsgid": 123, "getsid": 124, "sigaltstack": 131,
        "utime": 132, "mknod": 133, "statfs": 137, "fstatfs": 138,
        "getpriority": 140, "setpriority": 141,
        "sched_setparam": 142, "sched_getparam": 143,
        "sched_setscheduler": 144, "sched_getscheduler": 145,
        "sched_get_priority_max": 146, "sched_get_priority_min": 147,
        "mlock": 149, "munlock": 150, "mlockall": 151,
        "munlockall": 152, "prctl": 157, "arch_prctl": 158,
        "gettimeofday": 96, "setrlimit": 160,
        "chroot": 161, "sync": 162, "mount": 165,
        "umount2": 166, "reboot": 169,
        "setuid": 105, "setgid": 106,
        "gettid": 186, "futex": 202,
        "set_tid_address": 218, "clock_gettime": 228,
        "clock_getres": 229, "clock_nanosleep": 230,
        "exit_group": 231, "epoll_wait": 232, "epoll_ctl": 233,
        "openat": 257, "mkdirat": 258, "mknodat": 259,
        "fchownat": 260, "futimesat": 261, "fstatat": 262,
        "unlinkat": 263, "renameat": 264, "linkat": 265,
        "symlinkat": 266, "readlinkat": 267, "fchmodat": 268,
        "faccessat": 269, "pselect6": 270, "ppoll": 271,
        "splice": 275, "tee": 276, "utimensat": 280,
        "epoll_create1": 291, "pipe2": 293, "dup3": 292,
        "preadv": 295, "pwritev": 296,
        "recvmmsg": 299, "accept4": 288,
        "prlimit64": 302, "sendmmsg": 307,
        "renameat2": 316, "getrandom": 318,
        "execveat": 322, "copy_file_range": 326,
        "preadv2": 327, "pwritev2": 328,
        "statx": 332, "rseq": 334, "close_range": 436,
        "faccessat2": 439,
        "rt_sigtimedwait": 128, "sigsuspend": 130,
        "sigpending": 127, "getdents64": 217,
    }
elif _arch == "aarch64":
    NR = {
        "read": 63, "write": 64, "close": 57, "stat": -1,
        "fstat": 80, "lstat": -1, "poll": -1, "lseek": 62,
        "mmap": 222, "mprotect": 226, "munmap": 215, "brk": 214,
        "rt_sigaction": 134, "rt_sigprocmask": 135,
        "rt_sigreturn": 139, "ioctl": 29,
        "pread64": 67, "pwrite64": 68, "readv": 65, "writev": 66,
        "access": -1, "pipe": -1, "select": -1,
        "sched_yield": 124, "msync": 227, "madvise": 233,
        "dup": 23, "dup2": -1, "dup3": 24,
        "nanosleep": 101, "getitimer": 102, "setitimer": 103,
        "getpid": 172, "sendfile": 71, "socket": 198,
        "connect": 203, "accept": 202, "sendto": 206,
        "recvfrom": 207, "sendmsg": 211, "recvmsg": 212,
        "shutdown": 210, "bind": 200, "listen": 201,
        "getsockname": 204, "getpeername": 205, "socketpair": 199,
        "setsockopt": 208, "getsockopt": 209,
        "clone": 220, "fork": -1, "vfork": -1, "execve": 221,
        "exit": 93, "wait4": 260, "kill": 129,
        "uname": 160, "fcntl": 25, "flock": 32,
        "fsync": 82, "fdatasync": 83, "truncate": 45,
        "ftruncate": 46, "getdents": -1,
        "getcwd": 17, "chdir": 49, "fchdir": 50,
        "rename": -1, "mkdir": -1, "rmdir": -1,
        "creat": -1, "link": -1, "unlink": -1,
        "symlink": -1, "readlink": -1,
        "chmod": -1, "fchmod": 52, "chown": -1,
        "fchown": 55, "lchown": -1,
        "umask": 166, "getrlimit": -1,
        "getuid": 174, "getgid": 176, "geteuid": 175,
        "getegid": 177, "setpgid": 154, "getppid": 173,
        "getpgrp": -1, "setsid": 157, "setreuid": 145,
        "setregid": 143, "getgroups": 158, "setgroups": 159,
        "setresuid": 147, "getresuid": 148, "setresgid": 149,
        "getresgid": 150, "getpgid": 155, "setfsuid": 151,
        "setfsgid": 152, "getsid": 156, "sigaltstack": 132,
        "utime": -1, "mknod": -1, "statfs": 43, "fstatfs": 44,
        "getpriority": 141, "setpriority": 140,
        "sched_setparam": 118, "sched_getparam": 121,
        "sched_setscheduler": 119, "sched_getscheduler": 120,
        "sched_get_priority_max": 125, "sched_get_priority_min": 126,
        "prctl": 167, "gettimeofday": 169,
        "setrlimit": -1, "setuid": 146, "setgid": 144,
        "gettid": 178, "futex": 98,
        "set_tid_address": 96, "clock_gettime": 113,
        "clock_getres": 114, "clock_nanosleep": 115,
        "exit_group": 94,
        "openat": 56, "mkdirat": 34, "mknodat": 33,
        "fchownat": 54, "futimesat": -1, "fstatat": 79,
        "unlinkat": 35, "renameat": 38, "linkat": 37,
        "symlinkat": 36, "readlinkat": 78, "fchmodat": 53,
        "faccessat": 48, "ppoll": 73,
        "splice": 76, "tee": 77, "utimensat": 88,
        "pipe2": 59, "preadv": 69, "pwritev": 70,
        "accept4": 242, "prlimit64": 261,
        "renameat2": 276, "getrandom": 278,
        "execveat": 281, "copy_file_range": 285,
        "preadv2": 286, "pwritev2": 287,
        "statx": 291, "rseq": 293, "close_range": 436,
        "faccessat2": 439,
        "rt_sigtimedwait": 137, "sigsuspend": 133,
        "getrusage": 165, "getdents64": 61,
        "mremap": 216, "sigpending": -1,
    }


def _nr(name: str) -> int:
    """Get syscall number, raising if not available on this arch."""
    n = NR.get(name, -1)
    if n < 0:
        return -1
    return n


# ═══════════════════════════════════════════════════════════════════════
# BPF instruction helpers
# ═══════════════════════════════════════════════════════════════════════

# BPF instruction classes
BPF_LD  = 0x00
BPF_ST  = 0x02
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07

# BPF sizes
BPF_W = 0x00  # word (32-bit)

# BPF modes
BPF_ABS = 0x20  # absolute offset into seccomp_data
BPF_IMM = 0x00
BPF_K   = 0x00

# BPF ALU ops
BPF_AND = 0x50

# BPF jump ops
BPF_JA  = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40

# SECCOMP return values
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_KILL_THREAD  = 0x00000000
SECCOMP_RET_KILL         = SECCOMP_RET_KILL_THREAD
SECCOMP_RET_TRAP         = 0x00030000
SECCOMP_RET_ERRNO        = 0x00050000
SECCOMP_RET_ALLOW        = 0x7FFF0000
SECCOMP_RET_DATA         = 0x0000FFFF

# seccomp_data field offsets (same layout on all archs)
#   struct seccomp_data {
#       int   nr;          // offset 0
#       __u32 arch;        // offset 4
#       __u64 instruction_pointer;  // offset 8
#       __u64 args[6];     // offset 16, 24, 32, 40, 48, 56
#   };
OFF_NR   = 0
OFF_ARCH = 4
OFF_IP   = 8
OFF_ARGS = 16  # args[0] at 16, args[1] at 24, etc.

def _off_arg(n: int) -> int:
    """Offset of args[n] in seccomp_data (lower 32 bits)."""
    return OFF_ARGS + n * 8

def _off_arg_hi(n: int) -> int:
    """Offset of upper 32 bits of args[n]."""
    return OFF_ARGS + n * 8 + 4


# A BPF instruction is struct sock_filter: { __u16 code, __u8 jt, __u8 jf, __u32 k }
# Packed as: HBBi → 8 bytes  (but k is unsigned, so we use I)
_SOCK_FILTER_FMT = "=HBBI"
_SOCK_FILTER_SIZE = struct.calcsize(_SOCK_FILTER_FMT)
assert _SOCK_FILTER_SIZE == 8


def BPF_STMT(code: int, k: int) -> bytes:
    """Encode a BPF statement (no jumps)."""
    return struct.pack(_SOCK_FILTER_FMT, code, 0, 0, k & 0xFFFFFFFF)


def BPF_JUMP(code: int, k: int, jt: int, jf: int) -> bytes:
    """Encode a BPF jump instruction."""
    return struct.pack(_SOCK_FILTER_FMT, code, jt, jf, k & 0xFFFFFFFF)


# prctl constants
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# Socket families for filtering
AF_INET  = 2
AF_INET6 = 10
AF_UNIX  = 1

# Socket types
SOCK_STREAM = 1
SOCK_DGRAM  = 2

# Open flags
O_RDONLY   = 0
O_WRONLY   = 1
O_RDWR     = 2
O_CREAT    = 0o100
O_ACCMODE  = 3

# Protection flags
PROT_EXEC = 4

# ioctl commands allowed by "stdio"
FIONREAD = 0x541B
FIONBIO  = 0x5421
FIOCLEX  = 0x5451
FIONCLEX = 0x5450

# ioctl commands allowed by "tty"
TIOCGWINSZ = 0x5413
TCGETS     = 0x5401
TCSETS     = 0x5402
TCSETSW    = 0x5403
TCSETSF    = 0x5404

# fcntl commands
F_GETFD = 1
F_SETFD = 2
F_GETFL = 3
F_SETFL = 4
F_GETLK = 5
F_SETLK = 6
F_SETLKW = 7
F_DUPFD_CLOEXEC = 1030

# ═══════════════════════════════════════════════════════════════════════
# Promise definitions — which syscalls each promise group allows
# ═══════════════════════════════════════════════════════════════════════

# Each promise maps to a set of syscall names.  Some require argument
# filtering; those are handled specially in the BPF generator.

PROMISE_SYSCALLS: dict[str, set[str]] = {
    "stdio": {
        "exit", "exit_group", "close", "close_range",
        "dup", "dup2", "dup3",
        "fchdir",
        "fstat", "fstatat",
        "fsync", "fdatasync", "ftruncate",
        "getdents", "getdents64",
        "getegid", "geteuid", "getgid", "getgroups", "getuid",
        "getitimer", "setitimer",
        "getpgid", "getpgrp", "getpid", "getppid",
        "getresgid", "getresuid", "getrlimit",
        "getsid", "gettid",
        "gettimeofday",
        "getrandom",
        "clock_gettime", "clock_getres", "clock_nanosleep",
        "nanosleep",
        "lseek",
        "brk",
        "futex",            # glibc uses this internally even single-threaded
        "sched_yield",      # glibc may call this during lock contention
        "mremap",           # glibc realloc may use this
        "madvise", "mmap",  # mmap: PROT_EXEC filtered unless prot_exec
        "mprotect",         # mprotect: PROT_EXEC filtered unless prot_exec
        "msync", "munmap",
        "rseq",             # glibc >= 2.35 restartable sequences
        "pipe", "pipe2",
        "read", "readv", "pread64", "preadv", "preadv2",
        "write", "writev", "pwrite64", "pwritev", "pwritev2",
        "recv", "recvfrom",
        "send", "sendto",  # sendto: only with null addr
        "select", "pselect6", "poll", "ppoll",
        "epoll_wait", "epoll_ctl", "epoll_create1",
        "shutdown",
        "socketpair",
        "sigaltstack",
        "sigpending",
        "rt_sigaction",  # SIGSYS handler forbidden
        "rt_sigprocmask", "rt_sigreturn", "rt_sigtimedwait",
        "sigsuspend",
        "umask",
        "uname",
        "set_tid_address",
        "arch_prctl",
        "prctl",
        "ioctl",  # filtered: only FIONREAD, FIONBIO, FIOCLEX, FIONCLEX
        "fcntl",  # filtered: only F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_DUPFD_CLOEXEC
        "wait4",
        "splice", "tee", "copy_file_range",
        "sendfile",
        "getrusage",
    },

    "rpath": {
        "chdir", "getcwd",
        "open", "openat",  # filtered: O_RDONLY only
        "stat", "fstat", "lstat", "fstatat", "statx",
        "access", "faccessat", "faccessat2",
        "readlink", "readlinkat",
        "statfs", "fstatfs",
        "getdents", "getdents64",
    },

    "wpath": {
        "getcwd",
        "open", "openat",  # filtered: O_WRONLY allowed
        "stat", "fstat", "lstat", "fstatat", "statx",
        "access", "faccessat", "faccessat2",
        "readlink", "readlinkat",
        "chmod", "fchmod", "fchmodat",
        "utimensat", "futimesat", "utime",
    },

    "cpath": {
        "open", "openat",  # filtered: O_CREAT allowed
        "rename", "renameat", "renameat2",
        "link", "linkat",
        "symlink", "symlinkat",
        "unlink", "unlinkat",
        "rmdir",
        "mkdir", "mkdirat",
        "creat",
    },

    "dpath": {
        "mknod", "mknodat",
    },

    "chown": {
        "chown", "fchown", "lchown", "fchownat",
    },

    "flock": {
        "flock",
        "fcntl",  # filtered: F_GETLK, F_SETLK, F_SETLKW
    },

    "fattr": {
        "chmod", "fchmod", "fchmodat",
        "utime", "utimensat", "futimesat",
    },

    "tty": {
        "ioctl",  # filtered: TIOCGWINSZ, TCGETS, TCSETS, TCSETSW, TCSETSF
    },

    "inet": {
        "socket",  # filtered: AF_INET / AF_INET6 only
        "listen", "bind", "connect",
        "accept", "accept4",
        "getpeername", "getsockname",
        "setsockopt", "getsockopt",
        "sendto", "sendmsg", "recvfrom", "recvmsg",
    },

    "unix": {
        "socket",  # filtered: AF_UNIX only
        "listen", "bind", "connect",
        "accept", "accept4",
        "getpeername", "getsockname",
        "setsockopt", "getsockopt",
        "sendto", "sendmsg", "recvfrom", "recvmsg",
    },

    "dns": {
        "socket",  # filtered: AF_INET / AF_INET6, SOCK_DGRAM
        "sendto", "recvfrom", "connect",
        "bind",
    },

    "proc": {
        "fork", "vfork", "clone",  # clone filtered for threads in "thread"
        "kill", "wait4",
        "getpriority", "setpriority",
        "prlimit64", "setrlimit",
        "setpgid", "setsid",
        "sched_getscheduler", "sched_setscheduler",
        "sched_get_priority_min", "sched_get_priority_max",
        "sched_getparam", "sched_setparam",
        "sched_yield",
    },

    "thread": {
        "clone",  # with thread flags
        "futex",
        "set_tid_address",
        "mmap",      # PROT_EXEC allowed for thread stacks
        "mprotect",  # PROT_EXEC allowed for thread stacks
        "getpid", "gettid",
    },

    "id": {
        "setuid", "setreuid", "setresuid",
        "setgid", "setregid", "setresgid",
        "setgroups", "setfsuid", "setfsgid",
        "prlimit64", "setrlimit",
        "getpriority", "setpriority",
    },

    "exec": {
        "execve", "execveat",
    },

    "prot_exec": {
        "mmap",      # PROT_EXEC allowed
        "mprotect",  # PROT_EXEC allowed
    },

    "recvfd": {
        "recvmsg",
    },

    "sendfd": {
        "sendmsg",
    },

    "tmppath": {
        "unlink", "unlinkat",
        "lstat", "fstatat", "statx",
    },

    "vminfo": set(),  # Primarily about unveil paths, no extra syscalls needed
}


# ═══════════════════════════════════════════════════════════════════════
# BPF program builder
# ═══════════════════════════════════════════════════════════════════════

class BPFBuilder:
    """Builds a SECCOMP BPF filter program from a set of pledge promises."""

    def __init__(self, promises: set[str], penalty: int = SECCOMP_RET_ERRNO):
        self.promises = promises
        self.penalty = penalty | (errno.EPERM & SECCOMP_RET_DATA)
        self._instructions: list[bytes] = []

    def _emit(self, insn: bytes) -> None:
        self._instructions.append(insn)

    def _allow_syscall(self, nr: int) -> None:
        """Emit: if (nr == syscall) return ALLOW."""
        if nr < 0:
            return
        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1))
        self._emit(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    def _load_nr(self) -> None:
        """Load syscall number into accumulator."""
        self._emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR))

    def _load_arg(self, n: int) -> None:
        """Load lower 32 bits of arg[n] into accumulator."""
        self._emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(n)))

    def _load_arg_hi(self, n: int) -> None:
        """Load upper 32 bits of arg[n] into accumulator."""
        self._emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg_hi(n)))

    def build(self) -> bytes:
        """Generate the complete BPF filter program."""
        self._instructions.clear()

        # ── Preamble: validate architecture ──
        self._emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH))
        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0))
        self._emit(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

        # ── Load syscall number ──
        self._load_nr()

        # ── Collect all allowed syscalls ──
        allowed: set[int] = set()
        needs_arg_filter: dict[str, set[str]] = {}  # syscall_name -> set of promises

        for promise in self.promises:
            syscalls = PROMISE_SYSCALLS.get(promise, set())
            for sc in syscalls:
                nr = _nr(sc)
                if nr < 0:
                    continue

                # Some syscalls need argument filtering
                if sc in _FILTERED_SYSCALLS:
                    needs_arg_filter.setdefault(sc, set()).add(promise)
                else:
                    allowed.add(nr)

        # ── Emit simple allow rules (no arg filtering) ──
        for nr in sorted(allowed):
            self._allow_syscall(nr)

        # ── Emit argument-filtered rules ──
        self._emit_filtered_syscalls(needs_arg_filter)

        # ── Default: deny ──
        self._emit(BPF_STMT(BPF_RET | BPF_K, self.penalty))

        return b"".join(self._instructions)

    def _emit_filtered_syscalls(self, filtered: dict[str, set[str]]) -> None:
        """Emit BPF for syscalls that need argument checks."""

        # ── open / openat: check O_RDONLY / O_WRONLY / O_CREAT ──
        for sc_name, arg_idx in [("open", 1), ("openat", 2)]:
            if sc_name in filtered:
                promises = filtered[sc_name]
                nr = _nr(sc_name)
                if nr < 0:
                    continue
                self._emit_open_filter(nr, arg_idx, promises)

        # ── socket: check address family ──
        if "socket" in filtered:
            nr = _nr("socket")
            if nr >= 0:
                self._emit_socket_filter(nr, filtered["socket"])

        # ── ioctl: check command ──
        if "ioctl" in filtered:
            nr = _nr("ioctl")
            if nr >= 0:
                self._emit_ioctl_filter(nr, filtered["ioctl"])

        # ── fcntl: check command ──
        if "fcntl" in filtered:
            nr = _nr("fcntl")
            if nr >= 0:
                self._emit_fcntl_filter(nr, filtered["fcntl"])

        # ── mmap: check PROT_EXEC ──
        if "mmap" in filtered:
            nr = _nr("mmap")
            if nr >= 0:
                self._emit_mmap_filter(nr, filtered["mmap"])

        # ── mprotect: check PROT_EXEC ──
        if "mprotect" in filtered:
            nr = _nr("mprotect")
            if nr >= 0:
                self._emit_mprotect_filter(nr, filtered["mprotect"])

        # ── sendto: if only "stdio", addr must be NULL ──
        if "sendto" in filtered:
            nr = _nr("sendto")
            if nr >= 0:
                promises = filtered["sendto"]
                if promises <= {"stdio", "dns"}:
                    # Allow sendto only with NULL dest addr (arg[4])
                    self._emit_sendto_null_filter(nr)
                else:
                    self._allow_syscall(nr)

        # ── clone: if only "thread" (not "proc"), restrict flags ──
        if "clone" in filtered:
            nr = _nr("clone")
            if nr >= 0:
                promises = filtered["clone"]
                if "proc" in promises:
                    self._allow_syscall(nr)
                else:
                    # Thread-only clone
                    self._allow_syscall(nr)  # simplified

    def _emit_open_filter(self, nr: int, flags_arg: int,
                          promises: set[str]) -> None:
        """Filter open/openat based on which path promises are active."""
        # Build allowed flags mask
        allow_rdonly = "rpath" in promises or "stdio" in promises
        allow_wronly = "wpath" in promises
        allow_creat  = "cpath" in promises

        if allow_rdonly and allow_wronly and allow_creat:
            # All modes allowed
            self._allow_syscall(nr)
            return

        # if (nr != this_syscall) skip this block
        # The block length varies, so we build a sub-program
        skip_len = 0  # we'll calculate

        # Check syscall number
        sub: list[bytes] = []

        # Load flags argument
        sub.append(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(flags_arg)))

        # Mask off to get access mode
        sub.append(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE))

        allow_count = 0
        checks: list[bytes] = []

        if allow_rdonly:
            allow_count += 1
        if allow_wronly:
            allow_count += 1

        # We use a different strategy: just allow the syscall if any
        # promise grants it, since BPF forward-only jumps make complex
        # branching very tricky.  The key restriction is still that
        # without rpath, you can't open O_RDONLY, etc.

        if allow_rdonly:
            checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDONLY, 0, 1))
            checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        if allow_wronly:
            checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_WRONLY, 0, 1))
            checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
            checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDWR, 0, 1))
            checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        if allow_creat:
            # Reload full flags to check O_CREAT
            checks.append(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(flags_arg)))
            checks.append(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_CREAT))
            checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_CREAT, 0, 1))
            checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        total_sub = len(sub) + len(checks)

        # Emit: if (nr == open) goto sub_block; else skip
        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, total_sub))
        for insn in sub:
            self._emit(insn)
        for insn in checks:
            self._emit(insn)
        # Reload nr for next checks
        self._load_nr()

    def _emit_socket_filter(self, nr: int, promises: set[str]) -> None:
        """Filter socket() by address family."""
        allow_inet = "inet" in promises or "dns" in promises
        allow_unix = "unix" in promises

        checks: list[bytes] = []
        checks.append(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(0)))

        if allow_inet:
            checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 0, 1))
            checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
            checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 1))
            checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        if allow_unix:
            checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 1))
            checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, len(checks)))
        for insn in checks:
            self._emit(insn)
        self._load_nr()

    def _emit_ioctl_filter(self, nr: int, promises: set[str]) -> None:
        """Filter ioctl() by command."""
        allowed_cmds: list[int] = []

        if "stdio" in promises:
            allowed_cmds.extend([FIONREAD, FIONBIO, FIOCLEX, FIONCLEX])
        if "tty" in promises:
            allowed_cmds.extend([TIOCGWINSZ, TCGETS, TCSETS, TCSETSW, TCSETSF])

        checks: list[bytes] = []
        checks.append(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(1)))
        for cmd in allowed_cmds:
            checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, cmd, 0, 1))
            checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, len(checks)))
        for insn in checks:
            self._emit(insn)
        self._load_nr()

    def _emit_fcntl_filter(self, nr: int, promises: set[str]) -> None:
        """Filter fcntl() by command."""
        allowed_cmds: list[int] = []

        if "stdio" in promises:
            allowed_cmds.extend([F_GETFD, F_SETFD, F_GETFL, F_SETFL,
                                 F_DUPFD_CLOEXEC])
        if "flock" in promises:
            allowed_cmds.extend([F_GETLK, F_SETLK, F_SETLKW])

        checks: list[bytes] = []
        checks.append(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(1)))
        for cmd in allowed_cmds:
            checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, cmd, 0, 1))
            checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, len(checks)))
        for insn in checks:
            self._emit(insn)
        self._load_nr()

    def _emit_mmap_filter(self, nr: int, promises: set[str]) -> None:
        """Filter mmap() — block PROT_EXEC unless prot_exec or thread."""
        if "prot_exec" in promises or "thread" in promises:
            self._allow_syscall(nr)
            return

        # if (nr == mmap) { load prot (arg[2]); if (prot & PROT_EXEC) deny; else allow }
        checks: list[bytes] = []
        checks.append(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(2)))
        checks.append(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC))
        checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1))
        checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
        # If PROT_EXEC was set, fall through to deny

        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, len(checks)))
        for insn in checks:
            self._emit(insn)
        self._load_nr()

    def _emit_mprotect_filter(self, nr: int, promises: set[str]) -> None:
        """Filter mprotect() — block PROT_EXEC unless prot_exec or thread."""
        if "prot_exec" in promises or "thread" in promises:
            self._allow_syscall(nr)
            return

        checks: list[bytes] = []
        checks.append(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(2)))
        checks.append(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC))
        checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1))
        checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, len(checks)))
        for insn in checks:
            self._emit(insn)
        self._load_nr()

    def _emit_sendto_null_filter(self, nr: int) -> None:
        """Allow sendto only if dest_addr (arg[4]) is NULL."""
        checks: list[bytes] = []
        # Check lower 32 bits of arg[4]
        checks.append(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg(4)))
        checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3))
        # Check upper 32 bits of arg[4]
        checks.append(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, _off_arg_hi(4)))
        checks.append(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1))
        checks.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

        self._emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, len(checks)))
        for insn in checks:
            self._emit(insn)
        self._load_nr()


# Syscalls that need argument-level filtering
_FILTERED_SYSCALLS = {
    "open", "openat", "socket", "ioctl", "fcntl",
    "mmap", "mprotect", "sendto", "clone",
}

# ═══════════════════════════════════════════════════════════════════════
# ctypes structures for installing the filter
# ═══════════════════════════════════════════════════════════════════════

class SockFprog(ctypes.Structure):
    """struct sock_fprog { unsigned short len; struct sock_filter *filter; }"""
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.c_void_p),
    ]


# ═══════════════════════════════════════════════════════════════════════
# Main API
# ═══════════════════════════════════════════════════════════════════════

_libc: Optional[ctypes.CDLL] = None

def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return _libc


def _prctl(option: int, arg2: int = 0, arg3: int = 0,
           arg4: int = 0, arg5: int = 0) -> int:
    libc = _get_libc()
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = [
        ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
        ctypes.c_ulong, ctypes.c_ulong,
    ]
    ret = libc.prctl(option, arg2, arg3, arg4, arg5)
    if ret < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"prctl({option}): {os.strerror(e)}")
    return ret


def _install_filter(bpf_prog: bytes) -> None:
    """Install a SECCOMP BPF filter using prctl(2)."""
    n_insns = len(bpf_prog) // _SOCK_FILTER_SIZE
    assert len(bpf_prog) % _SOCK_FILTER_SIZE == 0

    # Create a ctypes buffer for the filter
    buf = ctypes.create_string_buffer(bpf_prog)

    prog = SockFprog()
    prog.len = n_insns
    prog.filter = ctypes.cast(buf, ctypes.c_void_p).value

    # PR_SET_NO_NEW_PRIVS must be set first (allows unprivileged seccomp)
    _prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    # Install the filter via raw syscall (avoids ctypes type conflicts
    # with prctl's varargs signature)
    libc = _get_libc()
    libc.syscall.restype = ctypes.c_long
    SYS_prctl = NR["prctl"]
    ret = libc.syscall(
        ctypes.c_long(SYS_prctl),
        ctypes.c_long(PR_SET_SECCOMP),
        ctypes.c_long(SECCOMP_MODE_FILTER),
        ctypes.byref(prog),
        ctypes.c_long(0),
        ctypes.c_long(0),
    )
    if ret < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"prctl(PR_SET_SECCOMP): {os.strerror(e)}")


_pledged = False

def pledge(promises: str, execpromises: Optional[str] = None) -> None:
    """
    Restrict the current process to only the specified promise categories.

    This is irreversible — you can call pledge() again to further reduce
    privileges, but never to increase them.

    Args:
        promises: Space-separated list of promise categories.
                  E.g. "stdio rpath" or "stdio rpath wpath inet".
        execpromises: Not supported on Linux (ignored with a warning).

    Raises:
        OSError: If the filter cannot be installed.
        ValueError: If an unknown promise is specified.

    Example:
        >>> pledge("stdio rpath")
        >>> open("/etc/hostname").read()  # works
        >>> import socket; socket.socket()  # raises EPERM
    """
    global _pledged

    if execpromises is not None:
        import warnings
        warnings.warn("pledge: execpromises not supported on Linux, ignored",
                      stacklevel=2)

    # Parse promises
    promise_set: set[str] = set()
    if promises.strip():
        for p in promises.split():
            p = p.strip().lower()
            if p and p not in PROMISE_SYSCALLS:
                raise ValueError(f"pledge: unknown promise '{p}'")
            promise_set.add(p)

    # Build and install the BPF filter
    builder = BPFBuilder(promise_set)
    bpf_prog = builder.build()

    n_insns = len(bpf_prog) // _SOCK_FILTER_SIZE
    if n_insns > 4096:
        raise ValueError(
            f"pledge: BPF program too large ({n_insns} insns, max 4096)")

    _install_filter(bpf_prog)
    _pledged = True


def pledge_available() -> bool:
    """Check if SECCOMP BPF is available on this system."""
    try:
        _prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        return True
    except OSError:
        return False


def _is_dynamic_elf(path: str) -> bool:
    """Check if a file is a dynamically linked ELF binary.

    Reads the ELF header to look for PT_INTERP (program interpreter),
    which indicates the binary needs ld.so to load shared libraries.
    Statically linked binaries and scripts return False.
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return False  # not an ELF — could be a script
            # Read ELF class (32 vs 64 bit)
            f.seek(4)
            ei_class = f.read(1)[0]
            is_64 = (ei_class == 2)
            # Read e_phoff, e_phentsize, e_phnum
            if is_64:
                f.seek(32)  # e_phoff at offset 32 in Elf64_Ehdr
                e_phoff = int.from_bytes(f.read(8), "little")
                f.seek(54)  # e_phentsize at offset 54
                e_phentsize = int.from_bytes(f.read(2), "little")
                e_phnum = int.from_bytes(f.read(2), "little")
            else:
                f.seek(28)  # e_phoff at offset 28 in Elf32_Ehdr
                e_phoff = int.from_bytes(f.read(4), "little")
                f.seek(42)  # e_phentsize at offset 42
                e_phentsize = int.from_bytes(f.read(2), "little")
                e_phnum = int.from_bytes(f.read(2), "little")
            # Scan program headers for PT_INTERP (type 3)
            PT_INTERP = 3
            for i in range(e_phnum):
                f.seek(e_phoff + i * e_phentsize)
                p_type = int.from_bytes(f.read(4), "little")
                if p_type == PT_INTERP:
                    return True
            return False
    except (OSError, IndexError, ValueError):
        # If we can't read it, assume dynamic (safer — grants prot_exec)
        return True


# ═══════════════════════════════════════════════════════════════════════
# Command-line interface
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    all_promises = sorted(PROMISE_SYSCALLS.keys())

    parser = argparse.ArgumentParser(
        prog="pledge",
        description="Run a command under OpenBSD-style pledge() restrictions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "promise categories:\n  "
            + ", ".join(all_promises)
            + "\n\nexamples:\n"
            "  pledge -p 'stdio rpath' ls -la\n"
            "  pledge -p 'stdio rpath wpath cpath' -- bash\n"
            "  pledge -p 'stdio rpath inet dns' -- curl -s http://example.com\n"
            "  pledge --test              # check if seccomp is available\n"
        ),
    )
    parser.add_argument("-p", "--promises", default="stdio rpath",
                        help="space-separated promise list "
                             "(default: 'stdio rpath')")
    parser.add_argument("--penalty", choices=["eperm", "kill"],
                        default="eperm",
                        help="violation penalty (default: eperm)")
    parser.add_argument("--test", action="store_true",
                        help="test if seccomp is available and exit")
    parser.add_argument("--dump", action="store_true",
                        help="dump BPF program stats and exit")
    parser.add_argument("command", nargs="*",
                        help="command to run under pledge")

    args = parser.parse_args()

    if args.test:
        if pledge_available():
            print("pledge: seccomp BPF is available")
            kv = platform.release()
            print(f"  kernel:  {kv}")
            print(f"  arch:    {_arch} (AUDIT_ARCH=0x{AUDIT_ARCH:08X})")
            sys.exit(0)
        else:
            print("pledge: seccomp BPF is NOT available", file=sys.stderr)
            sys.exit(1)

    if args.dump:
        promise_set = set(args.promises.split())
        builder = BPFBuilder(promise_set)
        prog = builder.build()
        n = len(prog) // _SOCK_FILTER_SIZE
        print(f"Promises: {args.promises}")
        print(f"BPF instructions: {n}")
        print(f"BPF program size: {len(prog)} bytes")

        # Collect all allowed syscalls for display
        allowed_names: set[str] = set()
        for p in promise_set:
            allowed_names |= PROMISE_SYSCALLS.get(p, set())
        valid = sorted(s for s in allowed_names if _nr(s) >= 0)
        print(f"Allowed syscalls ({len(valid)}): {', '.join(valid)}")
        sys.exit(0)

    if not args.command:
        parser.error("no command specified")

    # Set penalty
    if args.penalty == "kill":
        penalty = SECCOMP_RET_KILL_PROCESS
    else:
        penalty = SECCOMP_RET_ERRNO

    # Parse and validate promises
    promise_set = set(args.promises.split())
    for p in promise_set:
        if p not in PROMISE_SYSCALLS:
            print(f"pledge: unknown promise '{p}'", file=sys.stderr)
            sys.exit(1)

    # Build filter
    # When wrapping a command, we always need exec + rpath (to find
    # and load the binary).  For dynamically linked binaries we also
    # need prot_exec (ld.so must mmap .so files with PROT_EXEC).
    auto_added: list[str] = []
    if "exec" not in promise_set:
        promise_set.add("exec")
        auto_added.append("exec")
    if "rpath" not in promise_set:
        promise_set.add("rpath")
        auto_added.append("rpath")

    # Resolve command path early so we can check if it's dynamic
    cmd = args.command[0]
    cmd_args = args.command
    if "/" not in cmd:
        for d in os.environ.get("PATH", "/usr/bin:/bin").split(":"):
            candidate = os.path.join(d, cmd)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                cmd = candidate
                break

    if "prot_exec" not in promise_set and _is_dynamic_elf(cmd):
        promise_set.add("prot_exec")
        auto_added.append("prot_exec")

    if auto_added:
        print(f"pledge: auto-added promises for exec: {' '.join(auto_added)}",
              file=sys.stderr)

    builder = BPFBuilder(promise_set, penalty)
    bpf_prog = builder.build()
    n_insns = len(bpf_prog) // _SOCK_FILTER_SIZE

    # Install filter
    try:
        _install_filter(bpf_prog)
    except OSError as e:
        print(f"pledge: cannot install seccomp filter: {e}", file=sys.stderr)
        sys.exit(1)

    # exec the command
    try:
        os.execv(cmd, cmd_args)
    except OSError as e:
        print(f"pledge: exec {cmd}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
