# pledge.py

**OpenBSD `pledge(2)` for Linux — in pure Python**

A single-file, zero-dependency Python port of [Justine Tunney's pledge()](https://justine.lol/pledge/) that uses `ctypes` to build and install SECCOMP BPF filters at runtime. No C compiler, no `pip install`, no root required.

```python
from pledge import pledge

pledge("stdio rpath")          # only allow basic I/O and reading files
data = open("/etc/hosts").read()  # ✓ works
os.system("curl evil.com")        # ✗ Operation not permitted
```

---

## Table of Contents

- [Why](#why)
- [Quick Start](#quick-start)
- [Command-Line Usage](#command-line-usage)
- [Library Usage](#library-usage)
- [Promise Reference](#promise-reference)
- [Argument Filtering](#argument-filtering)
- [Examples](#examples)
  - [Sandboxing a Config Parser](#sandboxing-a-config-parser)
  - [Read-Only Data Pipeline](#read-only-data-pipeline)
  - [Network Client That Can't Touch the Filesystem](#network-client-that-cant-touch-the-filesystem)
  - [Progressive Privilege Dropping](#progressive-privilege-dropping)
  - [Worker Process Enclave](#worker-process-enclave)
  - [Sandboxing Untrusted Plugins](#sandboxing-untrusted-plugins)
  - [Locked-Down Web Scraper](#locked-down-web-scraper)
  - [Protecting a CLI Tool From Itself](#protecting-a-cli-tool-from-itself)
  - [Sandboxing AI Code Execution](#sandboxing-ai-code-execution)
- [Command-Line Examples](#command-line-examples)
- [How It Works](#how-it-works)
- [Architecture Support](#architecture-support)
- [Caveats](#caveats)
- [Requirements](#requirements)

---

## Why

Linux has powerful sandboxing via SECCOMP BPF, but using it normally requires writing raw BPF bytecode — an inscrutable stream of bitwise operations and jump offsets. OpenBSD's `pledge()` distills the same idea into a single function call with a human-readable string.

This library gives you that same simplicity on Linux:

```python
# Before pledge: your process can do anything
pledge("stdio rpath")
# After pledge: it can only do basic I/O and read files
# This is enforced by the kernel — it cannot be reversed
```

Violations return `EPERM` (or kill the process, your choice). The restriction is enforced by the kernel itself, so even native code loaded via `ctypes` or C extensions is constrained. 

---

## Quick Start

**1. Drop the file into your project:**

```bash
curl -O https://raw.githubusercontent.com/youruser/pledge-py/main/pledge.py
# or just copy pledge.py into your project directory
```

**2. Use it in your code:**

```python
from pledge import pledge

# Do your setup (imports, open config files, etc.) FIRST
import json
config = json.load(open("config.json"))

# Then lock down
pledge("stdio")

# From here on, only basic I/O works
print(json.dumps(config))  # ✓ fine — just writing to stdout
open("secrets.txt")        # ✗ EPERM — no rpath promise
```

**3. Or wrap an existing command:**

```bash
python3 pledge.py -p "stdio rpath" -- cat /etc/hostname
python3 pledge.py -p "stdio rpath" -- ls -la
```

---

## Command-Line Usage

```
pledge [-p PROMISES] [--penalty {eperm,kill}] [--test] [--dump] [command ...]
```

| Flag | Description |
|------|-------------|
| `-p PROMISES` | Space-separated promise list (default: `stdio rpath`) |
| `--penalty eperm` | Violations return `EPERM` (default) |
| `--penalty kill` | Violations kill the process with `SIGSYS` |
| `--test` | Check if SECCOMP BPF is available on this system |
| `--dump` | Print BPF program statistics for the given promises |

When wrapping a command, pledge.py automatically adds the `exec`, `rpath`, and (for dynamically linked binaries) `prot_exec` promises, since they are needed to load and run the target program. It detects dynamic vs. static ELF binaries by scanning for `PT_INTERP` in the ELF program headers.

---

## Library Usage

### `pledge(promises: str) -> None`

Restrict the current process to the specified promise categories.

```python
from pledge import pledge

pledge("stdio rpath wpath")
```

- `promises` is a space-separated string of category names.
- Calling `pledge()` is **irreversible**. You can call it again to narrow privileges further, but never to widen them.
- Raises `ValueError` for unknown promise names.
- Raises `OSError` if the filter cannot be installed.

### `pledge_available() -> bool`

Returns `True` if SECCOMP BPF is available on the current system.

```python
from pledge import pledge_available

if pledge_available():
    pledge("stdio rpath")
else:
    print("Warning: sandboxing not available on this kernel")
```

---

## Promise Reference

Every promise grants access to a specific group of system calls. Start with only what you need — the principle of least privilege.

| Promise | What it grants |
|---------|---------------|
| `stdio` | Core I/O: `read`, `write`, `close`, `pipe`, `poll`, `select`, `mmap` (no `PROT_EXEC`), `brk`, `futex`, `clock_gettime`, signals, `dup`, `fcntl` (get/set only), `ioctl` (FIONREAD/FIONBIO only), `getrandom`, `exit` |
| `rpath` | Read-only filesystem: `open(O_RDONLY)`, `openat(O_RDONLY)`, `stat`, `lstat`, `access`, `readlink`, `getcwd`, `chdir`, `getdents` |
| `wpath` | Write to files: `open(O_WRONLY)`, `openat(O_WRONLY/O_RDWR)`, `chmod`, `fchmod`, `utimensat` |
| `cpath` | Create/delete filesystem entries: `open(O_CREAT)`, `mkdir`, `rmdir`, `unlink`, `rename`, `link`, `symlink` |
| `dpath` | Create device nodes: `mknod`, `mknodat` |
| `chown` | Change file ownership: `chown`, `fchown`, `lchown`, `fchownat` |
| `flock` | File locking: `flock`, `fcntl(F_GETLK/F_SETLK/F_SETLKW)` |
| `fattr` | File attributes: `chmod`, `fchmod`, `utime`, `utimensat` |
| `tty` | Terminal ops: `ioctl(TIOCGWINSZ/TCGETS/TCSETS/TCSETSW/TCSETSF)` |
| `inet` | IPv4/IPv6 sockets: `socket(AF_INET/AF_INET6)`, `bind`, `listen`, `connect`, `accept`, `send*`, `recv*`, `setsockopt` |
| `unix` | Unix domain sockets: `socket(AF_UNIX)`, same ops as `inet` |
| `dns` | DNS resolution: `socket(AF_INET/AF_INET6)` + `sendto`, `recvfrom`, `connect` |
| `proc` | Process control: `fork`, `vfork`, `clone`, `kill`, `wait4`, `setpgid`, `setsid`, scheduling |
| `thread` | Threading: `clone` (thread flags), `futex`, `mmap`/`mprotect` with `PROT_EXEC` |
| `exec` | Execute programs: `execve`, `execveat` |
| `prot_exec` | Executable memory: allow `PROT_EXEC` in `mmap`/`mprotect` (needed for dynamic linking, JIT) |
| `id` | Identity changes: `setuid`, `setgid`, `setgroups`, `setfsuid`, `setfsgid`, `setreuid`, `setresuid` |
| `recvfd` | Receive file descriptors: `recvmsg` (SCM_RIGHTS) |
| `sendfd` | Send file descriptors: `sendmsg` (SCM_RIGHTS) |
| `tmppath` | Temp file ops: `unlink`, `unlinkat`, `lstat` |
| `vminfo` | System info: allows access to `/proc/stat`, `/proc/meminfo`, etc. (path-level; no extra syscalls) |

---

## Argument Filtering

Unlike simple syscall allowlists, pledge.py applies **argument-level filtering** on several system calls, matching the behavior of the original C implementation:

| Syscall | Filtering |
|---------|-----------|
| `open` / `openat` | Flags checked: `O_RDONLY` requires `rpath`, `O_WRONLY`/`O_RDWR` requires `wpath`, `O_CREAT` requires `cpath` |
| `socket` | Address family checked: `AF_INET`/`AF_INET6` requires `inet` or `dns`, `AF_UNIX` requires `unix` |
| `ioctl` | Command checked: `stdio` allows `FIONREAD`/`FIONBIO`/`FIOCLEX`/`FIONCLEX`; `tty` allows `TIOCGWINSZ`/`TCGETS`/`TCSETS*` |
| `fcntl` | Command checked: `stdio` allows `F_GETFD`/`F_SETFD`/`F_GETFL`/`F_SETFL`/`F_DUPFD_CLOEXEC`; `flock` allows `F_GETLK`/`F_SETLK`/`F_SETLKW` |
| `mmap` / `mprotect` | `PROT_EXEC` blocked unless `prot_exec` or `thread` is pledged |
| `sendto` | With `stdio`-only, destination address must be `NULL` (write to an already-connected socket) |

---

## Examples

### Sandboxing a Config Parser

Read a config file, then lock out all filesystem access:

```python
from pledge import pledge
import json

# Phase 1: privileged startup
with open("config.json") as f:
    config = json.load(f)

# Phase 2: drop all file access
pledge("stdio")

# From here on, the process can only do computation and I/O on
# already-open file descriptors (stdin/stdout/stderr)
result = expensive_computation(config)
print(json.dumps(result))

# This would raise PermissionError:
# open("steal_secrets.txt")
```

### Read-Only Data Pipeline

Process data files without any risk of modifying them:

```python
from pledge import pledge
import csv
import sys

pledge("stdio rpath")

# Can read any file the user has access to
with open(sys.argv[1]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        if float(row["amount"]) > 1000:
            print(f"{row['date']}: ${row['amount']}")

# But cannot write, create, or delete anything
# open("output.csv", "w")  → PermissionError
# os.unlink("data.csv")    → PermissionError
```

### Network Client That Can't Touch the Filesystem

Fetch data from the network but prevent any filesystem modification:

```python
import socket
import ssl
from pledge import pledge

# Import everything and set up SSL context BEFORE pledging
context = ssl.create_default_context()

pledge("stdio rpath inet dns")

# Can connect to servers
sock = socket.create_connection(("example.com", 443))
ssock = context.wrap_socket(sock, server_hostname="example.com")
ssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
response = ssock.recv(4096)
print(response.decode())

# But cannot write to disk
# open("/tmp/stolen.txt", "w")  → PermissionError

# And cannot fork or exec
# os.system("curl evil.com")    → PermissionError
```

### Progressive Privilege Dropping

Narrow permissions as your program moves through phases:

```python
from pledge import pledge
import sqlite3

# Phase 1: read config + database, allow network
pledge("stdio rpath inet dns")

config = open("app.conf").read()
conn = sqlite3.connect("data.db")  # inherits the open fd
results = conn.execute("SELECT * FROM users").fetchall()

# Phase 2: done reading files, only need network now
pledge("stdio inet")

# conn still works because the fd is already open
# But opening new files is blocked:
# open("other.db")  → PermissionError

send_results_to_api(results)

# Phase 3: all done with network, just compute and print
pledge("stdio")

# Now even sockets are blocked
# socket.socket()  → PermissionError
print(f"Processed {len(results)} records")
```

### Worker Process Enclave

Fork a worker that can only compute — no I/O, no files, no network:

```python
from pledge import pledge
import os
import mmap

# Create shared memory for communicating with the worker
buf = mmap.mmap(-1, 4096)
buf.write(b"input data here")

pid = os.fork()
if pid == 0:
    # Worker process: maximum lockdown
    pledge("stdio")

    # Can read/write the shared memory
    buf.seek(0)
    data = buf.read(15)
    result = data.upper()  # "do work"
    buf.seek(0)
    buf.write(result)

    os._exit(0)

os.waitpid(pid, 0)
buf.seek(0)
print(buf.read(15))  # b"INPUT DATA HERE"
```

### Sandboxing Untrusted Plugins

Load and run plugin code in a sandboxed subprocess:

```python
from pledge import pledge
import importlib
import json
import os
import sys

def run_plugin_sandboxed(plugin_name: str, input_data: dict) -> dict:
    """Run a plugin with only stdio access — no files, no network."""

    r_fd, w_fd = os.pipe()

    pid = os.fork()
    if pid == 0:
        os.close(r_fd)

        # Load the plugin before pledging
        plugin = importlib.import_module(f"plugins.{plugin_name}")

        # Lock down: plugin can only compute and write results to pipe
        pledge("stdio")

        try:
            result = plugin.process(input_data)
            os.write(w_fd, json.dumps(result).encode())
        except Exception as e:
            os.write(w_fd, json.dumps({"error": str(e)}).encode())

        os._exit(0)

    os.close(w_fd)
    data = b""
    while chunk := os.read(r_fd, 4096):
        data += chunk
    os.close(r_fd)
    os.waitpid(pid, 0)

    return json.loads(data)

# The plugin literally cannot:
# - Read or write any file
# - Open network connections
# - Spawn processes
# - Access the terminal
# Even if it tries via ctypes or inline C
```

### Locked-Down Web Scraper

Allow network access and reading files (for CA certs), but prevent
any filesystem writes or process spawning:

```python
import urllib.request
import ssl
import json
from pledge import pledge

# Set up SSL before pledging
context = ssl.create_default_context()

pledge("stdio rpath inet dns")

urls = [
    "https://api.example.com/data1",
    "https://api.example.com/data2",
]

results = []
for url in urls:
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=context) as resp:
        results.append(json.loads(resp.read()))

# Can print results but cannot save them to disk
for r in results:
    print(json.dumps(r, indent=2))

# These would all fail:
# open("results.json", "w")      → PermissionError
# subprocess.run(["curl", url])  → PermissionError
# os.system("rm -rf /")          → PermissionError
```

### Protecting a CLI Tool From Itself

Add pledge as a safety net to your own CLI applications:

```python
#!/usr/bin/env python3
"""A grep-like tool that pledges early."""
import sys
import re
from pledge import pledge, pledge_available

def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} PATTERN FILE [FILE...]", file=sys.stderr)
        sys.exit(1)

    pattern = re.compile(sys.argv[1])
    files = sys.argv[2:]

    # This tool only needs to read files and write to stdout.
    # Lock it down before processing any input.
    if pledge_available():
        pledge("stdio rpath")

    for filename in files:
        try:
            with open(filename) as f:
                for lineno, line in enumerate(f, 1):
                    if pattern.search(line):
                        print(f"{filename}:{lineno}: {line}", end="")
        except OSError as e:
            print(f"{filename}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
```

### Sandboxing AI Code Execution

Run LLM-generated code with tight restrictions:

```python
from pledge import pledge
import os
import sys
import json

def execute_ai_code(code: str, input_data: dict) -> dict:
    """Execute untrusted code in a pledged subprocess."""

    r_fd, w_fd = os.pipe()
    pid = os.fork()

    if pid == 0:
        os.close(r_fd)

        # Maximum restrictions: compute only, no I/O except the pipe
        pledge("stdio")

        result = {"status": "ok", "output": None}
        try:
            namespace = {"input_data": input_data}
            exec(code, namespace)
            result["output"] = namespace.get("output")
        except Exception as e:
            result = {"status": "error", "error": str(e)}

        os.write(w_fd, json.dumps(result).encode())
        os._exit(0)

    os.close(w_fd)
    data = b""
    while chunk := os.read(r_fd, 4096):
        data += chunk
    os.close(r_fd)
    _, status = os.waitpid(pid, 0)

    if os.WIFSIGNALED(status):
        return {"status": "killed", "signal": os.WTERMSIG(status)}

    return json.loads(data)


# The AI code literally cannot escape the sandbox:
result = execute_ai_code("""
output = sum(input_data["numbers"]) * 2
""", {"numbers": [1, 2, 3, 4, 5]})

print(result)  # {"status": "ok", "output": 30}

# Malicious code gets EPERM on everything dangerous:
result = execute_ai_code("""
import socket  # import works (already in memory), but...
s = socket.socket()  # PermissionError!
""", {})

print(result)  # {"status": "error", "error": "[Errno 1] ..."}
```

---

## Command-Line Examples

**List files (read-only):**

```bash
python3 pledge.py -p "stdio rpath" -- ls -la /etc/
```

**Read a file:**

```bash
python3 pledge.py -p "stdio rpath" -- cat /etc/hostname
```

**Run a shell with only read access (no writes, no network):**

```bash
python3 pledge.py -p "stdio rpath tty" -- bash
# Inside this shell:
#   cat /etc/passwd    ✓ works
#   echo hi > /tmp/x   ✗ Operation not permitted
#   curl example.com   ✗ Operation not permitted
```

**Allow a script to write to the current directory:**

```bash
python3 pledge.py -p "stdio rpath wpath cpath" -- python3 my_script.py
```

**Kill the process instead of returning EPERM:**

```bash
python3 pledge.py --penalty kill -p "stdio rpath" -- python3 untrusted.py
# Process receives SIGSYS and dies instantly on violation
```

**Check if the system supports SECCOMP BPF:**

```bash
$ python3 pledge.py --test
pledge: seccomp BPF is available
  kernel:  6.8.0
  arch:    x86_64 (AUDIT_ARCH=0xC000003E)
```

**Inspect the BPF filter that would be generated:**

```bash
$ python3 pledge.py --dump -p "stdio rpath inet dns"
Promises: stdio rpath inet dns
BPF instructions: 280
BPF program size: 2240 bytes
Allowed syscalls (107): accept, accept4, access, arch_prctl, bind, ...
```

**Run Python with network access but no filesystem writes:**

```bash
python3 pledge.py -p "stdio rpath inet dns" -- python3 -c "
import urllib.request
print(urllib.request.urlopen('http://example.com').read()[:100])
"
```

**Run a Node.js script with strict restrictions:**

```bash
python3 pledge.py -p "stdio rpath" -- node -e "
const fs = require('fs');
console.log(fs.readFileSync('/etc/hostname', 'utf8'));
// fs.writeFileSync('/tmp/x', 'y');  ← would fail
"
```

---

## How It Works

1. **Promise parsing** — Your promise string (e.g. `"stdio rpath inet"`) is split into categories. Each category maps to a set of allowed syscall names.

2. **BPF compilation** — A `BPFBuilder` generates a SECCOMP BPF filter program (an array of `sock_filter` instructions). The program:
   - Validates the CPU architecture (`AUDIT_ARCH_X86_64` or `AUDIT_ARCH_AARCH64`)
   - Loads the syscall number from `seccomp_data.nr`
   - For each allowed syscall, emits a conditional jump that returns `SECCOMP_RET_ALLOW`
   - For filtered syscalls (`open`, `socket`, `ioctl`, `mmap`, etc.), emits argument-checking logic using `seccomp_data.args[]`
   - Falls through to the default action (`SECCOMP_RET_ERRNO | EPERM` or `SECCOMP_RET_KILL_PROCESS`)

3. **Filter installation** — The compiled BPF program is installed via:
   ```
   prctl(PR_SET_NO_NEW_PRIVS, 1)          — required for unprivileged seccomp
   prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)  — install the filter
   ```
   Both calls are made through `ctypes` with raw `syscall()` to avoid glibc wrapper issues.

4. **Kernel enforcement** — Once installed, the filter is checked by the kernel before every system call for the lifetime of the process (and any children). It cannot be removed.

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ pledge()    │────▶│ BPFBuilder   │────▶│ prctl()      │
│ "stdio rp.."│     │ compile BPF  │     │ install      │
└─────────────┘     └──────────────┘     └──────┬───────┘
                                                │
                         ┌──────────────────────▼───────┐
                         │         Linux Kernel          │
                         │                               │
                         │  Every syscall ──▶ BPF check  │
                         │    ✓ allowed  → run syscall   │
                         │    ✗ denied   → EPERM / KILL  │
                         └───────────────────────────────┘
```

---

## Architecture Support

| Architecture | Supported | AUDIT_ARCH | Syscall table |
|---|---|---|---|
| x86_64 / amd64 | ✓ | `0xC000003E` | ~180 entries |
| aarch64 / arm64 | ✓ | `0xC00000B7` | ~170 entries |

Other architectures (i386, arm32, riscv64, s390x, ppc64) would need syscall number tables added to the `NR` dictionary.

---

## Caveats

**Import order matters.** Python's `import` machinery opens files, loads shared libraries, and sometimes creates executable memory. Do your imports *before* calling `pledge()`, or include `rpath` and `prot_exec` in your promises.

```python
# ✓ Correct: import before pledge
import json, csv, socket
from pledge import pledge
pledge("stdio")

# ✗ Wrong: will fail when json tries to import submodules
from pledge import pledge
pledge("stdio")
import json  # PermissionError!
```

**No filesystem path filtering.** Unlike OpenBSD's `unveil()`, pledge.py cannot restrict *which* files are accessible — only *whether* file operations are allowed at all. If you need path-level restrictions, consider combining pledge with Linux namespaces, Landlock LSM (kernel ≥ 5.13), or a chroot.

**glibc internals.** glibc uses `futex`, `rseq`, `mremap`, and other syscalls internally even in single-threaded programs. The `stdio` promise includes these so that basic C library functions don't break. If you find a program that fails unexpectedly, run it under `strace` to see which syscall is getting `EPERM`.

**Cumulative filters.** Each call to `pledge()` installs an *additional* SECCOMP filter. The kernel evaluates all installed filters and takes the most restrictive result. This means you can narrow privileges but never widen them — exactly like OpenBSD.

**No `execpromises`.** The Linux SECCOMP mechanism doesn't support different promise sets for `execve`'d programs the way OpenBSD does. The `execpromises` parameter is accepted but ignored with a warning.

---

## Requirements

- **Linux** kernel ≥ 3.5 (SECCOMP_MODE_FILTER support)
- **Python** ≥ 3.10
- **No root** — uses `PR_SET_NO_NEW_PRIVS` for unprivileged operation
- **No dependencies** — pure standard library + `ctypes`
- **Single file** — just copy `pledge.py` into your project

---

## License

Based on Justine Tunney's [cosmopolitan libc pledge() implementation](https://justine.lol/pledge/), which is ISC licensed. This Python port is released under the same terms.
