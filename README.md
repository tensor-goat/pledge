# pledge.py

**OpenBSD `pledge(2)` + `unveil(2)` for Linux — in pure Python**

A single-file, zero-dependency Python port of [Justine Tunney's pledge()](https://justine.lol/pledge/) that uses `ctypes` to build and install SECCOMP BPF filters and Landlock LSM rulesets at runtime. No C compiler, no `pip install`, no root required.

```python
from pledge import pledge, unveil

# Control WHAT the process can do
pledge("stdio rpath wpath")

# Control WHERE the process can do it
unveil("/etc",  "r")       # read-only
unveil("/tmp",  "rwc")     # read + write + create
unveil(None,    None)       # commit — lock it down

open("/etc/hostname").read()   # ✓ allowed path, allowed operation
open("/home/user/secrets")     # ✗ path not unveiled
os.system("curl evil.com")     # ✗ no inet promise
```

---

## Table of Contents

- [Why](#why)
- [The Two Halves of the Sandbox](#the-two-halves-of-the-sandbox)
- [Quick Start](#quick-start)
- [Command-Line Usage](#command-line-usage)
- [Library API](#library-api)
  - [pledge()](#pledgepromises-str---none)
  - [unveil()](#unveilpath-str--none-permissions-str--none---none)
  - [Availability Checks](#availability-checks)
- [Promise Reference](#promise-reference)
- [Unveil Permission Reference](#unveil-permission-reference)
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
  - [pledge + unveil Together: Full Sandbox](#pledge--unveil-together-full-sandbox)
  - [Web Server With Minimal Exposure](#web-server-with-minimal-exposure)
  - [Read-Only Config With Private Temp](#read-only-config-with-private-temp)
  - [Build System Sandbox](#build-system-sandbox)
- [Command-Line Examples](#command-line-examples)
- [How It Works](#how-it-works)
- [Architecture Support](#architecture-support)
- [Caveats](#caveats)
- [Requirements](#requirements)

---

## Why

Linux has powerful sandboxing mechanisms, but they are famously hard to use:

- **SECCOMP BPF** controls which syscalls are allowed, but requires writing raw BPF bytecode — an inscrutable chain of bitwise operations and forward-only jumps.
- **Landlock LSM** controls which filesystem paths are accessible, but has a three-syscall ceremony (`landlock_create_ruleset` → `landlock_add_rule` → `landlock_restrict_self`) with no glibc wrappers.

OpenBSD distills both ideas into two simple calls:

```python
pledge("stdio rpath")         # what operations are allowed
unveil("/data", "r")          # what paths are visible
```

This library gives you exactly that API on Linux. One function call, one human-readable string, kernel-enforced.

---

## The Two Halves of the Sandbox

`pledge()` and `unveil()` solve different problems and are most powerful when used together:

```
┌──────────────────────────────────────────────────────────────────┐
│                         Your Process                             │
│                                                                  │
│   pledge("stdio rpath wpath")      unveil("/data", "rw")        │
│   ┌─────────────────────────┐      ┌──────────────────────────┐  │
│   │  Controls OPERATIONS    │      │  Controls PATHS          │  │
│   │                         │      │                          │  │
│   │  ✓ read/write files     │      │  ✓ /data (read+write)    │  │
│   │  ✓ basic I/O            │      │  ✗ /etc (hidden)         │  │
│   │  ✗ network sockets      │      │  ✗ /home (hidden)        │  │
│   │  ✗ fork processes       │      │  ✗ everything else       │  │
│   │  ✗ execute programs     │      │                          │  │
│   │                         │      │                          │  │
│   │  SECCOMP BPF            │      │  Landlock LSM            │  │
│   │  (kernel ≥ 3.5)         │      │  (kernel ≥ 5.13)         │  │
│   └─────────────────────────┘      └──────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

| | `pledge()` only | `unveil()` only | Both together |
|---|---|---|---|
| Can the process open sockets? | Controlled | Not controlled | Controlled |
| Can the process read `/etc/shadow`? | Allowed (if `rpath`) | Controlled | Controlled |
| Can the process write to `/tmp`? | Allowed (if `wpath`) | Controlled | Controlled |
| Can the process fork? | Controlled | Not controlled | Controlled |
| **Kernel mechanism** | SECCOMP BPF | Landlock LSM | Both |
| **Minimum kernel** | 3.5 | 5.13 | 5.13 |

Using `pledge()` alone is still valuable — it prevents entire classes of operations (networking, process creation, etc.). Adding `unveil()` on top gives you path-level precision.

---

## Quick Start

**1. Drop the file into your project:**

```bash
curl -O https://raw.githubusercontent.com/tensor-goat/pledge/refs/heads/main/pledge.py
# or just copy pledge.py into your project directory
```

**2. Use it in your code:**

```python
from pledge import pledge, unveil

# Do your setup (imports, open config files, etc.) FIRST
import json
config = json.load(open("config.json"))

# Restrict paths (optional — requires kernel ≥ 5.13)
unveil(".", "r")           # read-only access to working dir
unveil(None, None)         # commit

# Restrict operations
pledge("stdio")            # only basic I/O from here on

print(json.dumps(config))  # ✓ fine
open("secrets.txt")        # ✗ EACCES (unveil) or EPERM (pledge)
```

**3. Or wrap an existing command:**

```bash
# pledge only — restrict operations
python3 pledge.py -p "stdio rpath" -- cat /etc/hostname

# pledge + unveil — restrict operations AND paths
python3 pledge.py -p "stdio rpath" -v /etc -- cat /etc/hostname
```

---

## Command-Line Usage

```
pledge [-p PROMISES] [-v [PERM:]PATH] [-V] [--penalty {eperm,kill}]
       [--test] [--dump] [command ...]
```

| Flag | Description |
|------|-------------|
| `-p PROMISES` | Space-separated promise list (default: `stdio rpath`) |
| `-v [PERM:]PATH` | Unveil a path. `PERM` defaults to `r`. Repeatable. |
| `-V` | Disable unveiling (pledge only, no path restrictions) |
| `--penalty eperm` | Violations return `EPERM` (default) |
| `--penalty kill` | Violations kill the process with `SIGSYS` |
| `--test` | Check if pledge/unveil are available on this system |
| `--dump` | Print BPF program statistics for the given promises |

When wrapping a command, the CLI automatically adds `exec`, `rpath`, and (for dynamically linked binaries) `prot_exec` promises. It detects dynamic vs. static ELF binaries by scanning for `PT_INTERP`.

---

## Library API

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
- Does not require root — uses `PR_SET_NO_NEW_PRIVS`.

### `unveil(path: str | None, permissions: str | None) -> None`

Restrict filesystem access to only the specified paths and permissions.

```python
from pledge import unveil

unveil("/usr",    "rx")      # read + execute
unveil("/etc",    "r")       # read only
unveil("/tmp",    "rwc")     # read + write + create
unveil(".",       "rwc")     # current directory
unveil(None,      None)      # commit — no more changes
```

- The first call to `unveil()` begins building an allowlist. The entire filesystem is hidden except for unveiled paths.
- `unveil(None, None)` commits the ruleset. After committing, no more paths can be added.
- On Linux, rules are batched and only take effect on commit (unlike OpenBSD where each call takes immediate effect).
- Requires kernel ≥ 5.13 (Landlock LSM). On older kernels, raises `OSError` with `ENOSYS`.
- Does not require root — uses `PR_SET_NO_NEW_PRIVS`.

**Permission characters:**

| Char | Meaning | Corresponding pledge promise |
|------|---------|-----|
| `r` | Read files, list directories | `rpath` |
| `w` | Write to existing files | `wpath` |
| `x` | Execute files | `exec` |
| `c` | Create and remove files/directories | `cpath` |

### Availability Checks

```python
from pledge import pledge_available, unveil_available

if pledge_available():
    pledge("stdio rpath")

if unveil_available():
    unveil("/data", "r")
    unveil(None, None)
```

`pledge_available()` returns `True` on kernel ≥ 3.5 (almost all modern systems).
`unveil_available()` returns `True` on kernel ≥ 5.13 with Landlock enabled.

---

## Promise Reference

Every promise grants access to a specific group of system calls. Start with only what you need.

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
| `id` | Identity changes: `setuid`, `setgid`, `setgroups`, `setfsuid`, `setfsgid` |
| `recvfd` | Receive file descriptors: `recvmsg` (SCM_RIGHTS) |
| `sendfd` | Send file descriptors: `sendmsg` (SCM_RIGHTS) |
| `tmppath` | Temp file ops: `unlink`, `unlinkat`, `lstat` |
| `vminfo` | System info: `/proc/stat`, `/proc/meminfo`, etc. |

---

## Unveil Permission Reference

The `unveil()` permission string controls what operations are allowed on each path. Permissions are additive — `"rw"` means read and write.

| Permission | Allowed operations | Landlock access rights |
|---|---|---|
| `r` | Read files, list directories, `stat`, `readlink` | `READ_FILE`, `READ_DIR` |
| `w` | Write to existing files, truncate | `WRITE_FILE`, `TRUNCATE` (ABI v3+) |
| `x` | Execute files (via `execve`) | `EXECUTE` |
| `c` | Create files/dirs, remove files/dirs, rename, link, symlink | `MAKE_REG`, `MAKE_DIR`, `MAKE_SYM`, `REMOVE_FILE`, `REMOVE_DIR`, `REFER` |

**Common combinations:**

| String | Meaning | Typical use |
|--------|---------|-------------|
| `"r"` | Read-only | Config dirs, CA certs, shared libraries |
| `"rw"` | Read and write | Log files, database files |
| `"rx"` | Read and execute | `/usr/bin`, `/lib` |
| `"rwc"` | Full file management | Working directories, `/tmp` |
| `"rwxc"` | Everything | Rarely needed |

---

## Argument Filtering

Unlike simple syscall allowlists, pledge.py applies **argument-level filtering** on several system calls:

| Syscall | Filtering |
|---------|-----------|
| `open` / `openat` | Flags checked: `O_RDONLY` needs `rpath`, `O_WRONLY`/`O_RDWR` needs `wpath`, `O_CREAT` needs `cpath` |
| `socket` | Family checked: `AF_INET`/`AF_INET6` needs `inet` or `dns`, `AF_UNIX` needs `unix` |
| `ioctl` | Command checked: `stdio` allows `FIONREAD`/`FIONBIO`/`FIOCLEX`/`FIONCLEX`; `tty` allows `TIOCGWINSZ`/`TCGETS`/`TCSETS*` |
| `fcntl` | Command checked: `stdio` allows `F_GETFD`/`F_SETFD`/`F_GETFL`/`F_SETFL`; `flock` allows `F_GETLK`/`F_SETLK` |
| `mmap` / `mprotect` | `PROT_EXEC` blocked unless `prot_exec` or `thread` is pledged |
| `sendto` | With `stdio`-only, destination address must be `NULL` |

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

# From here on, only computation and stdout/stderr work
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

with open(sys.argv[1]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        if float(row["amount"]) > 1000:
            print(f"{row['date']}: ${row['amount']}")

# Cannot write, create, or delete anything
# open("output.csv", "w")  → PermissionError
# os.unlink("data.csv")    → PermissionError
```

### Network Client That Can't Touch the Filesystem

```python
import socket
import ssl
from pledge import pledge

# Set up SSL BEFORE pledging
context = ssl.create_default_context()

pledge("stdio rpath inet dns")

sock = socket.create_connection(("example.com", 443))
ssock = context.wrap_socket(sock, server_hostname="example.com")
ssock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
response = ssock.recv(4096)
print(response.decode())

# Cannot write to disk or fork processes
# open("/tmp/stolen.txt", "w")  → PermissionError
```

### Progressive Privilege Dropping

```python
from pledge import pledge
import sqlite3

# Phase 1: read config, allow network
pledge("stdio rpath inet dns")

config = open("app.conf").read()
conn = sqlite3.connect("data.db")
results = conn.execute("SELECT * FROM users").fetchall()

# Phase 2: done reading files
pledge("stdio inet")

# conn still works (fd already open), but new opens blocked
send_results_to_api(results)

# Phase 3: computation only
pledge("stdio")

print(f"Processed {len(results)} records")
```

### Worker Process Enclave

Fork a worker that can only compute:

```python
from pledge import pledge
import os
import mmap

buf = mmap.mmap(-1, 4096)
buf.write(b"input data here")

pid = os.fork()
if pid == 0:
    pledge("stdio")

    buf.seek(0)
    data = buf.read(15)
    buf.seek(0)
    buf.write(data.upper())
    os._exit(0)

os.waitpid(pid, 0)
buf.seek(0)
print(buf.read(15))  # b"INPUT DATA HERE"
```

### Sandboxing Untrusted Plugins

```python
from pledge import pledge
import importlib
import json
import os

def run_plugin_sandboxed(plugin_name: str, input_data: dict) -> dict:
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        plugin = importlib.import_module(f"plugins.{plugin_name}")

        # Lock down — plugin can only compute and write to pipe
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
```

### Locked-Down Web Scraper

```python
import urllib.request
import ssl
import json
from pledge import pledge

context = ssl.create_default_context()
pledge("stdio rpath inet dns")

urls = ["https://api.example.com/data1", "https://api.example.com/data2"]
for url in urls:
    with urllib.request.urlopen(url, context=context) as resp:
        print(json.dumps(json.loads(resp.read()), indent=2))

# Cannot save results, spawn processes, or access terminal
```

### Protecting a CLI Tool From Itself

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

    if pledge_available():
        pledge("stdio rpath")

    for filename in sys.argv[2:]:
        with open(filename) as f:
            for lineno, line in enumerate(f, 1):
                if pattern.search(line):
                    print(f"{filename}:{lineno}: {line}", end="")

if __name__ == "__main__":
    main()
```

### Sandboxing AI Code Execution

```python
from pledge import pledge
import os
import json

def execute_ai_code(code: str, input_data: dict) -> dict:
    r_fd, w_fd = os.pipe()
    pid = os.fork()

    if pid == 0:
        os.close(r_fd)
        pledge("stdio")  # maximum lockdown

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


# Safe: computation only
r = execute_ai_code('output = sum(input_data["n"]) * 2', {"n": [1,2,3]})
# → {"status": "ok", "output": 12}

# Malicious: socket blocked
r = execute_ai_code('import socket; socket.socket()', {})
# → {"status": "error", "error": "[Errno 1] Operation not permitted"}

# Malicious: file write blocked
r = execute_ai_code('open("/tmp/pwned","w").write("hi")', {})
# → {"status": "error", "error": "[Errno 1] Operation not permitted"}
```

### pledge + unveil Together: Full Sandbox

This is the most secure pattern — controlling both operations and paths:

```python
from pledge import pledge, unveil, unveil_available
import json

# ── Phase 1: Set up path restrictions ──
if unveil_available():
    unveil("data/",    "r")       # read input data
    unveil("output/",  "rwc")     # write results
    unveil("/usr/lib", "r")       # shared libraries (already loaded)
    unveil(None, None)            # commit — filesystem locked

# ── Phase 2: Set up operation restrictions ──
pledge("stdio rpath wpath cpath")

# ── Now the process can: ──
data = json.load(open("data/input.json"))        # ✓ unveiled path + rpath

with open("output/result.json", "w") as f:       # ✓ unveiled path + wpath + cpath
    json.dump({"processed": len(data)}, f)

# ── But cannot: ──
# open("/etc/passwd")            → EACCES (not unveiled)
# open("/home/user/.ssh/id_rsa") → EACCES (not unveiled)
# socket.socket()                → EPERM  (no inet promise)
# os.fork()                      → EPERM  (no proc promise)
# os.system("rm -rf /")          → EPERM  (no exec/proc promise)
```

### Web Server With Minimal Exposure

```python
import socket
from pledge import pledge, unveil, unveil_available

# Pre-load everything
import json
import mimetypes

# Restrict filesystem to just the document root
if unveil_available():
    unveil("./public",     "r")     # serve files from here
    unveil("./logs",       "rw")    # write access logs
    unveil("/etc/ssl",     "r")     # TLS certificates
    unveil("/usr/lib",     "r")     # shared libraries
    unveil(None, None)

# Restrict operations
pledge("stdio rpath wpath inet")

# Bind and serve
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 8080))
server.listen(128)

while True:
    client, addr = server.accept()
    # serve files from ./public only
    # even if an attacker finds a bug, they can't:
    #   - read files outside ./public and ./logs
    #   - execute programs
    #   - escalate privileges
    client.close()
```

### Read-Only Config With Private Temp

```python
from pledge import pledge, unveil, unveil_available

# Typical application pattern: read config, write to temp
if unveil_available():
    unveil("/etc/myapp",   "r")     # config files
    unveil("/tmp/myapp",   "rwc")   # scratch space
    unveil("/var/log",     "rw")    # log files
    unveil(None, None)

pledge("stdio rpath wpath cpath tmppath")

# Can read config
config = open("/etc/myapp/settings.conf").read()

# Can use temp files
with open("/tmp/myapp/cache.dat", "w") as f:
    f.write("cached data")

# Cannot read sensitive files
# open("/etc/shadow")     → EACCES (not unveiled)
# open("/home/user/.ssh") → EACCES (not unveiled)
```

### Build System Sandbox

Inspired by [Justine Tunney's Landlocked Make](https://justine.lol/make/) — restrict a build command to its declared inputs/outputs:

```python
from pledge import pledge, unveil, unveil_available
import subprocess
import sys

def sandboxed_build(src_dirs: list[str], out_dir: str, cmd: list[str]):
    """Run a build command with restricted filesystem access."""

    if unveil_available():
        # Source directories: read-only
        for d in src_dirs:
            unveil(d, "r")

        # Output directory: full access
        unveil(out_dir, "rwc")

        # System directories needed for compilation
        unveil("/usr/bin",     "rx")
        unveil("/usr/lib",     "r")
        unveil("/lib",         "r")
        unveil("/tmp",         "rwc")
        unveil(None, None)

    pledge("stdio rpath wpath cpath exec prot_exec proc tmppath")

    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
    return result.returncode

# The compiler can only read source and write to build/
sandboxed_build(
    src_dirs=["src/", "include/"],
    out_dir="build/",
    cmd=["gcc", "-o", "build/main", "src/main.c"]
)
```

---

## Command-Line Examples

**List files (read-only):**

```bash
python3 pledge.py -p "stdio rpath" -- ls -la /etc/
```

**Read a file with path restrictions:**

```bash
# Only allow access to /etc — everything else is hidden
python3 pledge.py -p "stdio rpath" -v /etc -- cat /etc/hostname
```

**Run a shell with only read access:**

```bash
python3 pledge.py -p "stdio rpath tty" -- bash
# Inside:  cat /etc/passwd    ✓ works
#          echo hi > /tmp/x   ✗ EPERM
#          curl example.com   ✗ EPERM
```

**Grant write access to a specific directory:**

```bash
python3 pledge.py -p "stdio rpath wpath cpath" -v rwc:. -- python3 my_script.py
```

**Unveil multiple paths with different permissions:**

```bash
python3 pledge.py \
  -p "stdio rpath wpath cpath" \
  -v /etc \
  -v r:/usr/share \
  -v rwc:/tmp \
  -v rwc:. \
  -- bash
```

**Kill process on violation (instead of EPERM):**

```bash
python3 pledge.py --penalty kill -p "stdio rpath" -- python3 untrusted.py
```

**Check system capabilities:**

```bash
$ python3 pledge.py --test
kernel:    6.8.0-45-generic
arch:      x86_64 (AUDIT_ARCH=0xC000003E)
pledge:    available (seccomp BPF)
unveil:    available (Landlock ABI v4)
```

**Inspect the BPF filter:**

```bash
$ python3 pledge.py --dump -p "stdio rpath inet dns"
Promises: stdio rpath inet dns
BPF instructions: 280
BPF program size: 2240 bytes
Allowed syscalls (107): accept, accept4, access, ...
```

**Disable unveil (pledge only):**

```bash
python3 pledge.py -V -p "stdio rpath" -- ls -la
```

---

## How It Works

### pledge() — SECCOMP BPF

1. **Promise parsing** — Your promise string is split into categories. Each maps to a set of allowed syscall names with optional argument constraints.

2. **BPF compilation** — A `BPFBuilder` generates a SECCOMP BPF filter:
   - Validates CPU architecture (`AUDIT_ARCH_X86_64` / `AUDIT_ARCH_AARCH64`)
   - Loads the syscall number from `seccomp_data.nr`
   - For simple syscalls: conditional jump → `SECCOMP_RET_ALLOW`
   - For filtered syscalls (`open`, `socket`, `ioctl`, `mmap`, etc.): loads `seccomp_data.args[]` and checks argument values
   - Default: `SECCOMP_RET_ERRNO | EPERM` or `SECCOMP_RET_KILL_PROCESS`

3. **Installation** via `prctl(PR_SET_NO_NEW_PRIVS, 1)` + `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`.

### unveil() — Landlock LSM

1. **Rule collection** — Each `unveil(path, perms)` call stores a path + access rights pair.

2. **Ruleset creation** — On `unveil(None, None)`, calls:
   - `landlock_create_ruleset()` with a bitmask of all access rights to deny by default
   - `landlock_add_rule(LANDLOCK_RULE_PATH_BENEATH)` for each unveiled path, with an `O_PATH` fd and access bits
   - `landlock_restrict_self()` to enforce

3. **ABI negotiation** — Queries the Landlock ABI version and adjusts the handled access mask. Newer ABIs (v2: `REFER`, v3: `TRUNCATE`, v4: `IOCTL_DEV`) are used when available, older features degrade gracefully.

```
┌──────────┐    ┌─────────────┐    ┌──────────────┐
│ pledge() │───▶│ BPFBuilder  │───▶│ prctl()      │
│          │    │ (bytecode)  │    │ SECCOMP BPF  │
└──────────┘    └─────────────┘    └──────┬───────┘
                                          │
┌──────────┐    ┌─────────────┐    ┌──────▼───────┐
│ unveil() │───▶│ Landlock    │───▶│   Kernel     │
│          │    │ ruleset     │    │              │
└──────────┘    └─────────────┘    │  syscall ──▶ seccomp check
                                   │  file op ──▶ landlock check
                                   │    ✓ → allow
                                   │    ✗ → EPERM / EACCES
                                   └──────────────┘
```

---

## Architecture Support

| Architecture | pledge() | unveil() | AUDIT_ARCH |
|---|---|---|---|
| x86_64 / amd64 | ✓ | ✓ | `0xC000003E` |
| aarch64 / arm64 | ✓ | ✓ | `0xC00000B7` |

pledge() requires architecture-specific syscall number tables (~180 entries each). unveil() uses architecture-independent Landlock syscall numbers (444–446, same everywhere).

---

## Caveats

**Import order matters.** Python's `import` machinery opens files and loads shared libraries. Do your imports *before* calling `pledge()` or `unveil()`.

```python
# ✓ Correct: import before pledge
import json, csv, socket
from pledge import pledge
pledge("stdio")

# ✗ Wrong: import triggers file operations that are blocked
from pledge import pledge
pledge("stdio")
import json  # PermissionError!
```

**unveil paths are resolved at call time.** Paths are resolved to real paths via `os.path.realpath()` when you call `unveil()`. Symlinks are followed. If a directory is removed and recreated after unveiling, access may be denied.

**unveil commits are batched on Linux.** Unlike OpenBSD where each `unveil()` call takes immediate effect, on Linux rules are collected and only enforced when you call `unveil(None, None)`. This is a Landlock limitation — the ruleset must be built atomically.

**glibc internals.** glibc uses `futex`, `rseq`, `mremap`, and other syscalls internally. The `stdio` promise includes these. If a program fails unexpectedly, run it under `strace` to see which syscall is getting `EPERM`.

**Cumulative filters.** Each `pledge()` call installs an additional SECCOMP filter. Each `unveil(None, None)` call enforces an additional Landlock domain. The kernel takes the most restrictive result across all layers.

**No `execpromises`.** Linux SECCOMP doesn't support different promise sets post-`execve`. The `execpromises` parameter is accepted but ignored.

**Landlock ABI evolution.** Landlock gains new capabilities with each kernel version. pledge.py queries the ABI version and adapts:

| ABI | Kernel | New capability |
|-----|--------|----------------|
| v1 | 5.13 | Basic filesystem access control |
| v2 | 5.19 | File reparenting (`REFER`) |
| v3 | 6.2 | File truncation (`TRUNCATE`) |
| v4 | 6.8 | Device ioctl (`IOCTL_DEV`) |

On older ABIs, newer access rights are silently omitted from the handled mask.

---

## Requirements

- **Linux** kernel ≥ 3.5 for pledge (SECCOMP), ≥ 5.13 for unveil (Landlock)
- **Python** ≥ 3.10
- **No root** — uses `PR_SET_NO_NEW_PRIVS` for unprivileged operation
- **No dependencies** — pure standard library + `ctypes`
- **Single file** — just copy `pledge.py` into your project

---

## License

Based on Justine Tunney's [cosmopolitan libc pledge() implementation](https://justine.lol/pledge/), which is ISC licensed. This Python port is released under the same terms.
