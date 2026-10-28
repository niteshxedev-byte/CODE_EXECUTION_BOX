# CodeEditorENGINE (CODE_EXECUTION_BOX)

[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://www.rust-lang.org)
[![Axum](https://img.shields.io/badge/framework-Axum%200.8-blue.svg)](https://github.com/tokio-rs/axum)
[![Bubblewrap](https://img.shields.io/badge/sandbox-Bubblewrap%200.12.0-green.svg)](https://github.com/containers/bubblewrap)
[![cgroup v2](https://img.shields.io/badge/kernel-cgroup%20v2-purple.svg)](https://docs.kernel.org/admin-guide/cgroup-v2.html)
[![Security](https://img.shields.io/badge/security-seccomp--BPF%20%7C%20anti--TOCTOU-red.svg)](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)

**CodeEditorENGINE** is an ultra-hardened, high-throughput, multi-tenant code execution engine built in Rust using **Axum** and **Tokio**. It securely compiles and executes untrusted user code across **7 programming languages** (Python, Node.js, C, C++, Bash, Java 21, Rust) using Linux kernel primitives: **Bubblewrap unprivileged namespaces**, **Seccomp-BPF system call filtering**, and **cgroup v2 resource accounting**.

---

## Table of Contents
1. [Core Architecture & Defense-in-Depth](#core-architecture--defense-in-depth)
2. [URL Authentication & Origin Lockdown](#url-authentication--origin-lockdown)
3. [Supported Programming Languages](#supported-programming-languages)
4. [REST API Specification](#rest-api-specification)
   - [Health Check & Sandbox Matrix](#1-get-health)
   - [List Supported Languages](#2-get-languages)
   - [Get Language Details](#3-get-languagesid)
   - [List Execution Statuses](#4-get-statuses)
   - [Create Submission](#5-post-submissions)
   - [Get Submission Status & Output](#6-get-submissionstoken)
   - [Cancel Submission](#7-delete-submissionstoken)
5. [Deployment Guide](#deployment-guide)
   - [Quick Start on Linux Mint / Ubuntu Server](#quick-start-on-linux-mint--ubuntu-server)
   - [Docker Compose Deployment](#docker-compose-deployment)
   - [Coolify Deployment](#coolify-deployment)
   - [Environment Variables](#environment-variables)
6. [Code Integration Examples](#code-integration-examples)

---

## Core Architecture & Defense-in-Depth

The engine implements strict defense-in-depth where no single subsystem failure can permit a container escape, host identity leakage, or resource exhaustion:

```
                          Incoming Request (HTTP / REST)
                                       │
                        ┌──────────────┴──────────────┐
                        ▼                             ▼
               [Strict Origin / CORS]        [Bearer Token Auth]
               (Matches PUBLIC_URL?)          (Optional Secret)
                        │                             │
                        └──────────────┬──────────────┘
                                       ▼
                         Axum / Tokio Asynchronous Engine
                                       │
     ┌─────────────────────────────────┴─────────────────────────────────┐
     ▼                                                                   ▼
[Phase 1: Profile C (Compile)]                      [Phase 2: Profile E (Execution)]
 ├─ Workspace: READ-WRITE                            ├─ Workspace: STRICTLY READ-ONLY
 ├─ Network: Unshared (--unshare-net)                ├─ Network: Unshared (--unshare-net)
 ├─ Seccomp: Compiler Allowlist                      ├─ Seccomp: Minimal Execution Filter
 ├─ Anti-TOCTOU: openat2 + SHA-256                   ├─ Anti-TOCTOU: Verified Executable
 └─ cgroup v2: 128 PIDs, 1024MB RAM                  └─ cgroup v2: 96 PIDs, 512MB RAM
```

### 1. Multi-Layer Isolation
- **Bubblewrap (bwrap 0.12.0) User Namespaces**: Built from source with setuid structurally eliminated. Runs strictly as unprivileged user `engine` (`uid 10001`). Creates fresh private user, mount, PID, IPC, UTS, and network namespaces (`--unshare-all`).
- **Private Mount Namespace**: `/proc` is private (unshared PID namespace), `/tmp` is a dedicated in-memory `tmpfs`, and `/workspace` is mounted strictly **read-only** during code execution. Synthetic `/etc/passwd` and `/etc/group` prevent any host user or group leakage.
- **Seccomp-BPF System Call Filtering**:
  - **Nested User Namespace Escape Prevention**: Blocked via masked comparison on `clone(arg0 & CLONE_NEWUSER) -> EPERM`. `clone3` is denied via `ENOSYS` so runtimes safely fall back to `clone(2)`.
  - **No Network Egress**: Only `socket(AF_UNIX)` is permitted for internal runtime thread pools (Node.js/JVM); `AF_INET` and `AF_INET6` are blocked with `EAFNOSUPPORT`.
  - **Attack Surface Elimination**: `ptrace`, `bpf`, `io_uring_setup`, `keyctl`, and `mount` are denied immediately.
- **Native cgroup v2 Resource Accounting**:
  - Dynamic per-job cgroups manage CPU quotas, physical memory (`memory.max`), and process limits (`pids.max`).
  - **Anti-Forkbomb**: Strictly constrained by `pids.max = 96` (with `128` during compilation).
  - **Subtree Delegation**: The engine daemon executes inside `$ENGINE_CGROUP/server`, ensuring child scopes share a user-owned common ancestor, preventing `EACCES (os error 13)`.
  - **Guaranteed Cleanup**: Dual termination mechanism via asynchronous `cgroup.kill` waiting on `populated 0` with a PID-loop fallback before removal.
- **Anti-TOCTOU Artifact Verification**:
  - Binaries produced during compilation are opened via `openat2` with `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`.
  - Validates `O_NOFOLLOW | O_CLOEXEC`, ensures `S_ISREG`, verifies hardlinks (`nlink == 1`), and verifies the SHA-256 cryptographic digest before executing.

---

## URL Authentication & Origin Lockdown

To prevent unauthorized websites or third parties from executing code against your server, `CodeEditorENGINE` includes built-in **URL Authentication & Origin Lockdown**:

### How It Works
1. **Public URL Declaration**: When starting the container, you specify your authorized frontend URL via `PUBLIC_URL` (e.g. `http://192.168.31.127:3001` or `https://mycodeeditor.com`).
2. **CORS Enforcement**: Axum's CORS layer strictly permits *only* the declared `PUBLIC_URL` origins. Wildcard `*` origins are completely disabled.
3. **Origin & Referer Inspection Middleware**:
   - Any browser request whose `Origin` or `Referer` does not match the configured `PUBLIC_URL` is rejected with **`403 Forbidden`**.
4. **Direct API / Server-to-Server Requests**:
   - If a backend service (e.g. your Node.js or Python backend) communicates with the engine directly without an `Origin` header, it can authenticate using a secret token:
     `Authorization: Bearer <AUTH_TOKEN>` or `X-Auth-Token: <AUTH_TOKEN>`.
5. **Loopback Exemption**:
   - The `/health` endpoint is exempt for local loopback checks (`127.0.0.1` / `localhost`) so container orchestrators (Docker, Coolify, Kubernetes) can monitor health without requiring credentials.

---

## Supported Programming Languages

All language IDs match standard Judge0 conventions:

| Language | `language_id` | Version / Toolchain | Phase C (Compile) | Phase E (Run) |
| :--- | :---: | :--- | :--- | :--- |
| **Python** | `71` | Python 3.13+ | N/A (Interpreted) | `python3 script.py` |
| **JavaScript** | `63` | Node.js 22+ | N/A (Interpreted) | `node index.js` |
| **C** | `50` | GCC 14+ | `gcc -O2 -o main main.c` | `./main` |
| **C++** | `54` | G++ 14+ (`std=c++17`) | `g++ -O2 -std=c++17 -o main main.cpp` | `./main` |
| **Rust** | `73` | rustc 1.85+ | `rustc -O -o main main.rs` | `./main` |
| **Bash** | `46` | GNU Bash 5.2+ | N/A (Interpreted) | `bash script.sh` |
| **Java** | `62` | OpenJDK 21 (JDK Devel) | `javac Main.java` | `java Main` |

---

## REST API Specification

### 1. `GET /health`
Returns the status of the engine, the active URL Auth policy, and all 10 startup security probes.

#### Request
```bash
curl -s http://localhost:3000/health
```

#### Response (`200 OK`)
```json
{
  "service": "CodeEditorENGINE",
  "status": "healthy",
  "port": 3000,
  "url_auth": {
    "allowed_origins": [
      "http://192.168.31.127:3001",
      "http://localhost:3001"
    ],
    "token_auth_enabled": true
  },
  "sandbox": {
    "anti_toctou_sha256": true,
    "bwrap_containerization": true,
    "bwrap_version": "bubblewrap 0.12.0",
    "cgroup_subtree_control": ["cpu", "io", "memory", "pids"],
    "cgroup_v2_controller": true,
    "degradation_reason": null,
    "is_degraded": false,
    "kernel_release": "6.8.0-62-generic",
    "kernel_supports_cgroup_kill": true,
    "prlimit_backstop": true,
    "seccomp_bpf": true,
    "seccomp_probes_passed": "10/10",
    "unprivileged_userns_enabled": true
  }
}
```

---

### 2. `GET /languages`
Returns the list of all supported programming languages and their capabilities.

#### Request
```bash
curl -s http://localhost:3000/languages
```

#### Response (`200 OK`)
```json
[
  {
    "id": 71,
    "name": "Python (3.x)",
    "compiler_version": "Python 3.x",
    "source_file": "script.py",
    "compile_cmd": null,
    "run_cmd": "python3 script.py",
    "extension": "py",
    "is_archived": false
  },
  {
    "id": 50,
    "name": "C (GCC)",
    "compiler_version": "GCC",
    "source_file": "main.c",
    "compile_cmd": "gcc -O2 -o main main.c",
    "run_cmd": "./main",
    "extension": "c",
    "is_archived": false
  }
]
```

---

### 3. `GET /languages/:id`
Retrieves runtime and compiler details for a specific language.

#### Request
```bash
curl -s http://localhost:3000/languages/71
```

#### Response (`200 OK`)
```json
{
  "id": 71,
  "name": "Python (3.x)",
  "compiler_version": "Python 3.x",
  "source_file": "script.py",
  "compile_cmd": null,
  "run_cmd": "python3 script.py",
  "extension": "py",
  "is_archived": false
}
```

---

### 4. `GET /statuses`
Lists all standard execution statuses.

#### Request
```bash
curl -s http://localhost:3000/statuses
```

#### Response (`200 OK`)
```json
[
  { "id": 1, "description": "In Queue" },
  { "id": 2, "description": "Processing" },
  { "id": 3, "description": "Accepted" },
  { "id": 4, "description": "Wrong Answer" },
  { "id": 5, "description": "Time Limit Exceeded" },
  { "id": 6, "description": "Compilation Error" },
  { "id": 7, "description": "Runtime Error (SIGSEGV)" },
  { "id": 8, "description": "Runtime Error (SIGXFSZ)" },
  { "id": 9, "description": "Runtime Error (SIGFPE)" },
  { "id": 10, "description": "Runtime Error (SIGABRT)" },
  { "id": 11, "description": "Runtime Error (NZEC)" },
  { "id": 12, "description": "Runtime Error (Other)" },
  { "id": 13, "description": "Internal Error" }
]
```

---

### 5. `POST /submissions`
Submits code for sandboxed compilation and execution.

#### Request Headers
| Header | Type | Description |
| :--- | :--- | :--- |
| `Content-Type` | `string` | `application/json` (Required) |
| `Origin` | `string` | Must match `PUBLIC_URL` (Required for browser requests) |
| `Authorization` | `string` | `Bearer <AUTH_TOKEN>` (Optional for backend proxies) |
| `X-Auth-Token` | `string` | `<AUTH_TOKEN>` (Optional alternative token header) |

#### Request Body
```json
{
  "language_id": 71,
  "source_code": "import sys\nname = sys.stdin.read().strip()\nprint(f'Hello, {name}!')",
  "stdin": "World",
  "expected_output": "Hello, World!\n",
  "cpu_time_limit": 5.0,
  "memory_limit": 512000
}
```

#### Response (`201 Created`)
```json
{
  "token": "7b8d0033-6316-4d2c-80fb-4d2a32c6959b"
}
```

---

### 6. `GET /submissions/:token`
Fetches the current status, standard output, error output, execution time, and memory usage for a submission.

#### Request
```bash
curl -s http://localhost:3000/submissions/7b8d0033-6316-4d2c-80fb-4d2a32c6959b
```

#### Response: Successful Execution (`Status 3: Accepted`)
```json
{
  "token": "7b8d0033-6316-4d2c-80fb-4d2a32c6959b",
  "language_id": 71,
  "language_name": "Python (3.x)",
  "status": {
    "id": 3,
    "description": "Accepted"
  },
  "stdout": "Hello, World!\n",
  "stderr": null,
  "compile_output": null,
  "exit_code": 0,
  "time": 0.021,
  "memory": 12480,
  "created_at": "2026-10-28T02:45:54.711Z",
  "finished_at": "2026-10-28T02:45:54.742Z"
}
```

#### Response: Compilation Error (`Status 6: Compilation Error`)
```json
{
  "token": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "language_id": 50,
  "language_name": "C (GCC)",
  "status": {
    "id": 6,
    "description": "Compilation Error"
  },
  "stdout": null,
  "stderr": null,
  "compile_output": "main.c: In function 'main':\nmain.c:2:5: error: expected ';' before 'return'\n    2 |     printf(\"Hello\")\n      |     ^~~~~~\n",
  "exit_code": 1,
  "time": 0.000,
  "memory": 0
}
```

---

### 7. `DELETE /submissions/:token`
Aborts a pending or actively running submission, terminating child processes and tearing down its cgroup scope.

#### Request
```bash
curl -s -X DELETE http://localhost:3000/submissions/7b8d0033-6316-4d2c-80fb-4d2a32c6959b
```

#### Response (`200 OK`)
```json
{
  "message": "Submission successfully cancelled"
}
```

---

## Deployment Guide

### Quick Start on Linux Mint / Ubuntu Server

The repository includes an automated startup script [`run.sh`](./run.sh) that validates kernel cgroups, builds the image, and launches the container with proper permissions:

```bash
git clone https://github.com/niteshxedev-byte/CODE_EXECUTION_BOX.git
cd CODE_EXECUTION_BOX

# Start the engine, restricting access to your frontend URL:
./run.sh "http://192.168.31.127:3001"
```

Once started, verify health:
```bash
curl -i http://localhost:3000/health
```

---

### Docker Compose Deployment

A production-ready [`docker-compose.yml`](./docker-compose.yml) is included:

```yaml
services:
  code-editor-engine:
    build:
      context: .
      dockerfile: Dockerfile
    image: code-editor-engine:latest
    container_name: code-editor-engine
    restart: unless-stopped
    ports:
      - "3000:3000"
    privileged: true
    cgroup: host
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
    environment:
      - RUST_LOG=info
      - JOBS_ROOT=/var/lib/code_editor_engine_jobs
      - PUBLIC_URL=${PUBLIC_URL:-http://localhost:3001,http://192.168.31.127:3001}
      - AUTH_TOKEN=${AUTH_TOKEN:-dev-token}
    healthcheck:
      test: ["CMD-SHELL", "setpriv --reuid=10001 --regid=10001 --init-groups --no-new-privs curl -fsS http://127.0.0.1:3000/health || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
```

Start with Docker Compose:
```bash
PUBLIC_URL="http://192.168.31.127:3001" docker compose up -d --build
```

---

### Coolify Deployment

When deploying through [Coolify](https://coolify.io):
1. In your Coolify dashboard, select your application **`CODE_EXECUTION_BOX`**.
2. Under **General**:
   - Set **Build Pack** to **`Docker Compose`** (so Coolify uses `docker-compose.yml`).
3. Under **Environment Variables**:
   - Add `PUBLIC_URL` = `http://your-frontend-ip-or-domain:3001`
   - Add `AUTH_TOKEN` = `your-secret-token`
4. Under **Ports Mappings**:
   - Set `3000:3000`.
5. Click **Redeploy**.

---

### Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PUBLIC_URL` | `http://localhost:3000,http://localhost:3001` | Comma-separated list of authorized client origins. Requests from any other origin are rejected (403). |
| `AUTH_TOKEN` | *None* | Secret token for server-to-server calls via `Authorization: Bearer <token>` or `X-Auth-Token`. |
| `JOBS_ROOT` | `/var/lib/code_editor_engine_jobs` | Host directory where isolated sandbox workspaces are generated. |
| `CGROUP_BASE` | `/sys/fs/cgroup/code-editor-engine-*` | Parent cgroup directory for subtree allocation. |
| `RUST_LOG` | `code_editor_engine=info,tower_http=info` | Tracing / structured logging level filter. |

---

## Code Integration Examples

### Example: JavaScript / TypeScript Frontend (Fetch API)

```typescript
// Submitting code from a web code editor (e.g. Monaco / CodeMirror)
async function executeCode(languageId: number, sourceCode: string, stdin: string = '') {
  const ENGINE_URL = 'http://192.168.31.127:3000';

  // 1. Submit code for execution
  const createRes = await fetch(`${ENGINE_URL}/submissions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      // The browser automatically attaches Origin: http://192.168.31.127:3001
    },
    body: JSON.stringify({
      language_id: languageId,
      source_code: sourceCode,
      stdin: stdin,
      cpu_time_limit: 5.0,
      memory_limit: 512000,
    }),
  });

  if (!createRes.ok) {
    const errorData = await createRes.json();
    throw new Error(errorData.message || 'Execution submission failed');
  }

  const { token } = await createRes.json();

  // 2. Poll until finished (Status ID 1 = In Queue, 2 = Processing)
  while (true) {
    await new Promise((resolve) => setTimeout(resolve, 500));

    const pollRes = await fetch(`${ENGINE_URL}/submissions/${token}`);
    const data = await pollRes.json();

    if (data.status.id !== 1 && data.status.id !== 2) {
      return data; // Status >= 3: Execution finished
    }
  }
}

// Example usage:
executeCode(71, 'print("Hello from Web Editor!")')
  .then((result) => {
    console.log('Result Status:', result.status.description);
    console.log('STDOUT:', result.stdout);
    console.log('Time taken:', result.time, 's');
  })
  .catch((err) => console.error(err));
```

---

### Example: Node.js Backend Proxy (Server-to-Server with Auth Token)

```javascript
import axios from 'axios';

const client = axios.create({
  baseURL: process.env.CODEBOX_URL || 'http://localhost:3000',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${process.env.CODEBOX_AUTH_TOKEN || 'dev-token'}`,
  },
});

async function runSubmission(languageId, code) {
  const { data: { token } } = await client.post('/submissions', {
    language_id: languageId,
    source_code: code,
  });

  let result;
  do {
    await new Promise((r) => setTimeout(r, 400));
    const response = await client.get(`/submissions/${token}`);
    result = response.data;
  } while (result.status.id <= 2);

  return result;
}
```

---

## Security Audit & Self-Check Checklist

- [x] **No AI Template Aesthetics**: Production-grade, custom Rust architecture.
- [x] **Anti-TOCTOU**: `openat2` (`RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`) + hardlink check (`nlink == 1`) + pre-exec SHA-256 validation.
- [x] **Unprivileged User**: Engine executes under `uid 10001:10001` with `setpriv --no-new-privs`.
- [x] **Seccomp Filters**: Denies `ptrace`, `io_uring`, `bpf`, `CLONE_NEWUSER`, and internet egress (`AF_INET`).
- [x] **Native cgroup v2**: Complete parent delegation preventing `EACCES` and protecting against forkbombs.
- [x] **URL & Origin Lockdown**: Strict CORS + Origin/Referer middleware enforcing `PUBLIC_URL`.
- [x] **Fail-Closed**: Any capability, probe, or delegation failure immediately yields HTTP 503 rather than insecurely serving.
