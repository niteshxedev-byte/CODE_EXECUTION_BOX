# CodeEditorENGINE (CODE_EXECUTION_BOX)

Hardened, multi-tenant Linux sandbox and code execution engine written in Rust (Axum/Tokio). Supports 7 runtimes (Python, Node.js, C, C++, Bash, Java 21, Rust) with multi-layered isolation: Bubblewrap 0.12.0 namespaces, Seccomp-BPF system call filtering, and Linux cgroup v2 resource accounting.

Includes strict **URL Authentication & Origin Lockdown**: you specify your authorized frontend URL (`PUBLIC_URL`), and all requests originating from or targeting any other URL are rejected with `403 Forbidden`.

---

## Running on Linux Mint / Ubuntu Server with Docker

### Prerequisites on Linux Mint
Ensure Docker is installed:
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2 curl git
sudo usermod -aG docker $USER
# Log out and log back in, or run: newgrp docker
```

---

### Option 1: Automated Startup Script with URL Lockdown

Run with your frontend's public URL:
```bash
git clone https://github.com/niteshxedev-byte/CODE_EXECUTION_BOX.git
cd CODE_EXECUTION_BOX
./run.sh "http://192.168.31.127:3001"
```
*(Only requests originating from `http://192.168.31.127:3001` or localhost will be allowed! Any other URL will be rejected with 403 Forbidden).*

---

### Option 2: Docker Compose

In `docker-compose.yml`, configure your `PUBLIC_URL`:
```yaml
environment:
  - PUBLIC_URL=http://192.168.31.127:3001,http://localhost:3001
  - AUTH_TOKEN=dev-token
```
Then start:
```bash
docker compose up -d --build
```

---

### Option 3: Standard Docker CLI Commands

```bash
# 1. Build the image
docker build -t code-editor-engine:latest .

# 2. Run the container with PUBLIC_URL lockdown & cgroup delegation
docker run -d \
  --name code-editor-engine \
  --restart unless-stopped \
  -p 3000:3000 \
  -e PUBLIC_URL="http://192.168.31.127:3001" \
  -e AUTH_TOKEN="dev-token" \
  --privileged \
  --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  code-editor-engine:latest
```

---

## URL Authentication & Security Behavior

| Request Type | Condition | Result |
| :--- | :--- | :--- |
| **Health Probe** (`/health`) | Any host / local Docker monitoring | **`200 OK`** |
| **Browser Request** | `Origin` matches `PUBLIC_URL` | **`200 OK`** (with strict CORS headers) |
| **Browser Request** | `Origin` does **not** match `PUBLIC_URL` | **`403 Forbidden`** |
| **Direct Request (API/Curl)** | Header `Authorization: Bearer <token>` or `X-Auth-Token: <token>` | **`200 OK`** |
| **Direct Request (API/Curl)** | `Host` header matches allowed domain or localhost | **`200 OK`** |
| **Direct Request (API/Curl)** | `Host` header does not match | **`403 Forbidden`** |

---

## Verifying the Engine

### 1. Health & Security Sandbox Check
```bash
curl -s http://localhost:3000/health | jq
```
Expected output:
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
    "seccomp_probes_passed": "10/10",
    "bwrap_containerization": true,
    "cgroup_v2_controller": true,
    "is_degraded": false
  }
}
```

### 2. Verify URL Lockdown (Testing 403 Forbidden)
```bash
# Test from an unauthorized origin -> returns 403 Forbidden!
curl -i -X POST http://localhost:3000/submissions \
  -H "Origin: http://evil-site.com" \
  -H "Content-Type: application/json" \
  -d '{"language_id": 71, "source_code": "print(1)"}'
# Returns: HTTP/1.1 403 Forbidden

# Test from your authorized PUBLIC_URL -> returns 200 OK!
curl -i -X POST http://localhost:3000/submissions \
  -H "Origin: http://192.168.31.127:3001" \
  -H "Content-Type: application/json" \
  -d '{"language_id": 71, "source_code": "print(1)"}'
# Returns: HTTP/1.1 200 OK with execution token!
```
