# CodeEditorENGINE (CODE_EXECUTION_BOX)

Hardened, multi-tenant Linux sandbox and code execution engine written in Rust (Axum/Tokio). Supports 7 runtimes (Python, Node.js, C, C++, Bash, Java 21, Rust) with multi-layered isolation: Bubblewrap 0.12.0 namespaces, Seccomp-BPF system call filtering, and Linux cgroup v2 resource accounting.

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

### Option 1: Automated One-Line Script (Easiest)

Clone the repository and run the automated startup script:
```bash
git clone https://github.com/niteshxedev-byte/CODE_EXECUTION_BOX.git
cd CODE_EXECUTION_BOX
./run.sh
```
This script will:
1. Verify Docker and cgroup v2 availability.
2. Build the multi-stage Docker container.
3. Start the container with `-p 3000:3000`, `--privileged`, `--cgroupns=host`, and `/sys/fs/cgroup` mounted.
4. Wait for the engine's 10-probe startup self-test to report healthy.

---

### Option 2: Docker Compose

```bash
git clone https://github.com/niteshxedev-byte/CODE_EXECUTION_BOX.git
cd CODE_EXECUTION_BOX
docker compose up -d --build
```

To stop:
```bash
docker compose down
```

---

### Option 3: Standard Docker CLI Commands

```bash
# 1. Build the image
docker build -t code-editor-engine:latest .

# 2. Run the container with required host sandbox permissions
docker run -d \
  --name code-editor-engine \
  --restart unless-stopped \
  -p 3000:3000 \
  --privileged \
  --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  code-editor-engine:latest
```

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
  "sandbox": {
    "seccomp_probes_passed": "10/10",
    "bwrap_containerization": true,
    "cgroup_v2_controller": true,
    "is_degraded": false
  }
}
```

### 2. Supported Languages
```bash
curl -s http://localhost:3000/languages | jq
```

### 3. Submit Code for Execution

Submit a Python snippet:
```bash
curl -X POST http://localhost:3000/submissions \
  -H "Content-Type: application/json" \
  -d '{"language_id": 71, "source_code": "print(sum([x * 2 for x in range(10)]))"}'
```
Response:
```json
{
  "token": "d748f34f-0158-45ee-911d-6aa8eb4ca9ea"
}
```

Fetch the execution result:
```bash
curl -s http://localhost:3000/submissions/d748f34f-0158-45ee-911d-6aa8eb4ca9ea | jq
```
Output:
```json
{
  "stdout": "90\n",
  "status": {
    "id": 3,
    "description": "Accepted"
  },
  "time": "0.024",
  "memory": 12480
}
```

