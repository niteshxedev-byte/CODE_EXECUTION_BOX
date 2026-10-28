#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="code-editor-engine"
IMAGE_NAME="code-editor-engine:latest"
PORT="3000"
PUBLIC_URL="${1:-${PUBLIC_URL:-http://localhost:3001,http://192.168.31.127:3001}}"
AUTH_TOKEN="${AUTH_TOKEN:-dev-token}"

echo "========================================================"
echo "  CodeEditorENGINE - Linux Mint / Docker Startup"
echo "  Public URL Lockdown: $PUBLIC_URL"
echo "========================================================"

# 1. Check for Docker
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker is not installed or not in PATH." >&2
    echo "Install docker on Linux Mint with: sudo apt install docker.io docker-compose-v2" >&2
    exit 1
fi

# 2. Check cgroup v2 presence
if [ ! -d /sys/fs/cgroup ]; then
    echo "ERROR: /sys/fs/cgroup not found. Cgroup v2 is required." >&2
    exit 1
fi

# 3. Stop and remove existing container if running
echo "[1/4] Stopping existing container if present..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# 4. Build the image
echo "[2/4] Building Docker image..."
if command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1; then
    docker compose build || docker build -t "$IMAGE_NAME" .
else
    docker build -t "$IMAGE_NAME" .
fi

# 5. Start container with required host sandbox permissions & URL Auth
echo "[3/4] Launching container with URL auth & cgroup delegation..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${PORT}:3000" \
    -e PUBLIC_URL="$PUBLIC_URL" \
    -e AUTH_TOKEN="$AUTH_TOKEN" \
    --privileged \
    --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    "$IMAGE_NAME"

# 6. Verify healthcheck
echo "[4/4] Verifying engine startup & 10/10 security probes..."
MAX_RETRIES=30
for i in $(seq 1 "$MAX_RETRIES"); do
    sleep 1
    if curl -s -f "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
        echo ""
        echo "========================================================"
        echo "  CodeEditorENGINE is RUNNING and HEALTHY!"
        echo "  URL: http://localhost:${PORT}"
        echo "  Health: http://localhost:${PORT}/health"
        echo "  Protected by URL Auth: Only requests from $PUBLIC_URL are accepted."
        echo "========================================================"
        echo ""
        curl -s "http://127.0.0.1:${PORT}/health"
        echo ""
        exit 0
    fi
    echo -n "."
done

echo ""
echo "WARNING: Health check did not pass within 30 seconds. Checking container logs:"
docker logs --tail 30 "$CONTAINER_NAME"
exit 1
