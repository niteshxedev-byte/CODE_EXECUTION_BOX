#!/bin/bash
set -euo pipefail

ENGINE_UID=10001
ENGINE_GID=10001

# Dynamic per-container cgroup to prevent collisions across multiple containers with --cgroupns=host
RAND_SUFFIX=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || date +%s%N)
ENGINE_CGROUP="${ENGINE_CGROUP:-/sys/fs/cgroup/code-editor-engine-${RAND_SUFFIX:0:8}}"

# Clean up cgroup scope when the container shuts down
cleanup() {
    rmdir "$ENGINE_CGROUP" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Provision the cgroup v2 subtree the engine manages.
# Requires: --privileged (or --cap-add SYS_ADMIN) + --cgroupns=host.
# If the host has not delegated controllers, the engine's startup probe
# matrix will fail closed — which is the intended behavior, not a bug.
# ---------------------------------------------------------------------------
if [ -w /sys/fs/cgroup/cgroup.controllers ]; then
    available=$(cat /sys/fs/cgroup/cgroup.controllers)
    # Enable controllers at parent/root level (suppress error if already enabled or restricted)
    for ctl in memory pids cpu io; do
        if echo " $available " | grep -q " $ctl "; then
            echo "+$ctl" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
        fi
    done

    mkdir -p "$ENGINE_CGROUP"

    # Enable controllers in engine's own subtree_control.
    # Must fail-closed without '|| true' so misconfigurations abort immediately!
    for ctl in memory pids cpu io; do
        if echo " $available " | grep -q " $ctl "; then
            echo "+$ctl" > "$ENGINE_CGROUP/cgroup.subtree_control"
        fi
    done

    chown -R "$ENGINE_UID:$ENGINE_GID" "$ENGINE_CGROUP"
    chmod 0755 "$ENGINE_CGROUP"
else
    echo "[entrypoint] /sys/fs/cgroup not writable; run with --privileged (or --cap-add SYS_ADMIN) --cgroupns=host" >&2
fi

export CGROUP_BASE="$ENGINE_CGROUP"
export JOBS_ROOT="${JOBS_ROOT:-/var/lib/code_editor_engine_jobs}"

# ---------------------------------------------------------------------------
# Drop privileges and exec the engine.
# ---------------------------------------------------------------------------
exec setpriv \
    --reuid="$ENGINE_UID" \
    --regid="$ENGINE_GID" \
    --init-groups \
    --no-new-privs \
    /usr/local/bin/code-editor-engine "$@"

