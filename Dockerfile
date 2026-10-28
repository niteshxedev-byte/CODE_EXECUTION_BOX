# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Stage 1: build the engine
# ---------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
# Warm the dependency cache independently of source changes
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src
COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked \
    && cp target/release/CodeEditorENGINE target/release/code-editor-engine

# ---------------------------------------------------------------------------
# Stage 2: build bubblewrap 0.12.0 from source
# Fedora 41/42/43 ship 0.11.0, which still supports setuid builds. The engine
# refuses setuid bwrap at runtime, but 0.12.0 removes the class structurally.
# ---------------------------------------------------------------------------
FROM fedora:43 AS bwrap-builder
RUN dnf -y install --setopt=install_weak_deps=False \
        git meson ninja-build gcc pkgconfig \
        libcap-devel libselinux-devel libseccomp-devel \
    && dnf clean all && rm -rf /var/cache/dnf
RUN git clone --depth 1 --branch v0.12.0 \
        https://github.com/containers/bubblewrap.git /src
WORKDIR /src
RUN meson setup builddir --prefix=/usr -Dman=disabled -Dselinux=disabled \
    && ninja -C builddir \
    && DESTDIR=/out ninja -C builddir install

# ---------------------------------------------------------------------------
# Stage 3: runtime
# ---------------------------------------------------------------------------
FROM fedora:43 AS runtime

# --- 7 runtimes + sandbox runtime deps -------------------------------------
RUN dnf -y install --setopt=install_weak_deps=False \
        python3 \
        nodejs \
        gcc gcc-c++ make \
        bash \
        java-21-openjdk-headless \
        rust cargo \
        libseccomp \
        glibc glibc-common \
        util-linux \
        curl \
        ca-certificates \
    && dnf clean all && rm -rf /var/cache/dnf

# --- bubblewrap 0.12.0 from source -----------------------------------------
COPY --from=bwrap-builder /out/usr/bin/bwrap /usr/bin/bwrap
RUN chmod 0755 /usr/bin/bwrap \
    && test -z "$(find /usr/bin/bwrap -perm /4000 -print -quit)" \
    && test -z "$(find /usr/bin/bwrap -perm /0022 -print -quit)" \
    && bwrap --version

# --- Unprivileged engine user ----------------------------------------------
# bwrap creates its own user namespace per invocation; it is deliberately
# NOT setuid and the engine deliberately does NOT run as root.
# Workspace root is separated from /tmp so that /tmp can remain mounted noexec
# while the jobs root maintains execution privileges for compiled artifacts.
RUN groupadd --gid 10001 engine \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /sbin/nologin engine \
    && mkdir -p /var/lib/code_editor_engine_jobs \
    && chown 10001:10001 /var/lib/code_editor_engine_jobs \
    && chmod 0700 /var/lib/code_editor_engine_jobs

# --- Engine binary + verification harness ----------------------------------
COPY --from=builder /build/target/release/code-editor-engine /usr/local/bin/code-editor-engine
COPY tests/ /app/tests/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh \
            /usr/local/bin/code-editor-engine

WORKDIR /app
EXPOSE 3000
LABEL traefik.enable="true"
LABEL traefik.http.services.code-editor-engine.loadbalancer.server.port="3000"

# Runs healthcheck unprivileged as engine user (uid 10001) without elevated root caps
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD setpriv --reuid=10001 --regid=10001 --init-groups --no-new-privs curl -fsS http://127.0.0.1:3000/health >/dev/null || exit 1

# Entrypoint runs as root only to provision the cgroup subtree, then drops
# to uid 10001 before exec'ing the engine.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
