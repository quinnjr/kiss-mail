# ============================================================================
# KISS Mail Server - Docker Hardened Images (Alpine)
# ============================================================================
# Uses Docker Hardened Images (DHI) for security-hardened, minimal containers
# https://www.docker.com/products/hardened-images/
#
# PREFERRED: Pull from registry instead of building:
#   docker pull ghcr.io/quinnjr/kiss-mail:latest
#
# Build locally (if needed):
#   docker build -t kiss-mail .
#
# Run:
#   docker run -d -p 25:2525 -p 143:1143 -p 110:1100 -p 8080:8080 \
#     -v kiss-mail-data:/data ghcr.io/quinnjr/kiss-mail:latest
#
# Security Features:
#   - Docker Hardened Images base (minimal, regularly patched)
#   - Alpine Linux (minimal attack surface)
#   - Non-root user (uid 1000)
#   - Pure-Rust TLS (rustls) - no OpenSSL in the build or the runtime image
#   - Compatible with a read-only root filesystem, PROVIDED /data is mounted
#     as a writable volume (all state is written to the data directory)
#   - Note: the runtime image still contains busybox (a shell) because it is
#     used by apk at build time and by the nc-based healthcheck
# ============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build (using DHI Rust Alpine dev image)
# -----------------------------------------------------------------------------
FROM dhi.io/rust:1.94-alpine3.23-dev AS builder

WORKDIR /app

# Install build dependencies.
# All TLS is rustls-based (reqwest "rustls-tls", ldap3 "tls-rustls-ring"), so
# no OpenSSL headers/libraries are needed; ring only needs a C toolchain.
RUN apk add --no-cache \
    musl-dev \
    gcc

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src to cache dependencies
RUN mkdir src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release --locked && rm -rf src target/release/deps/kiss_mail*

# Copy actual source
COPY src/ src/

# Build release binary
RUN cargo build --release --locked

# Strip binary for smaller size
RUN strip /app/target/release/kiss-mail

# -----------------------------------------------------------------------------
# Stage 2: Runtime (using DHI Alpine minimal image)
# -----------------------------------------------------------------------------
FROM dhi.io/alpine:3.23 AS runtime

ARG VERSION=dev
ARG COMMIT=unknown

# Labels
LABEL org.opencontainers.image.title="KISS Mail Server"
LABEL org.opencontainers.image.description="Simple SMTP, IMAP, POP3 email server - Hardened Container"
LABEL org.opencontainers.image.source="https://github.com/quinnjr/kiss-mail"
LABEL org.opencontainers.image.vendor="Joseph R. Quinn"
LABEL org.opencontainers.image.base.name="dhi.io/alpine:3.23"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"

# Install minimal runtime dependencies
# - ca-certificates: for TLS connections
# - libgcc: required by Rust binaries on Alpine
# - netcat-openbsd: for healthcheck (nc command)
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    netcat-openbsd \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 kissmail && \
    adduser -D -u 1000 -G kissmail -s /sbin/nologin kissmail

# Copy binary from builder
COPY --from=builder /app/target/release/kiss-mail /usr/local/bin/kiss-mail

# Ensure binary is executable
RUN chmod +x /usr/local/bin/kiss-mail

# Create data directory
# The data directory must stay writable (mount a volume here)
RUN mkdir -p /data && chown kissmail:kissmail /data
WORKDIR /data

# Switch to non-root user
USER kissmail

# Environment defaults
# KISS_MAIL_DATA_DIR (alias: KISS_MAIL_DATA) - where all state is stored
ENV KISS_MAIL_DATA_DIR=/data
ENV KISS_MAIL_DOMAIN=localhost
ENV KISS_MAIL_SMTP_PORT=2525
ENV KISS_MAIL_IMAP_PORT=1143
ENV KISS_MAIL_POP3_PORT=1100
ENV KISS_MAIL_WEB_PORT=8080
ENV KISS_MAIL_WEB_BIND=0.0.0.0
ENV KISS_MAIL_API_PORT=8025
ENV KISS_MAIL_API_BIND=0.0.0.0
ENV RUST_LOG=kiss_mail=info

# Expose ports
EXPOSE 2525 1143 1100 8080 8025

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z localhost 2525 || exit 1

# Data volume
VOLUME ["/data"]

# Entry point
# The server shuts down gracefully on SIGTERM (Docker's default stop signal);
# stated explicitly so it is not lost if a base image changes it.
STOPSIGNAL SIGTERM

ENTRYPOINT ["kiss-mail"]
# No CMD: running kiss-mail without arguments starts the server.
# CLI example (password read from stdin, so it never appears in `ps` output):
#   printf '%s' "$NEW_PASSWORD" | docker exec -i kiss-mail kiss-mail passwd admin --stdin
