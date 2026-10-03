# ============================================================================
# KISS Mail Server - Alpine
# ============================================================================
# Multi-stage build: a static-friendly Rust build on rust:alpine, then a
# minimal Alpine runtime running as an unprivileged user (uid 1000).
#
# Build: docker build -t kiss-mail .
# Run:   docker run -d -v kiss-mail-data:/data -p 25:2525 -p 143:1143 \
#          -p 110:1100 kiss-mail
# ============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM rust:1.94-alpine AS builder

WORKDIR /app

# Install build dependencies.
# All TLS is rustls-based (reqwest "rustls-tls", ldap3 "tls-rustls-ring"), so
# no OpenSSL headers/libraries are needed; ring only needs a C toolchain.
RUN apk add --no-cache \
    musl-dev \
    gcc

# Copy manifests
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

# Strip binary
RUN strip /app/target/release/kiss-mail

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM alpine:3.23 AS runtime

ARG VERSION=dev
ARG COMMIT=unknown

LABEL org.opencontainers.image.title="KISS Mail Server"
LABEL org.opencontainers.image.description="Simple SMTP, IMAP, POP3 email server"
LABEL org.opencontainers.image.source="https://github.com/quinnjr/kiss-mail"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.base.name="alpine:3.23"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    netcat-openbsd \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 kissmail && \
    adduser -D -u 1000 -G kissmail -s /sbin/nologin kissmail

# Copy binary
COPY --from=builder /app/target/release/kiss-mail /usr/local/bin/kiss-mail
RUN chmod +x /usr/local/bin/kiss-mail

# Create data directory
# The data directory must stay writable (mount a volume here)
RUN mkdir -p /data && chown kissmail:kissmail /data
WORKDIR /data

USER kissmail

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

EXPOSE 2525 1143 1100 8080 8025

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z localhost 2525 || exit 1

VOLUME ["/data"]

# The server shuts down gracefully on SIGTERM (Docker's default stop signal);
# stated explicitly so it is not lost if a base image changes it.
STOPSIGNAL SIGTERM

ENTRYPOINT ["kiss-mail"]
# No CMD: running kiss-mail without arguments starts the server.
# CLI example (password read from stdin, so it never appears in `ps` output):
#   printf '%s' "$NEW_PASSWORD" | docker exec -i kiss-mail kiss-mail passwd admin --stdin
