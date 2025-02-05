# Build Stage
FROM golang:1.21-alpine3.18 AS builder
# v1.21-alpine3.18 - Secure base image for build stage

# Build arguments for version tracking
ARG VERSION
ARG BUILD_DATE
ARG GIT_COMMIT

# Set secure build environment
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GO111MODULE=on \
    GOSUMDB=off

# Install build dependencies
RUN apk add --no-cache \
    git=2.40.1-r0 \
    make=4.4.1-r1 \
    bash=5.2.15-r5

# Create non-root user for build
RUN addgroup -g 10001 blackpoint && \
    adduser -D -u 10001 -G blackpoint blackpoint

# Set up secure build directory
WORKDIR /app
RUN chown -R blackpoint:blackpoint /app

# Copy source code with proper permissions
COPY --chown=blackpoint:blackpoint . .

# Switch to non-root user for build
USER blackpoint

# Download and verify dependencies
RUN go mod download && \
    go mod verify

# Build optimized binary with security flags
RUN bash scripts/build.sh && \
    # Verify binary size (must be under 50MB)
    test $(stat -f %z bin/blackpoint-cli) -lt 52428800

# Runtime Stage
FROM alpine:3.18
# v3.18 - Minimal base image for runtime

# Runtime labels
LABEL maintainer="BlackPoint Security" \
      version=${VERSION} \
      build-date=${BUILD_DATE} \
      git-commit=${GIT_COMMIT} \
      component=cli \
      security.scan=required

# Create non-root user for runtime
RUN addgroup -g 10001 blackpoint && \
    adduser -D -u 10001 -G blackpoint blackpoint

# Install runtime security updates and dependencies
RUN apk upgrade --no-cache && \
    apk add --no-cache \
        ca-certificates=20230506-r0 \
        tzdata=2023c-r1

# Set up secure runtime environment
ENV PATH=/usr/local/bin:$PATH \
    HOME=/home/blackpoint

# Copy binary from builder with proper permissions
COPY --from=builder --chown=blackpoint:blackpoint /app/bin/blackpoint-cli /usr/local/bin/blackpoint-cli

# Security hardening
RUN chmod 755 /usr/local/bin/blackpoint-cli && \
    mkdir -p /home/blackpoint/.blackpoint && \
    chown -R blackpoint:blackpoint /home/blackpoint

# Switch to non-root user
USER blackpoint
WORKDIR /home/blackpoint

# Health check
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["/usr/local/bin/blackpoint-cli", "version"]

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/blackpoint-cli"]
CMD ["--help"]