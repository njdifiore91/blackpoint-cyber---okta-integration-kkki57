# Build stage
FROM golang:1.21-alpine3.18 AS builder

# Security: Set build arguments and environment variables
ARG SERVICE
ARG VERSION
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOSUMDB=sum.golang.org \
    GOPROXY=https://proxy.golang.org,direct

# Verify build arguments
RUN test -n "$SERVICE" || (echo "SERVICE build arg not set" && false) && \
    test -n "$VERSION" || (echo "VERSION build arg not set" && false) && \
    echo $SERVICE | grep -E '^(analyzer|collector|normalizer)$' || (echo "Invalid SERVICE specified" && false)

WORKDIR /app

# Install security tools and build dependencies
RUN apk add --no-cache \
    ca-certificates=20230506-r0 \
    tzdata=2023c-r1 \
    git=2.40.1-r0 \
    gcc=12.2.1_git20220924-r10 \
    musl-dev=1.2.4-r1 \
    && update-ca-certificates

# Copy and verify go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download && \
    go mod verify

# Copy source code with appropriate permissions
COPY . .
RUN chmod -R 755 /app

# Security: Run static code analysis
RUN go vet ./... && \
    go test -v ./...

# Build optimized binary with security flags
RUN go build -trimpath -ldflags="-s -w -X main.Version=${VERSION} -extldflags=-static" \
    -o /app/bin/${SERVICE} ./cmd/${SERVICE} && \
    chmod 755 /app/bin/${SERVICE}

# Verify binary size constraints
RUN size=$(wc -c < /app/bin/${SERVICE}) && \
    case ${SERVICE} in \
        "analyzer") max=52428800 ;; \
        "collector") max=78643200 ;; \
        "normalizer") max=104857600 ;; \
    esac && \
    test $size -le $max || (echo "Binary size exceeds limit" && false)

# Final stage
FROM alpine:3.18

# Security: Set runtime environment variables
ENV TZ=UTC \
    PATH=/app/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Install minimal runtime dependencies and security patches
RUN apk add --no-cache \
    ca-certificates=20230506-r0 \
    tzdata=2023c-r1 \
    && update-ca-certificates \
    && rm -rf /var/cache/apk/*

# Security: Create non-root user
RUN addgroup -g 10001 -S blackpoint && \
    adduser -u 10001 -S blackpoint -G blackpoint

# Set up working directory with proper permissions
WORKDIR /app
RUN chown -R blackpoint:blackpoint /app && \
    chmod 755 /app

# Copy binary from builder stage
COPY --from=builder --chown=blackpoint:blackpoint /app/bin/${SERVICE} /app/bin/

# Security: Configure container security options
RUN chmod 755 /app/bin/${SERVICE}

# Switch to non-root user
USER blackpoint

# Configure health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/app/bin/${SERVICE}", "health"] || exit 1

# Security: Set security options
STOPSIGNAL SIGTERM

# Set resource limits
LABEL org.opencontainers.image.source="https://github.com/blackpoint/backend" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="BlackPoint Security" \
      org.opencontainers.image.title="${SERVICE}" \
      org.opencontainers.image.description="BlackPoint Security ${SERVICE} service"

# Run the service
ENTRYPOINT ["/app/bin/${SERVICE}"]
CMD ["serve"]