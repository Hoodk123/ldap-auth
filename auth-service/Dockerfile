FROM golang:1.24-alpine AS builder

# Install git and ca-certificates needed for go mod download
RUN apk add --no-cache git ca-certificates tzdata

# Built non-root user for the final image 
RUN adduser -D -g '' appuser

WORKDIR /build

# Copy dependency files first — Docker layer caching
# If go.mod and go.sum don't change, this layer is reused
# and go mod download is skipped on rebuilds — faster builds
COPY go.mod go.sum ./

RUN go mod download

RUN go mod verify

COPY . .

# Build the binary
# CGO_ENABLED=0  — pure Go binary, no C dependencies
# GOOS=linux     — target Linux (our container OS)
# -ldflags       — strip debug info to reduce binary size
# -a             — force rebuild of all packages
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a \
    -o auth-service \
    .

# ────────────────────────────────────────
# Stage 2 — Final image (minimal)
# ────────────────────────────────────────
FROM scratch

# Import from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd

# Copy only the compiled binary — nothing else
COPY --from=builder /build/auth-service /auth-service

# Run as non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check — Docker will mark container unhealthy if this fails
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/auth-service", "-health"] || exit 1

ENTRYPOINT ["/auth-service"]

