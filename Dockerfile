# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
# CGO_ENABLED=0 for static binary (no C dependencies)
# -ldflags="-s -w" strips debug info to reduce binary size
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /build/vaultwarden-api \
    ./cmd/api

# Final stage - minimal runtime image
FROM node:24-alpine

# Install CA certificates and wget
RUN apk --no-cache add ca-certificates wget && \
    npm install -g @bitwarden/cli && \
    npm cache clean --force

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/vaultwarden-api .

# Change ownership to existing node user
RUN chown -R node:node /app

# Set Bitwarden CLI data directory to /tmp (writable)
ENV BITWARDENCLI_APPDATA_DIR=/tmp/.bitwarden

# Switch to non-root user
USER node

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["/app/vaultwarden-api"]
