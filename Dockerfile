# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w" \
    -o /build/vaultwarden-api \
    ./cmd/api

# Runtime stage — pure Alpine, no Node.js
FROM alpine:3.23

RUN apk --no-cache add ca-certificates wget && \
    adduser -D -H appuser

WORKDIR /app
COPY --from=builder /build/vaultwarden-api .

USER appuser
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/vaultwarden-api"]
