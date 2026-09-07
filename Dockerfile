# syntax=docker/dockerfile:1.7
FROM golang:1.23-bookworm AS builder

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /crypto-bff \
    ./cmd/server

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /crypto-bff /crypto-bff

USER nonroot:nonroot

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --start-interval=5s --retries=3 \
    CMD ["/crypto-bff", "-health-check"]

ENTRYPOINT ["/crypto-bff"]
