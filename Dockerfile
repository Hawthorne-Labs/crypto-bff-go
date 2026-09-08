# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm AS builder
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOPROXY=https://proxy.golang.org,direct

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/crypto-bff ./cmd/server

FROM --platform=$TARGETPLATFORM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /out/crypto-bff /usr/local/bin/crypto-bff

EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/crypto-bff"]
