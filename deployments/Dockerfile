# Multi-stage build for the IAM server. Three stages:
FROM node:22-alpine AS web-build

WORKDIR /src/web

COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS server-build

RUN apk add --no-cache git

WORKDIR /src

COPY go.mod ./
COPY go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY --from=web-build /src/web/dist ./web/dist
COPY . .

# we need to check versions release?
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/iam-server \
        ./cmd/server

# we could want to seed the db with some admin
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/seed-user \
        ./cmd/seed-user

# one-shot migration runner, the discrete alternative to AUTO_MIGRATE=true
# for multi-replica deployments (see cmd/migrate)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/migrate \
        ./cmd/migrate

# audit_log retention: drops old monthly partitions
# deliberately never run by iam-server itself (see cmd/audit-prune)
# shipped so an operator can run it manually against the container's own image
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/audit-prune \
        ./cmd/audit-prune

FROM alpine:3.20 AS final

LABEL org.opencontainers.image.title="iam-server" \
      org.opencontainers.image.description="OpenID Connect provider + CAS server with MFA and federation" \
      org.opencontainers.image.source="https://github.com/lusopoint/lusoiam" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN adduser -D -u 65532 nonroot

COPY --from=server-build --chown=nonroot:nonroot /out/iam-server /iam-server
COPY --from=server-build --chown=nonroot:nonroot /out/seed-user /seed-user
COPY --from=server-build --chown=nonroot:nonroot /out/migrate /migrate
COPY --from=server-build --chown=nonroot:nonroot /out/audit-prune /audit-prune
COPY --chown=nonroot:nonroot deployments/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
USER nonroot

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O- --tries=1 http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/entrypoint.sh"]
