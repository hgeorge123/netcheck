# syntax=docker/dockerfile:1
# NetCheck API/controller + Cloudscape UI. Multi-stage, static binary,
# distroless non-root runtime. Multi-arch (amd64/arm64 for EKS Graviton):
#   docker buildx build --platform linux/amd64,linux/arm64 -t <ecr>/netcheck:<tag> --push .
# Pin base images by digest in CI (pending, see README).
ARG NODE_IMAGE=node:24-trixie-slim
ARG GO_IMAGE=golang:1.27.3-trixie
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot

# The web bundle is architecture independent: build it once natively.
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# Cross-compile Go natively for the target architecture (no emulation).
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
# Shown to administrators in System → Versions:
#   --build-arg VERSION=0.2.0 --build-arg COMMIT=$(git rev-parse --short HEAD) --build-arg BUILD_DATE=$(date -u +%FT%TZ)
ARG VERSION=dev
ARG COMMIT=""
ARG BUILD_DATE=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/netcheck ./cmd/netcheck

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/netcheck /netcheck
COPY --from=web /src/web/dist /app/web
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/netcheck"]
