# syntax=docker/dockerfile:1
# Probe image: a single static Go binary, no shell, no network tools, no
# package manager. Build from the repository root (multi-arch for EKS):
#   docker buildx build --platform linux/amd64,linux/arm64 -f probe-image/Dockerfile -t <ecr>/netcheck-probe:<tag> --push .
# Deploy it ONLY by digest (the chart and the admission policy require it).
ARG GO_IMAGE=golang:1.27-bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/probe/ cmd/probe/
COPY internal/probes/ internal/probes/
COPY internal/diagnostics/ internal/diagnostics/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/probe ./cmd/probe

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/probe /probe
USER 65532:65532
ENTRYPOINT ["/probe"]
