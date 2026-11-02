SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c

GO ?= go
# Explicit package list: web/node_modules may contain third-party Go code.
GO_PKGS := ./cmd/... ./internal/...
NPM ?= npm
HELM ?= helm
REGISTRY ?= localhost:5001
TAG ?= dev
# Build metadata shown on the System page (version = chart appVersion).
VERSION ?= $(shell awk -F'"' '/^appVersion:/ {print $$2}' chart/netcheck/Chart.yaml)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_ARGS = --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: fmt lint test build test-integration docker-build helm-lint run-local lab-up lab-gateway lab-deploy lab-down web-install docs-screenshots

fmt:
	gofmt -w cmd internal test
	cd web && npx eslint . --fix

lint:
	test -z "$$(gofmt -l cmd internal test)" || (gofmt -l cmd internal test; exit 1)
	$(GO) vet $(GO_PKGS)
	$(GO) vet -tags integration ./test/integration/...
	cd web && $(NPM) run lint && $(NPM) run typecheck

web-install:
	cd web && $(NPM) ci

test:
	$(GO) test -race $(GO_PKGS)
	cd web && $(NPM) run test

build: web-install
	cd web && $(NPM) run build
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/netcheck ./cmd/netcheck
	CGO_ENABLED=0 GOOS=linux $(GO) build -trimpath -o bin/probe-linux ./cmd/probe

# Requires a laboratory cluster prepared with `make lab-up` and the probe
# image digest exported as NETCHECK_PROBE_IMAGE.
test-integration:
	$(GO) test -tags integration -count=1 -v -timeout 15m ./test/integration/...

docker-build:
	docker build $(BUILD_ARGS) -t $(REGISTRY)/netcheck:$(TAG) .
	docker build -f probe-image/Dockerfile -t $(REGISTRY)/netcheck-probe:$(TAG) .

helm-lint:
	HELM=$(HELM) GO=$(GO) chart/check.sh

run-local:
	mkdir -p .data
	cd web && $(NPM) run build
	@test -n "$${NETCHECK_BOOTSTRAP_ADMIN_PASSWORD:-}" || (echo "export NETCHECK_BOOTSTRAP_ADMIN_PASSWORD (>= 12 chars) first"; exit 1)
	NETCHECK_ENV=development $(GO) run ./cmd/netcheck -config dev/config.dev.yaml

# UI walkthrough against the lab Gateway (lab.sh gateway + deploy and a
# port-forward of the Gateway to 8443). Regenerates docs/images/*.png.
docs-screenshots:
	cd web && NETCHECK_ADMIN_PASSWORD="$${NETCHECK_ADMIN_PASSWORD:-$$(kubectl --context kind-netcheck-lab -n netcheck get secret netcheck-bootstrap-admin \
	  -o jsonpath='{.data.password}' | base64 -d)}" npx playwright test

# Local kind + Calico laboratory. These targets create local Docker
# containers and download pinned images and manifests.
lab-up:
	test/integration/lab.sh up

lab-gateway:
	test/integration/lab.sh gateway

lab-deploy:
	test/integration/lab.sh deploy

lab-down:
	test/integration/lab.sh down
