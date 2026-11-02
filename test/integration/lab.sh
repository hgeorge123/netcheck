#!/usr/bin/env bash
# Local NetCheck laboratory: kind + Calico (enforces NetworkPolicy) + local
# registry. Creates LOCAL resources only and downloads pinned images and the
# Calico manifest. Never point it at a shared or production cluster.
#
#   lab.sh up       create registry + kind cluster + Calico + fixtures
#   lab.sh deploy   build/push images, install the chart by digest
#   lab.sh down     delete the kind cluster and the registry container
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLUSTER=netcheck-lab
CONTEXT="kind-${CLUSTER}"
REGISTRY_NAME=kind-registry
REGISTRY_PORT=5001
# Versions pinned for reproducibility, verified 2026-10-21 with kind v0.33.0
# (node image = that release's default, pinned by digest). Node images must
# match the installed kind release; bump both together.
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}"
CALICO_VERSION="${CALICO_VERSION:-v3.33.0}"
# NGINX Gateway Fabric release older than two weeks at verification time.
NGF_VERSION="${NGF_VERSION:-v2.7.2}"
TAG="${TAG:-lab}"

kc() { kubectl --context "${CONTEXT}" "$@"; }

up() {
  if [ "$(docker inspect -f '{{.State.Running}}' "${REGISTRY_NAME}" 2>/dev/null || true)" != "true" ]; then
    docker run -d --restart=always -p "127.0.0.1:${REGISTRY_PORT}:5000" --network bridge --name "${REGISTRY_NAME}" registry:2
  fi
  kind create cluster --image "${KIND_NODE_IMAGE}" --config "${ROOT}/test/integration/kind/kind-config.yaml"
  for node in $(kind get nodes --name "${CLUSTER}"); do
    docker exec "${node}" mkdir -p "/etc/containerd/certs.d/localhost:${REGISTRY_PORT}"
    printf '[host."http://%s:5000"]\n' "${REGISTRY_NAME}" | docker exec -i "${node}" cp /dev/stdin "/etc/containerd/certs.d/localhost:${REGISTRY_PORT}/hosts.toml"
  done
  docker network connect kind "${REGISTRY_NAME}" 2>/dev/null || true

  kc apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
  kc -n kube-system rollout status daemonset/calico-node --timeout=300s
  kc -n kube-system rollout status deployment/calico-kube-controllers --timeout=300s
  kc wait --for=condition=Ready nodes --all --timeout=300s

  kc apply -f "${ROOT}/test/integration/manifests/lab.yaml"
  kc -n nc-target rollout status deployment/echo --timeout=180s
  echo "Lab ready. Next: $0 deploy"
}

digest_of() {
  docker push "$1" >/dev/null
  docker inspect --format='{{index .RepoDigests 0}}' "$1"
}

deploy() {
  local app="localhost:${REGISTRY_PORT}/netcheck:${TAG}" probe="localhost:${REGISTRY_PORT}/netcheck-probe:${TAG}"
  local version
  version="$(awk -F'"' '/^appVersion:/ {print $2}' "${ROOT}/chart/netcheck/Chart.yaml")"
  docker build --build-arg VERSION="${version}" --build-arg COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || true)" \
    --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" -t "${app}" "${ROOT}"
  docker build -f "${ROOT}/probe-image/Dockerfile" -t "${probe}" "${ROOT}"
  local app_ref probe_ref
  app_ref="$(digest_of "${app}")"
  probe_ref="$(digest_of "${probe}")"

  # Expose through the lab Gateway when `lab.sh gateway` was run.
  local overlay=()
  if kc -n gateway-lab get gateway lab-gateway >/dev/null 2>&1; then
    overlay=(-f "${ROOT}/test/integration/values-kind-gateway.yaml")
  fi

  kc create namespace netcheck --dry-run=client -o yaml | kc apply -f -
  kc label namespace netcheck pod-security.kubernetes.io/enforce=restricted --overwrite
  helm --kube-context "${CONTEXT}" upgrade --install netcheck "${ROOT}/chart/netcheck" \
    --namespace netcheck \
    -f "${ROOT}/test/integration/values-kind.yaml" "${overlay[@]}" \
    --set image.repository="${app_ref%@*}" --set image.digest="${app_ref#*@}" \
    --set probeImage.repository="${probe_ref%@*}" --set probeImage.digest="${probe_ref#*@}" \
    --wait --timeout 5m

  echo "export NETCHECK_PROBE_IMAGE=${probe_ref}"
  echo "Access (lab only): kubectl --context ${CONTEXT} -n netcheck port-forward svc/netcheck 8080:8080"
}

# NGINX Gateway Fabric + an HTTPS Gateway in its own namespace, mirroring the
# EKS setup (the Gateway is managed outside the NetCheck chart).
gateway() {
  kc kustomize "https://github.com/nginx/nginx-gateway-fabric/config/crd/gateway-api/standard?ref=${NGF_VERSION}" | kc apply -f -
  helm --kube-context "${CONTEXT}" upgrade --install ngf oci://ghcr.io/nginx/charts/nginx-gateway-fabric \
    --version "${NGF_VERSION#v}" --namespace nginx-gateway --create-namespace \
    --set nginx.service.type=ClusterIP --wait --timeout 5m

  local tmp
  tmp="$(mktemp -d)"
  # On Git Bash (Windows) MSYS_NO_PATHCONV stops "/CN=..." being rewritten as
  # a path, so file paths are converted explicitly with cygpath.
  local ftmp="${tmp}"
  command -v cygpath >/dev/null && ftmp="$(cygpath -m "${tmp}")"
  MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=netcheck.lab.test" \
    -addext "subjectAltName=DNS:netcheck.lab.test" -keyout "${ftmp}/tls.key" -out "${ftmp}/tls.crt" 2>/dev/null
  kc create namespace gateway-lab --dry-run=client -o yaml | kc apply -f -
  kc -n gateway-lab create secret tls lab-tls --cert="${tmp}/tls.crt" --key="${tmp}/tls.key" --dry-run=client -o yaml | kc apply -f -
  cp "${tmp}/tls.crt" "${ROOT}/.data/lab-gateway-ca.crt" 2>/dev/null || true
  rm -rf "${tmp}"
  kc apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: lab-gateway
  namespace: gateway-lab
spec:
  gatewayClassName: nginx
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      hostname: netcheck.lab.test
      tls:
        mode: Terminate
        certificateRefs:
          - name: lab-tls
      allowedRoutes:
        namespaces:
          from: All
EOF
  kc -n gateway-lab wait --for=condition=Programmed gateway/lab-gateway --timeout=180s
  echo "Gateway ready. Re-run: $0 deploy (adds the HTTPRoute)."
  echo "Access: kubectl --context ${CONTEXT} -n gateway-lab port-forward svc/lab-gateway-nginx 8443:443"
  echo "        then https://netcheck.lab.test:8443 (map netcheck.lab.test to 127.0.0.1)"
}

down() {
  kind delete cluster --name "${CLUSTER}" || true
  docker rm -f "${REGISTRY_NAME}" 2>/dev/null || true
}

case "${1:-}" in
  up) up ;;
  gateway) gateway ;;
  deploy) deploy ;;
  down) down ;;
  *) echo "usage: $0 up|gateway|deploy|down" >&2; exit 2 ;;
esac
