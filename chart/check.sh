#!/usr/bin/env bash
# Chart checks run by `make helm-lint`: lint, render, unsafe or incomplete
# combinations that must fail (with the expected reason) and
# chart/config-loader sync.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHART="${ROOT}/chart/netcheck"
HELM="${HELM:-helm}"
GO="${GO:-go}"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

EKS=(-f "${CHART}/ci/eks-values.yaml")
# helm template has no cluster: declare the Gateway API that EKS would have.
GW=(--api-versions gateway.networking.k8s.io/v1/HTTPRoute)
failures=0

# helm lint cannot declare extra API versions: lint without the route (the
# route is covered by the template renders below).
"${HELM}" lint --strict "${CHART}" "${EKS[@]}" --set httpRoute.enabled=false
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${GW[@]}" > "${TMP}/eks.yaml"
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${GW[@]}" --set namespaceScope.mode=list \
  --set 'namespaceScope.namespaces={payments,orders}' --set 'namespaceScope.exclude=null' > "${TMP}/list.yaml"
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${GW[@]}" --set image.tag=0.2.2 --set probeImage.tag=0.2.2 > "${TMP}/tagged.yaml"

expect() {
  local name="$1" file="$2" pattern="$3"
  if grep -qE -- "${pattern}" "${file}"; then echo "PASS  ${name}"; else echo "FAIL  ${name}"; failures=$((failures + 1)); fi
}
expect_not() {
  local name="$1" file="$2" pattern="$3"
  if grep -qE -- "${pattern}" "${file}"; then echo "FAIL  ${name}"; failures=$((failures + 1)); else echo "PASS  ${name}"; fi
}
expect "all mode renders a ClusterRole" "${TMP}/eks.yaml" '^kind: ClusterRole$'
expect "all mode can create probe ServiceAccounts" "${TMP}/eks.yaml" 'resources: \["serviceaccounts"\]'
if grep -A1 -F 'resources: ["resourcequotas", "limitranges"]' "${TMP}/eks.yaml" | grep -qF 'verbs: ["list"]'; then
  echo "PASS  quotas and limit ranges are read-only"
else
  echo "FAIL  quotas and limit ranges are read-only"; failures=$((failures + 1))
fi
expect "HTTPRoute attaches to the HTTPS listener" "${TMP}/eks.yaml" 'sectionName: https'
expect "gp3 encrypted StorageClass" "${TMP}/eks.yaml" 'provisioner: ebs.csi.aws.com'
expect "bootstrap admin Secret" "${TMP}/eks.yaml" 'name: netcheck-bootstrap-admin'
expect "VAP excludes system namespaces (incl. default)" "${TMP}/eks.yaml" '"kube-system","kube-public","kube-node-lease","default","amazon-cloudwatch"'
expect "VAP allows only the ping sysctl" "${TMP}/eks.yaml" 'net.ipv4.ping_group_range'
expect_not "no NetworkPolicy by default" "${TMP}/eks.yaml" '^kind: NetworkPolicy'
expect_not "no Namespace by default" "${TMP}/eks.yaml" '^kind: Namespace'
# Initial admin password: random on a new install (helm template has no
# existing Secret to keep), the chosen one if set, no Secret with existingSecret.
expect "random 24-character admin password" "${TMP}/eks.yaml" '^  password: [A-Za-z0-9+/]{32}$'
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${GW[@]}" > "${TMP}/eks2.yaml"
if [ "$(grep -E '^  password: ' "${TMP}/eks.yaml")" != "$(grep -E '^  password: ' "${TMP}/eks2.yaml")" ]; then
  echo "PASS  admin password differs per install"
else
  echo "FAIL  admin password differs per install"; failures=$((failures + 1))
fi
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${GW[@]}" --set auth.bootstrapAdmin.password=My-Initial-Password-1 > "${TMP}/pw.yaml"
expect "chosen admin password in Secret" "${TMP}/pw.yaml" "password: $(printf My-Initial-Password-1 | base64)"
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${GW[@]}" --set auth.bootstrapAdmin.existingSecret=my-admin > "${TMP}/existing.yaml"
expect_not "no bootstrap Secret with existingSecret" "${TMP}/existing.yaml" 'name: netcheck-bootstrap-admin'
expect "Deployment reads existingSecret" "${TMP}/existing.yaml" 'name: my-admin'
expect "version env for System page" "${TMP}/eks.yaml" 'name: NETCHECK_CHART_VERSION'
expect "ServiceAccount admission policy" "${TMP}/eks.yaml" 'name: netcheck-probe-serviceaccounts'
expect "images pinned by digest" "${TMP}/eks.yaml" 'netcheck@sha256:1111'
expect "release tag shown next to the digest" "${TMP}/tagged.yaml" 'image: "?[^ ]*/netcheck:0.2.2@sha256:1111'
expect "admission policy pins the tagged probe reference" "${TMP}/tagged.yaml" 'netcheck-probe:0.2.2@sha256:2222.*)'
expect_not "list mode has no ClusterRole" "${TMP}/list.yaml" '^kind: ClusterRole'
expect "list mode creates namespaced Roles" "${TMP}/list.yaml" '^kind: Role$'
expect "list mode includes the NetCheck namespace" "${TMP}/list.yaml" 'namespace: netcheck'
"${HELM}" template netcheck "${CHART}" --namespace default "${EKS[@]}" "${GW[@]}" --set namespace.create=true --set namespace.name=netcheck-sys > "${TMP}/ns.yaml"
expect "namespace.create renders the Namespace" "${TMP}/ns.yaml" '^kind: Namespace'
expect "resources go to namespace.name" "${TMP}/ns.yaml" 'namespace: netcheck-sys'
expect "controller identity follows namespace.name" "${TMP}/ns.yaml" 'system:serviceaccount:netcheck-sys:netcheck-controller'
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${GW[@]}" --set 'persistence.createStorageClass.zones={eu-west-1a}' > "${TMP}/zone.yaml"
expect "gp3 volume pinned to the chosen AZ" "${TMP}/zone.yaml" 'values: \["eu-west-1a"\]'
expect_not "no AZ restriction by default" "${TMP}/eks.yaml" '^allowedTopologies'
# Exposure alternative: AWS Load Balancer Controller Ingress (no Gateway API needed).
ALB=(--set httpRoute.enabled=false --set ingress.enabled=true --set 'ingress.hosts={netcheck.example.com}'
     --set 'ingress.alb.certificateArns={arn:aws:acm:eu-west-1:123456789012:certificate/abc}')
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${ALB[@]}" > "${TMP}/alb.yaml"
expect "ALB mode renders an Ingress for the alb class" "${TMP}/alb.yaml" 'ingressClassName: alb'
expect "ALB terminates HTTPS with the ACM certificate" "${TMP}/alb.yaml" 'certificate-arn: "arn:aws:acm:'
expect "ALB targets Pod IPs" "${TMP}/alb.yaml" 'target-type: "ip"'
expect "ALB is internal by default" "${TMP}/alb.yaml" 'scheme: "internal"'
expect "ALB health check uses /healthz" "${TMP}/alb.yaml" 'healthcheck-path: "/healthz"'
expect_not "ALB mode has no HTTPRoute" "${TMP}/alb.yaml" '^kind: HTTPRoute'
expect_not "HTTPRoute mode has no Ingress" "${TMP}/eks.yaml" '^kind: Ingress'
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${ALB[@]}" --set networkPolicy.enabled=true \
  --set 'networkPolicy.apiServer.cidrs[0]=10.0.0.0/20' --set 'networkPolicy.loadBalancerCidrs[0]=10.0.64.0/20' > "${TMP}/alb-np.yaml"
expect "opt-in NetworkPolicy admits only the ALB subnets" "${TMP}/alb-np.yaml" 'cidr: 10.0.64.0/20'
"${HELM}" template netcheck "${CHART}" --namespace netcheck "${EKS[@]}" "${GW[@]}" --set networkPolicy.enabled=true --set 'networkPolicy.apiServer.cidrs[0]=10.0.0.0/20' > "${TMP}/np.yaml"
expect "opt-in NetworkPolicy admits only the Gateway namespace" "${TMP}/np.yaml" 'kubernetes.io/metadata.name: nginx-gateway'

must_fail() {
  local name="$1" expect="$2" out
  shift 2
  if out="$("${HELM}" template netcheck "${CHART}" --namespace netcheck "$@" 2>&1)"; then
    echo "FAIL  ${name}: rendered but must be refused"; failures=$((failures + 1))
  elif ! grep -qF -- "${expect}" <<<"${out}"; then
    echo "FAIL  ${name}: refused for an unexpected reason: ${out}"; failures=$((failures + 1))
  else
    echo "PASS  ${name}"
  fi
}

must_fail "chart defaults without an image digest" "image.digest (sha256:...) is required in production" "${GW[@]}" --set image.digest=
must_fail "empty image repository" "image.repository is required" "${EKS[@]}" "${GW[@]}" --set image.repository=
must_fail "invalid environment" "environment must be development or production" "${EKS[@]}" "${GW[@]}" --set environment=staging
must_fail "production image without digest" "image.digest (sha256:...) is required in production" "${EKS[@]}" "${GW[@]}" --set image.digest= --set image.tag=latest
must_fail "invalid image tag" "image.tag must be a lowercase image tag" "${EKS[@]}" "${GW[@]}" --set image.tag=Latest
must_fail "probe image by tag" "probeImage.digest must be a sha256" "${EKS[@]}" "${GW[@]}" --set probeImage.digest=latest
must_fail "insecure cookie in production" "cookieSecure=false is only allowed in development" "${EKS[@]}" "${GW[@]}" --set auth.cookieSecure=false
must_fail "no forced password change in production" "forcePasswordChange=false is only allowed in development" "${EKS[@]}" "${GW[@]}" --set auth.bootstrapAdmin.forcePasswordChange=false
must_fail "bad log level" "logLevel must be debug, info, warn or error" "${EKS[@]}" "${GW[@]}" --set logLevel=verbose
must_fail "bad namespace mode" "namespaceScope.mode must be all or list" "${EKS[@]}" "${GW[@]}" --set namespaceScope.mode=everything
must_fail "list mode without namespaces" "at least one namespace in list mode" "${EKS[@]}" "${GW[@]}" --set namespaceScope.mode=list
must_fail "kube-system as source" "kube-system is not allowed" "${EKS[@]}" "${GW[@]}" --set namespaceScope.mode=list --set 'namespaceScope.namespaces={kube-system}'
must_fail "default as source" "default is not allowed" "${EKS[@]}" "${GW[@]}" --set namespaceScope.mode=list --set 'namespaceScope.namespaces={default}'
must_fail "release namespace as source" "netcheck is not allowed" "${EKS[@]}" "${GW[@]}" --set namespaceScope.mode=list --set 'namespaceScope.namespaces={netcheck}'
must_fail "empty destination allowlist" "destinations.allowCidrs is empty" "${EKS[@]}" "${GW[@]}" --set 'destinations.allowCidrs=null'
must_fail "empty port allowlist" "destinations.allowPorts is empty" "${EKS[@]}" "${GW[@]}" --set 'destinations.allowPorts=null'
must_fail "netpol without API server" "apiServer.cidrs is required" "${EKS[@]}" "${GW[@]}" --set networkPolicy.enabled=true
must_fail "no storage" "persistence.storageClassName" "${EKS[@]}" "${GW[@]}" --set persistence.createStorageClass.enabled=false
must_fail "route without hostnames" "httpRoute.hostnames is required" "${EKS[@]}" "${GW[@]}" --set 'httpRoute.hostnames=null'
must_fail "route without HTTPS listener" "needs name and sectionName" "${EKS[@]}" "${GW[@]}" --set 'httpRoute.parentRefs[0].sectionName='
must_fail "route without trusted proxies" "auth.trustedProxyCidrs is required" "${EKS[@]}" "${GW[@]}" --set 'auth.trustedProxyCidrs=null'
must_fail "cluster without Gateway API" "the cluster has no Gateway API" "${EKS[@]}"
must_fail "HTTPRoute and Ingress together" "mutually exclusive" "${EKS[@]}" "${GW[@]}" "${ALB[@]}" --set httpRoute.enabled=true
must_fail "ALB without certificate" "ingress.alb.certificateArns is required" "${EKS[@]}" "${ALB[@]}" --set 'ingress.alb.certificateArns=null'
must_fail "ALB certificate that is not an ARN" "is not an ACM certificate ARN" "${EKS[@]}" "${ALB[@]}" --set 'ingress.alb.certificateArns={my-cert}'
must_fail "ALB without hosts" "ingress.hosts is required" "${EKS[@]}" "${ALB[@]}" --set 'ingress.hosts=null'
must_fail "ALB with unknown scheme" "must be internal or internet-facing" "${EKS[@]}" "${ALB[@]}" --set ingress.alb.scheme=public
must_fail "ALB without trusted proxies" "auth.trustedProxyCidrs is required with ingress" "${EKS[@]}" "${ALB[@]}" --set 'auth.trustedProxyCidrs=null'
must_fail "ALB netpol without LB subnets" "networkPolicy.loadBalancerCidrs is required" "${EKS[@]}" "${ALB[@]}" --set networkPolicy.enabled=true --set 'networkPolicy.apiServer.cidrs[0]=10.0.0.0/20'

# The rendered config must be accepted by the strict Go loader.
for values in eks list kind; do
  case "${values}" in
    eks) extra=("${EKS[@]}" "${GW[@]}") ;;
    list) extra=("${EKS[@]}" "${GW[@]}" --set namespaceScope.mode=list --set 'namespaceScope.namespaces={payments}' --set 'namespaceScope.exclude=null') ;;
    kind) extra=(-f "${ROOT}/test/integration/values-kind.yaml" --set image.repository=localhost:5001/netcheck --set image.tag=lab
          --set probeImage.repository=localhost:5001/netcheck-probe --set "probeImage.digest=sha256:$(printf '0%.0s' {1..64})") ;;
  esac
  "${HELM}" template netcheck "${CHART}" --namespace netcheck "${extra[@]}" --show-only templates/configmap.yaml > "${TMP}/cm-${values}.yaml"
  cm="${TMP}/cm-${values}.yaml"
  command -v cygpath > /dev/null && cm="$(cygpath -w "${cm}")"
  (cd "${ROOT}" && NETCHECK_RENDERED_CONFIGMAP="${cm}" "${GO}" test -count=1 -run TestChartRenderedConfig ./internal/config/ > /dev/null) \
    && echo "PASS  rendered config (${values}) accepted by loader" \
    || { echo "FAIL  rendered config (${values})"; failures=$((failures + 1)); }
done

# Chart defaults (used by the lab values): open destinations, protections on.
expect "default destinations allow any IPv4/IPv6" "${TMP}/cm-kind.yaml" '0\.0\.0\.0/0'
expect "default destinations allow any hostname" "${TMP}/cm-kind.yaml" "allowHostnameSuffixes:.*\\*|- '\\*'|- \"\\*\""
expect "default destinations allow every port" "${TMP}/cm-kind.yaml" 'to: 65535'
expect "metadata/API server protections on by default" "${TMP}/cm-kind.yaml" 'protectPlatformDestinations: true'
expect "destination policy managed in the web by default" "${TMP}/cm-kind.yaml" 'destinationsManagedBy: "ui"'
must_fail "unknown policy manager" "destinationsManagedBy must be ui" "${EKS[@]}" "${GW[@]}" --set destinationsManagedBy=git

[ "${failures}" -eq 0 ] || { echo "${failures} chart check(s) failed"; exit 1; }
echo "All chart checks passed."
