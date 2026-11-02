# Installing NetCheck on Kubernetes

This guide installs NetCheck on any Kubernetes cluster, step by step, from the prerequisites to the first sign-in.
Each step says what to do, why, the exact commands and how to check that it worked.

- Running on **Amazon EKS**? Follow [install-eks.md](install-eks.md) instead: it covers the VPC CNI, EBS volumes,
  availability zones and the AWS Load Balancer Controller.
- Just want to try it? See [Try it locally with kind](#appendix-try-it-locally-with-kind) at the end.

## Contents

1. [How it works](#1-how-it-works)
2. [Requirements](#2-requirements)
3. [Check the cluster](#3-check-the-cluster)
4. [Choose the release](#4-choose-the-release)
5. [Create the namespace](#5-create-the-namespace)
6. [Choose how to expose NetCheck](#6-choose-how-to-expose-netcheck)
7. [Write your values file](#7-write-your-values-file)
8. [Validate against the cluster](#8-validate-against-the-cluster)
9. [Install](#9-install)
10. [Verify the installation](#10-verify-the-installation)
11. [First sign-in](#11-first-sign-in)
12. [Smoke test](#12-smoke-test)
13. [Upgrade, roll back and uninstall](#13-upgrade-roll-back-and-uninstall)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. How it works

NetCheck is **one Pod** (API, web interface and controller) with a SQLite database on a persistent volume. When a user
runs a test, NetCheck creates a short-lived **probe Job** in the source namespace the user picked. The probe measures
(DNS, TCP, UDP, HTTP/HTTPS, ping, traceroute), prints the result, and NetCheck reads it through the Kubernetes API and
deletes the Job.

Because the probe is a normal Pod in that namespace, it is subject to the **same NetworkPolicies** as your
applications. That is the whole point: you do not create any NetworkPolicy for NetCheck.

The chart creates the Deployment, Service, ConfigMap, initial admin Secret, PVC, a least-privilege ServiceAccount with
RBAC, two `ValidatingAdmissionPolicies` that restrict what the controller can create and, optionally, an `HTTPRoute`.
See [architecture.md](architecture.md) and [security.md](security.md) for the details.

## 2. Requirements

| Requirement | Why |
|---|---|
| Kubernetes **1.30 or later** | The chart uses `ValidatingAdmissionPolicy` v1 and refuses older versions |
| A CNI that **enforces NetworkPolicy** (Calico, Cilium, Antrea, Amazon VPC CNI with network policy enabled…) | Without enforcement every test "succeeds" and the results are meaningless. `kindnet` and Flannel alone do not enforce policies |
| **Linux** nodes | Probes are pinned to `kubernetes.io/os: linux` |
| A StorageClass with **ReadWriteOnce block storage** (local-path, Ceph RBD, cloud disks…) | SQLite needs a local file system; do not use NFS or other network file systems |
| Nodes able to pull from Docker Hub (or GHCR, or your mirror) | The images are published on Docker Hub and GitHub Container Registry |
| **Helm 3.14+** and **kubectl** on your workstation | Installation |
| Cluster administrator rights **during installation** | The chart creates cluster-scoped objects (ClusterRole, admission policies) |
| Optional: a **Gateway API** implementation with an HTTPS listener | To publish the web interface (step 6) |

Run the commands of this guide in a bash shell (Linux, macOS, WSL or Git Bash).

## 3. Check the cluster

```bash
kubectl config current-context          # must be the cluster you want
kubectl version                          # server 1.30 or later
kubectl get nodes -L kubernetes.io/os,kubernetes.io/arch
```

Images are published for `amd64` and `arm64`.

**Permissions.** Both commands must answer `yes`:

```bash
kubectl auth can-i create clusterroles
kubectl auth can-i create validatingadmissionpolicies.admissionregistration.k8s.io
```

**NetworkPolicy enforcement.** Find your CNI and make sure it enforces policies:

```bash
kubectl get pods -A -o wide | grep -Ei 'calico|cilium|antrea|aws-node|weave|kube-router'
```

If you are not sure, create a quick test: a namespace with a deny-all egress policy from which a Pod must fail to
connect. If it connects, your CNI does not enforce NetworkPolicy and you must fix that first.

**Storage.** Pick the StorageClass for the database:

```bash
kubectl get storageclass
```

Write down its name; it goes in `persistence.storageClassName`.

## 4. Choose the release

The Helm chart is published as an OCI artifact. Each chart version already points to the images of its release on
Docker Hub, **pinned by digest** (tags can be moved, digests cannot), so you do not set any image values: installing
a chart version installs exactly the images built for it.

The commands in this guide name the **latest release** explicitly (`--version`); the release pipeline updates them
with every new version, so the `main` branch always documents the latest release. Older versions are listed in the
[releases](https://github.com/hgeorge123/netcheck/releases) and in [CHANGELOG.md](../CHANGELOG.md).

<!-- x-release-please-start-version -->
```bash
helm show chart oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5
helm show values oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 > values.reference.yaml
```
<!-- x-release-please-end -->

`values.reference.yaml` documents every setting; its `image` and `probeImage` blocks show the repositories and
digests the chart will use.

| Image | Docker Hub (default) | GitHub Container Registry (same digests) |
|---|---|---|
| Application (API, UI and controller) | `docker.io/hgeorge123/netcheck` | `ghcr.io/hgeorge123/netcheck` |
| Probe (static Go binary, no shell) | `docker.io/hgeorge123/netcheck-probe` | `ghcr.io/hgeorge123/netcheck-probe` |

**GHCR, a private mirror or air-gapped clusters.** Keep the digests from `values.reference.yaml` and change only the
repositories. For a mirror, first copy both images by digest (for example with `crane copy` or `skopeo copy --all`)
and add `imagePullSecrets` if it needs credentials:

```yaml
image:
  repository: registry.example.com/netcheck
probeImage:
  repository: registry.example.com/netcheck-probe
```

**Building your own images.** From a checkout of the repository; then set `image.repository`/`image.digest` and
`probeImage.repository`/`probeImage.digest` to the images you pushed:

<!-- x-release-please-start-version -->
```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=0.2.5 --build-arg COMMIT="$(git rev-parse --short HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t registry.example.com/netcheck:0.2.5 --push .
docker buildx build --platform linux/amd64,linux/arm64 -f probe-image/Dockerfile \
  -t registry.example.com/netcheck-probe:0.2.5 --push .
```
<!-- x-release-please-end -->

## 5. Create the namespace

```bash
export NC_NS=netcheck
kubectl create namespace "$NC_NS"
kubectl label namespace "$NC_NS" pod-security.kubernetes.io/enforce=restricted
```

NetCheck runs under the Pod Security `restricted` profile. The chart can create the namespace instead
(`namespace.create: true`); in that case the release is stored in another namespace and `helm uninstall` also deletes
the NetCheck namespace.

Probes **never** run in the NetCheck namespace (unless an administrator enables it for a specific user) nor in
`kube-system`, `kube-public`, `kube-node-lease` or `default`.

## 6. Choose how to expose NetCheck

Sign-in passwords travel to NetCheck, so it must be served over **HTTPS**. Choose one option:

| Option | Values | When |
|---|---|---|
| **A. Gateway API `HTTPRoute`** (default) | `httpRoute.enabled: true` | You have a Gateway (NGINX Gateway Fabric, Envoy Gateway, Istio, Cilium…) with an HTTPS listener |
| **B. AWS ALB `Ingress`** | `httpRoute.enabled: false`, `ingress.enabled: true` | Amazon EKS with the AWS Load Balancer Controller: see [install-eks.md](install-eks.md) |
| **C. No exposure** | `httpRoute.enabled: false` | Evaluation only: reach it with `kubectl port-forward` |

For **option A**, collect the data of your Gateway:

```bash
kubectl get gateway -A
export GW_NAME=<gateway-name> GW_NS=<gateway-namespace>
# Listener names and protocols: note the NAME of the HTTPS listener
kubectl -n "$GW_NS" get gateway "$GW_NAME" \
  -o jsonpath='{range .spec.listeners[*]}{.name}{"  "}{.protocol}{"  "}{.hostname}{"\n"}{end}'
# Which namespaces may attach routes to it
kubectl -n "$GW_NS" get gateway "$GW_NAME" -o jsonpath='{.spec.listeners[?(@.protocol=="HTTPS")].allowedRoutes}'; echo
```

- If `allowedRoutes.namespaces.from` is `Same`, the Gateway will reject the route. Change it to `All`, or to `Selector`
  and label the NetCheck namespace accordingly.
- The listener certificate must cover the NetCheck host name (for example `netcheck.example.com`).
- You also need the **CIDR the Gateway data plane Pods use** (usually the cluster Pod CIDR). It goes in
  `auth.trustedProxyCidrs`, so NetCheck can see the real client IP for sign-in throttling.

## 7. Write your values file

Start from the generic example:

<!-- x-release-please-start-version -->
```bash
helm pull oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 --untar
cp netcheck/values-generic.example.yaml values.yaml
```
<!-- x-release-please-end -->

Fill every `<...>`:

| Value | Example | Notes |
|---|---|---|
| `clusterId` | `prod-eu-1` | Free text shown in the interface |
| `auth.trustedProxyCidrs` | `[10.244.0.0/16]` | CIDR of the Gateway data plane Pods (option A) |
| `namespaceScope.mode` | `all` | `all`: every namespace, including future ones (ClusterRole). `list`: only `namespaceScope.namespaces` (one Role per namespace, no cluster-wide rights) |
| `namespaceScope.exclude` | `[calico-system, nginx-gateway]` | Platform namespaces nobody may test from. Enforced by the admission policy too. More can be added later in the web |
| `persistence.storageClassName` | `standard` | Step 3 |
| `httpRoute.hostnames` / `httpRoute.parentRefs` | `[netcheck.example.com]` / your Gateway and HTTPS listener | Step 6 |
| `preflight.vpcCniNetworkPolicy` / `preflight.ebsCsiDriver` | `false` | These checks only make sense on EKS |

Settings you usually keep:

- **Destinations:** any name, IP and port can be tested by default. The cloud metadata service, the Kubernetes API
  server, loopback and link-local addresses are always denied (`protectPlatformDestinations: true`). After installation
  administrators can restrict destinations in **Administration → Destination policy** without redeploying.
- **Initial admin password:** `admin` / `NetCheck-ChangeMe-1`, which must be changed at first sign-in. To set your own
  without storing it in the values file, create a Secret and reference it:

  ```bash
  kubectl -n "$NC_NS" create secret generic netcheck-initial-admin --from-literal=password='<a-long-password>'
  ```

  ```yaml
  auth:
    bootstrapAdmin:
      existingSecret: netcheck-initial-admin
  ```

- **Limits:** 7 checks per test, 10 s per check, 90 s per Job, 3 concurrent Jobs per namespace and 10 in total.
- **Retention:** test output 15 days, test history and audit 45 days. These are initial values: administrators change
  them later in **Administration → Data retention**.
- **Sessions:** 60 min idle, 12 h maximum, 15 min lockout after 5 failed attempts.
- **`probe.settleSeconds`:** 3 s wait so the CNI applies policies to the new probe Pod before measuring (step 12).

Keep `values.yaml` in your configuration repository. It holds no secrets if you use `existingSecret`.

## 8. Validate against the cluster

<!-- x-release-please-start-version -->
```bash
helm upgrade --install netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 \
  -n "$NC_NS" -f values.yaml --dry-run=server > /tmp/netcheck-render.yaml && echo OK
```
<!-- x-release-please-end -->

The chart validates the values and queries the cluster. It stops with a clear message when something is wrong, for
example:

| Message | Fix |
|---|---|
| `image.digest (sha256:...) is required in production` | You changed `image.repository` to your own build: set its digest too (step 4) |
| `preflight: StorageClass <name> not found` | Step 3 |
| `preflight: Gateway <ns>/<name> not found` | `httpRoute.parentRefs` (step 6) |
| `the cluster has no Gateway API` | Install the Gateway API CRDs, or use option C |
| `auth.trustedProxyCidrs is required with httpRoute` | Step 6 |
| `httpRoute.enabled and ingress.enabled are mutually exclusive` | Choose one option |
| `namespace kube-system is not allowed as probe source` | Remove system namespaces from `namespaceScope` |
| `preflight: DaemonSet kube-system/aws-node not found` | Not EKS: set `preflight.vpcCniNetworkPolicy: false` |

## 9. Install

<!-- x-release-please-start-version -->
```bash
helm upgrade --install netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 \
  -n "$NC_NS" -f values.yaml --wait --timeout 10m
```
<!-- x-release-please-end -->

## 10. Verify the installation

```bash
kubectl -n "$NC_NS" get pods,pvc,svc,httproute
kubectl -n "$NC_NS" logs deploy/netcheck | head -20

# Option A: the Gateway accepted the route (Accepted=True, ResolvedRefs=True)
kubectl -n "$NC_NS" get httproute netcheck \
  -o jsonpath='{range .status.parents[*].conditions[*]}{.type}={.status} {.reason}{"\n"}{end}'

# Admission policies are in place
kubectl get validatingadmissionpolicy | grep netcheck

# The controller can NOT create Pods, read Secrets or change RBAC (expected: no, no, no)
for v in "create pods" "list secrets" "create clusterrolebindings"; do
  echo -n "$v: "; kubectl auth can-i $v -A --as=system:serviceaccount:$NC_NS:netcheck-controller
done

# The chart created no NetworkPolicy (expected: No resources found)
kubectl -n "$NC_NS" get networkpolicy
```

**DNS (option A).** Point the NetCheck host name to your Gateway address
(`kubectl -n "$GW_NS" get gateway "$GW_NAME" -o jsonpath='{.status.addresses[*].value}'`) and check:

```bash
curl -sI https://netcheck.example.com/ | head -1      # HTTP/2 200
```

**Option C.** Forward the port and open `http://localhost:8080`:

```bash
kubectl -n "$NC_NS" port-forward svc/netcheck 8080:8080
```

## 11. First sign-in

| User | Initial password |
|---|---|
| `admin` | `NetCheck-ChangeMe-1`, or the one in `auth.bootstrapAdmin.password` / `existingSecret` |

```bash
kubectl -n "$NC_NS" get secret netcheck-bootstrap-admin -o jsonpath='{.data.password}' | base64 -d; echo
```

1. Open NetCheck **right after installing**. Until the password is changed, anyone who can reach the URL and knows the
   default could sign in.
2. The interface is in English; choose **Español** in the **Language** selector if you prefer Spanish.
3. Sign in as `admin`. NetCheck **forces a password change** (at least 12 characters) before anything else.
4. Open **Administration → System and versions**: it must show the version and the image digests of the chart.
5. Create the users ([admin guide](admin-guide.md), Part II).

The Secret password only creates the first administrator. Afterwards it is no longer valid, but the Secret is kept for
emergency recovery ([admin guide](admin-guide.md), Part III §5).

## 12. Smoke test

1. **Allowed vs. blocked.** Pick two namespaces and one service: one namespace whose NetworkPolicies allow egress to
   it and one that denies it. Run a **TCP connection** test to the service port from both: *Succeeded* in the first,
   *Timed out* in the second. If both succeed, your CNI is not enforcing the policy.
2. **ICMP.** Run **Ping** to a Pod IP from a namespace without policies: it must get replies. If you get "ICMP is not
   permitted inside the probe", see [troubleshooting](#14-troubleshooting).
3. **Calibrate `settleSeconds`.** Repeat the blocked test several times with `--set probe.settleSeconds=0`. If any run
   succeeds, the probe measured before the CNI applied the policy: go back to 3–5 s.
4. **Restart.** `kubectl -n "$NC_NS" rollout restart deploy/netcheck` and check that the history is still there.

## 13. Upgrade, roll back and uninstall

<!-- x-release-please-start-version -->
```bash
# Upgrade: the new chart version brings the digests of its images
helm upgrade netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 -n "$NC_NS" -f values.yaml \
  --wait --timeout 10m

# History and rollback
helm history netcheck -n "$NC_NS"
helm rollback netcheck <REVISION> -n "$NC_NS" --wait

# Uninstall (the PVC and the admin Secret are kept on purpose)
helm uninstall netcheck -n "$NC_NS"
```
<!-- x-release-please-end -->

- Always pass `-f values.yaml` (or `--reset-then-reuse-values`). Do **not** use `--reuse-values`: it skips new chart
  defaults and the templates may fail.
- Database migrations run automatically at startup.
- Read [CHANGELOG.md](../CHANGELOG.md) before upgrading.

To delete everything, including data, see the [admin guide](admin-guide.md), Part III §7.

## 14. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| PVC `Pending` | Wrong or missing StorageClass, or the provisioner is not running | `kubectl -n $NC_NS describe pvc netcheck-data` |
| `ImagePullBackOff` | Nodes cannot reach Docker Hub (or your mirror), Docker Hub rate limits, or a wrong digest | Check egress to the registry, or use a mirror (step 4) |
| `CrashLoopBackOff` | Invalid configuration | `kubectl -n $NC_NS logs deploy/netcheck --previous` names the wrong value |
| HTTPRoute `Accepted=False` | `allowedRoutes` does not admit the namespace, or wrong `sectionName` | Step 6 |
| Every test "succeeds", even from namespaces with deny policies | The CNI does not enforce NetworkPolicy | Step 2 |
| Every test ends in "Infrastructure error" | No access to the API server, quota or Pod Security in the source namespace | Pod logs; `kubectl -n <ns> describe job` |
| "ICMP is not permitted inside the probe" | An admission controller (Kyverno, Gatekeeper) blocks the safe sysctl `net.ipv4.ping_group_range` | Allow that sysctl for Pods labelled `app.kubernetes.io/part-of=netcheck,app.kubernetes.io/component=probe` |
| Ping gets no reply but TCP works | ICMP filtered by policies or firewalls | Expected |
| "Not allowed by the NetCheck destination policy" | Protected destination or a restricted policy | The message gives the exact reason; see **Administration → Destination policy** |
| Many `429` at sign-in | `auth.trustedProxyCidrs` does not cover the Gateway Pods, so every user shares one IP | Step 6 |

More in the [admin guide](admin-guide.md), Part III §8.

---

## Appendix: try it locally with kind

The repository includes a laboratory that creates a local [kind](https://kind.sigs.k8s.io/) cluster with Calico
(which enforces NetworkPolicies), a local registry and sample namespaces with policies:

```bash
git clone https://github.com/hgeorge123/netcheck.git && cd netcheck
bash test/integration/lab.sh up        # kind cluster + Calico + sample namespaces
bash test/integration/lab.sh deploy    # builds the images and installs the chart
kubectl --context kind-netcheck-lab -n netcheck port-forward svc/netcheck 8080:8080
```

Open `http://localhost:8080` and sign in as `admin` / `NetCheck-ChangeMe-1` (the lab does not force the password
change). Try a TCP test to `echo.nc-target.svc.cluster.local` port `8080` from `nc-allow` (succeeds) and from
`nc-deny` (times out). Remove everything with `bash test/integration/lab.sh down`.

Requirements: Docker, kind, kubectl and Helm. See [test/integration/README.md](../test/integration/README.md).
