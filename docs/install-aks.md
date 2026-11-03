# Installing NetCheck on Azure Kubernetes Service (AKS)

This guide installs NetCheck on AKS step by step. It complements [install.md](install.md), which explains each value
and the verification in detail; here you find what is specific to Azure: the network policy engine, Azure Disk storage,
the ways to expose NetCheck and the Azure platform addresses.

NetCheck needs no Azure identity: neither Managed Identity nor Workload Identity, for the application or for the
probes.

## Contents

1. [Requirements](#1-requirements)
2. [Check the cluster](#2-check-the-cluster)
3. [Network policy engine](#3-network-policy-engine)
4. [Storage](#4-storage)
5. [Exposure](#5-exposure)
6. [Values file](#6-values-file)
7. [Install and verify](#7-install-and-verify)
8. [AKS notes](#8-aks-notes)

## 1. Requirements

- AKS with Kubernetes **1.30 or later** (the admission policies of the chart need it).
- A **network policy engine** in the cluster (section 3): without it NetworkPolicies are not enforced and results
  would say nothing about them.
- `az` (Azure CLI), `kubectl` and Helm 3.14+ (or 4.x), with access to the cluster:

```bash
RG=<resource-group>
CLUSTER=<aks-cluster>
az aks get-credentials -g "$RG" -n "$CLUSTER"
kubectl get nodes
```

## 2. Check the cluster

```bash
az aks show -g "$RG" -n "$CLUSTER" --query "{version:kubernetesVersion, plugin:networkProfile.networkPlugin, \
pluginMode:networkProfile.networkPluginMode, policy:networkProfile.networkPolicy, dataplane:networkProfile.networkDataplane, \
podCidr:networkProfile.podCidr}" -o table
```

| Field | What you need |
|---|---|
| `version` | 1.30 or later |
| `policy` | `azure`, `calico` or `cilium`. Empty or `none`: see section 3 |
| `podCidr` | Note it: with an in-cluster Ingress controller or gateway it goes in `auth.trustedProxyCidrs` |

## 3. Network policy engine

AKS enforces NetworkPolicies only with an engine, chosen with `--network-policy`:

| Engine | How it is set | Notes |
|---|---|---|
| **Cilium** | `--network-dataplane cilium --network-policy cilium` (Azure CNI powered by Cilium) | Recommended for new clusters |
| **Calico** | `--network-policy calico` | Works with Azure CNI and kubenet |
| **Azure Network Policy Manager** | `--network-policy azure` | Azure CNI |

Whether an existing cluster can switch engines depends on its network plugin; check `az aks update --help` and the
Azure documentation for your case. Plan the change carefully on a production cluster: it affects every workload.

## 4. Storage

AKS installs the Azure Disk CSI driver with the `managed-csi` (Standard SSD) and `managed-csi-premium` (Premium SSD)
classes. NetCheck keeps its SQLite database on one `ReadWriteOnce` disk, so in the values:

```yaml
persistence:
  storageClassName: managed-csi
  createStorageClass:
    enabled: false        # the class the chart can create is for AWS EBS
```

A **locally redundant** disk (LRS, the default) lives in one zone, so the Pod can only run on nodes of that zone, as
with EBS on AWS. On regions with zones you can use a **zone-redundant** disk (ZRS), which any zone can attach:

```bash
kubectl apply -f - <<'EOF'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: netcheck-zrs
provisioner: disk.csi.azure.com
parameters:
  skuName: StandardSSD_ZRS
reclaimPolicy: Retain
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
EOF
```

and set `persistence.storageClassName: netcheck-zrs`.

## 5. Exposure

Choose one; HTTPS is mandatory in both (sign-in passwords travel through them).

**A. Gateway API (recommended).** Application Gateway for Containers, the Istio add-on with Gateway API, or any other
implementation. The chart creates an `HTTPRoute` attached to your Gateway's HTTPS listener:

```yaml
httpRoute:
  enabled: true
  hostnames: [netcheck.example.com]
  parentRefs:
    - name: <gateway-name>
      namespace: <gateway-namespace>
      sectionName: <https-listener-name>
```

**B. Ingress.** The application routing add-on (managed NGINX, IngressClass `webapprouting.kubernetes.azure.com`) or
any other controller, with the generic Ingress of the chart and a TLS Secret (yours, or one created by cert-manager):

```yaml
httpRoute:
  enabled: false
ingress:
  enabled: true
  provider: generic
  className: webapprouting.kubernetes.azure.com
  hosts: [netcheck.example.com]
  generic:
    tlsSecretName: netcheck-tls
```

```bash
kubectl -n netcheck create secret tls netcheck-tls --cert=netcheck.crt --key=netcheck.key
```

In both cases set `auth.trustedProxyCidrs` to the addresses NetCheck receives the requests from: the Pod CIDR of the
controller or gateway Pods (section 2), or the subnet of Application Gateway for Containers.

## 6. Values file

Start from the AKS example of the chart:

<!-- x-release-please-start-version -->
```bash
helm pull oci://ghcr.io/hgeorge123/charts/netcheck --version 1.0.2 --untar
cp netcheck/values-aks.example.yaml values-aks.yaml
```
<!-- x-release-please-end -->

Fill every `<...>`. Besides storage and exposure, the example already:

- turns off the EKS-only checks (`preflight.vpcCniNetworkPolicy` and `preflight.ebsCsiDriver`);
- excludes the AKS system namespaces as test sources (`gatekeeper-system`, `app-routing-system`, the Istio add-on
  namespaces) besides `kube-system`;
- denies `168.63.129.16`, the Azure platform address (section 8).

Everything else (destination policy, limits, retention, single sign-on with [sso.md](sso.md)) works as in
[install.md](install.md) §7.

## 7. Install and verify

```bash
NC_NS=netcheck
kubectl create namespace "$NC_NS"
kubectl label namespace "$NC_NS" pod-security.kubernetes.io/enforce=restricted
```

<!-- x-release-please-start-version -->
```bash
helm upgrade --install netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 1.0.2 \
  -n "$NC_NS" -f values-aks.yaml --dry-run=server > /dev/null && echo "VALIDATION OK"
helm upgrade --install netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 1.0.2 \
  -n "$NC_NS" -f values-aks.yaml --wait --timeout 10m
```
<!-- x-release-please-end -->

Then follow [install.md](install.md) from §10: verify the installation, sign in with the generated `admin` password
and run the smoke test.

## 8. AKS notes

- **Azure platform addresses.** `169.254.169.254` (instance metadata) is always denied by NetCheck. `168.63.129.16` is
  the Azure platform address (wireserver, Azure DNS, load balancer probes); the example denies it as a destination
  because testing it is never useful and it is part of the host platform.
- **Azure Policy / Gatekeeper.** If the cluster restricts image registries or requires labels, allow the NetCheck
  images (`docker.io/hgeorge123/netcheck` and `netcheck-probe`, or your mirror) and the probe Jobs that NetCheck creates
  in the source namespaces. A rejected Job shows as *Admission rejected* with Kubernetes' reason.
- **Private registries.** To use Azure Container Registry, import the release images keeping their digests
  (`az acr import --source docker.io/hgeorge123/netcheck:<version>`), check that the imported digests match the release
  notes, then set `image.repository` and `probeImage.repository` to your registry.
- **Private clusters.** NetCheck detects the API server address of the `kubernetes` Service. On a private cluster add
  the private endpoint address to `kubeApiServerCidrs` so tests can never target it.
- **Security groups.** Network Security Groups of the node subnet also apply to the probes, like to your Pods: a
  result reflects them too.
