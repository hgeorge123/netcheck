# Installing NetCheck on Amazon EKS

For other Kubernetes distributions follow [install.md](install.md).

This guide installs NetCheck on an **Amazon EKS** cluster step by step, from an empty workstation to the first
sign-in. Each step says **what you do**, **why**, **the exact command** and **how to check** it worked. Do not skip the
checks: they catch most problems.

> **Before you start:** try NetCheck on your own machine with the local laboratory (`test/integration/lab.sh`, see
> appendix A). You will know the UI and the workflow before touching the cluster.

## Contents

0. Architecture overview
1. Tools on your workstation
2. Required permissions (AWS IAM and Kubernetes)
3. Working variables and cluster access
4. Check the cluster (version, nodes, zones)
5. Enable Network Policy in Amazon VPC CNI
6. EBS CSI driver and its IAM role
7. Storage: gp3, Availability Zones and Pod rescheduling
8. Exposure: NGINX Gateway Fabric or AWS Load Balancer Controller (ALB)
9. VPC network data
10. Container images: Docker Hub or an ECR mirror
11. Image digests
12. NetCheck namespace
13. The `values-eks.yaml` file
14. Validate with `--dry-run=server`
15. Install
16. Verify the installation
17. DNS
18. First sign-in (default user and password)
19. Smoke test and calibration
20. IAM roles summary
21. Upgrade, roll back and uninstall
22. Troubleshooting
- Appendix A. Local laboratory
- Appendix B. Final checklist

---

## 0. Architecture overview

NetCheck is **a single Pod** (API, web UI and controller) with its **SQLite database on a gp3 EBS volume**. Each test
creates an **ephemeral Job** (the *probe*) in the source namespace chosen by the user; when it finishes, NetCheck reads
the result through the Kubernetes API server and deletes the Job.

```
Browser ──HTTPS──► Gateway (NGINX Gateway Fabric, yours) ──HTTPRoute──┐
        └─HTTPS──► ALB (AWS Load Balancer Controller) ──Ingress──────┴──► Service netcheck ──► Pod netcheck
                                                                                │ SQLite on EBS gp3
                                                                                ▼
                                                              Probe Job in the source namespace
```

What the chart **does** create: Deployment, Service, HTTPRoute **or** Ingress (you choose one, step 8), ConfigMap, initial admin Secret, PVC, encrypted gp3
StorageClass, controller ServiceAccount (no IAM role), minimal RBAC, two ValidatingAdmissionPolicies and, if requested,
the namespace. What it does **not** create: any NetworkPolicy (unless you enable the optional one), any IAM role, the
Gateway, the ALB (created by the AWS Load Balancer Controller) or the certificate.

**NetworkPolicies in source namespaces: not needed.** The probe egresses with the policies the namespace already has
(exactly what is being measured), accepts no connections, and its result is read through the API server. Full details
in the [admin guide](admin-guide.md), Part I §1.1.

## 1. Tools on your workstation

| Tool | Version | Install (Windows with winget) | Check |
|---|---|---|---|
| AWS CLI | v2 | `winget install Amazon.AWSCLI` | `aws --version` |
| kubectl | ±1 minor version of the cluster | `winget install Kubernetes.kubectl` | `kubectl version --client` |
| Helm | 3.14+ or 4.x | `winget install Helm.Helm` | `helm version` |
| Docker with Buildx (to read digests or mirror images) | 24+ | `winget install Docker.DockerDesktop` | `docker buildx version` |
| Git | any | `winget install Git.Git` | `git --version` |

On macOS use Homebrew (`brew install awscli kubectl helm git` plus Docker Desktop). Run the commands of this guide in a
**bash** terminal (Linux, macOS, WSL or Git Bash on Windows).

## 2. Required permissions

### 2.1 AWS (IAM) for the installer

| Service | Actions | Why |
|---|---|---|
| STS | `sts:GetCallerIdentity` | Find the account |
| EKS | `eks:DescribeCluster`, `eks:DescribeAddon`, `eks:CreateAddon`, `eks:UpdateAddon`, `eks:ListPodIdentityAssociations` | Inspect the cluster and add-ons |
| ECR (only for an ECR mirror, step 10) | `ecr:CreateRepository`, `ecr:GetAuthorizationToken`, `ecr:BatchCheckLayerAvailability`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:PutImage`, `ecr:BatchGetImage`, `ecr:DescribeImages`, `ecr:DescribeImageScanFindings` | Repositories and images |
| EC2 | `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeVolumes`, `ec2:DescribeAvailabilityZones` | Network and volume data |
| IAM (only if you install the EBS CSI driver or the AWS Load Balancer Controller) | `iam:CreateRole`, `iam:CreatePolicy`, `iam:AttachRolePolicy`, `iam:PassRole`, `eks:CreatePodIdentityAssociation` | Driver and controller roles |
| ACM (ALB option) | `acm:ListCertificates`, `acm:DescribeCertificate`, `acm:RequestCertificate` | ALB certificate |

### 2.2 Kubernetes

Cluster administrator permissions **during installation** (`cluster-admin` through EKS access entries or `aws-auth`).
The chart creates cluster-scoped objects: `ClusterRole`, `ClusterRoleBinding`, `ValidatingAdmissionPolicy`,
`StorageClass` and, optionally, `Namespace`. After installation NetCheck runs with its own least-privilege
ServiceAccount.

Check:

```bash
kubectl auth can-i create clusterrole
kubectl auth can-i create validatingadmissionpolicies.admissionregistration.k8s.io
# Both must answer: yes
```

## 3. Working variables and cluster access

```bash
export AWS_REGION=eu-west-1                 # cluster region
export CLUSTER_NAME=my-cluster              # EKS cluster name
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ECR=${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com   # only for an ECR mirror
export NC_NS=netcheck                       # NetCheck namespace

aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION"
kubectl config current-context              # must show YOUR cluster ARN
kubectl get nodes
```

**Check** that `current-context` is the right cluster before continuing: every later command acts on it. If you open
another terminal, define the variables again.

## 4. Check the cluster

```bash
# 4.1 Kubernetes version: 1.30 or later (ValidatingAdmissionPolicy v1)
aws eks describe-cluster --name "$CLUSTER_NAME" --query cluster.version --output text

# 4.2 Nodes: OS, architecture, zone and compute type
kubectl get nodes -L kubernetes.io/os,kubernetes.io/arch,topology.kubernetes.io/zone,eks.amazonaws.com/compute-type
```

| Requirement | Why | If not met |
|---|---|---|
| Kubernetes ≥ 1.30 | The chart uses `ValidatingAdmissionPolicy` v1 and refuses older versions | Upgrade the cluster |
| **EC2 Linux** nodes | VPC CNI does not enforce NetworkPolicies on Fargate or Windows; probes are pinned to `kubernetes.io/os: linux` | Add a Linux node group |
| Nodes in the zone(s) where the volume will live | EBS volumes are zonal (step 7) | Adjust node groups |

Write down the **architectures** (images are built for `amd64` and `arm64`) and the **zones** that have nodes (`ZONE`
column). If a namespace is bound to a **Fargate profile**, tests from it would run without NetworkPolicies: exclude it
(`namespaceScope.exclude`).

## 5. Enable Network Policy in Amazon VPC CNI

Without it **no NetworkPolicy in the cluster is enforced** and NetCheck results would be misleading. The chart checks
this and refuses to install when it is disabled.

> **Warning:** if the cluster already has `NetworkPolicy` objects that are **not** enforced today, enabling this feature
> starts enforcing them cluster-wide. Review `kubectl get networkpolicy -A` with the affected teams first.

```bash
# 5.1 Add-on version (Network Policy needs v1.14 or later)
aws eks describe-addon --cluster-name "$CLUSTER_NAME" --addon-name vpc-cni \
  --query 'addon.{version:addonVersion,config:configurationValues}' --output table

# 5.2 Enabled? --enable-network-policy=true must appear
kubectl -n kube-system get daemonset aws-node -o yaml | grep -- '--enable-network-policy'
```

If `--enable-network-policy=true` is missing:

```bash
aws eks update-addon --cluster-name "$CLUSTER_NAME" --addon-name vpc-cni \
  --resolve-conflicts PRESERVE --configuration-values '{"enableNetworkPolicy": "true"}'
aws eks wait addon-active --cluster-name "$CLUSTER_NAME" --addon-name vpc-cni
kubectl -n kube-system rollout status daemonset aws-node
kubectl -n kube-system get daemonset aws-node -o yaml | grep -- '--enable-network-policy=true'
```

- If you already had `configurationValues`, **merge** `"enableNetworkPolicy": "true"` into your JSON; do not replace it.
- If VPC CNI was installed with Helm: `helm upgrade --set enableNetworkPolicy=true aws-vpc-cni -n kube-system eks/aws-vpc-cni`.

**Enforcement mode.** In the default (*standard*) mode a new Pod starts as "allow all" until its policies are applied.
Probes are new Pods, so NetCheck waits `probe.settleSeconds` (3 s) before measuring. *Strict* mode removes that window but
changes the behaviour of the **whole** cluster; it is a platform decision.

## 6. EBS CSI driver and its IAM role

```bash
aws eks describe-addon --cluster-name "$CLUSTER_NAME" --addon-name aws-ebs-csi-driver \
  --query addon.status --output text 2>/dev/null || echo "NOT INSTALLED"
kubectl get csidriver ebs.csi.aws.com
```

If it answers `ACTIVE` and the `csidriver` exists, go to step 7. Otherwise install it with **EKS Pod Identity**:

```bash
# 6.1 Pod Identity agent
aws eks create-addon --cluster-name "$CLUSTER_NAME" --addon-name eks-pod-identity-agent || true
aws eks wait addon-active --cluster-name "$CLUSTER_NAME" --addon-name eks-pod-identity-agent

# 6.2 Driver IAM role (trust: only the Pod Identity service)
cat > ebs-csi-trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "pods.eks.amazonaws.com"},
    "Action": ["sts:AssumeRole", "sts:TagSession"]
  }]
}
EOF
aws iam create-role --role-name "${CLUSTER_NAME}-ebs-csi" \
  --assume-role-policy-document file://ebs-csi-trust.json
aws iam attach-role-policy --role-name "${CLUSTER_NAME}-ebs-csi" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy

# 6.3 Add-on bound to the role
aws eks create-addon --cluster-name "$CLUSTER_NAME" --addon-name aws-ebs-csi-driver \
  --pod-identity-associations "serviceAccount=ebs-csi-controller-sa,roleArn=arn:aws:iam::${AWS_ACCOUNT_ID}:role/${CLUSTER_NAME}-ebs-csi"
aws eks wait addon-active --cluster-name "$CLUSTER_NAME" --addon-name aws-ebs-csi-driver
kubectl get csidriver ebs.csi.aws.com
kubectl -n kube-system get pods -l app.kubernetes.io/name=aws-ebs-csi-driver
```

If you encrypt with your **own KMS key** (`persistence.createStorageClass.kmsKeyId`), grant the role `kms:CreateGrant`,
`kms:Decrypt`, `kms:DescribeKey`, `kms:Encrypt`, `kms:GenerateDataKey*` and `kms:ReEncrypt*` on that key.

## 7. Storage: gp3, Availability Zones and Pod rescheduling

### 7.1 How it works

- An **EBS (gp3) volume lives in a single Availability Zone** and can only attach to nodes in that zone. There is no EBS
  volume that "jumps" between zones.
- The chart StorageClass uses `volumeBindingMode: WaitForFirstConsumer`: the volume is created **in the zone of the node
  where the Pod first starts**.
- Once created, the PersistentVolume carries *node affinity* to that zone. From then on, **every time the Pod is deleted
  or rescheduled (restart, upgrade, node drain), the Kubernetes scheduler automatically places it on a node in that same
  zone**. Nothing else to do… as long as there are nodes in that zone.
- The Deployment uses the `Recreate` strategy: the old Pod releases the volume before the new one starts, so two Pods
  never fight over the same EBS volume.

### 7.2 What you must guarantee

| Situation | What happens | What to do |
|---|---|---|
| Nodes exist in the volume's zone | The Pod starts there again | Nothing |
| No free nodes in that zone | The Pod stays `Pending` (`volume node affinity conflict`) | Keep capacity in that zone: one node group per zone, or one that includes it |
| Cluster Autoscaler | Only adds nodes in the right zone when the node group is **single-zone** | Use per-zone node groups and `--balance-similar-node-groups` |
| Karpenter | Takes the volume's zone into account when launching nodes | Make sure the `NodePool` allows that zone |
| The whole zone fails | The volume is unavailable until the zone recovers | Restore from a snapshot in another zone (7.4) |

### 7.3 Recommendation: pin the zone

For predictable placement, choose **one zone that has nodes** and pin it in `values-eks.yaml`:

```yaml
persistence:
  createStorageClass:
    zones: [eu-west-1a]     # zone where the EBS volume is created
```

The chart adds `allowedTopologies` to the StorageClass. Check that the zone has Linux nodes:

```bash
kubectl get nodes -l topology.kubernetes.io/zone=eu-west-1a,kubernetes.io/os=linux
```

> This only affects **new** volumes. An existing volume never changes zone (see 7.4).

### 7.4 Need another zone? Snapshot and restore

No gp3 setup changes zone automatically. To move NetCheck (or recover from a zone outage):

```bash
# 1. Current volume and its zone
PV=$(kubectl -n "$NC_NS" get pvc netcheck-data -o jsonpath='{.spec.volumeName}')
VOL=$(kubectl get pv "$PV" -o jsonpath='{.spec.csi.volumeHandle}')
aws ec2 describe-volumes --volume-ids "$VOL" --query 'Volumes[0].AvailabilityZone' --output text

# 2. Cold (consistent) snapshot
kubectl -n "$NC_NS" scale deploy/netcheck --replicas=0
SNAP=$(aws ec2 create-snapshot --volume-id "$VOL" --description netcheck --query SnapshotId --output text)
aws ec2 wait snapshot-completed --snapshot-ids "$SNAP"

# 3. New volume in the target zone
NEWVOL=$(aws ec2 create-volume --snapshot-id "$SNAP" --availability-zone eu-west-1b --volume-type gp3 \
  --encrypted --query VolumeId --output text)
```

Then create a static PV/PVC pointing to `$NEWVOL` (with `nodeAffinity` to the new zone) and deploy with
`--set persistence.existingClaim=<pvc>`. For disaster recovery schedule snapshots with **AWS Backup** or **Data
Lifecycle Manager** ([admin guide](admin-guide.md), Part III).

### 7.5 Why not EFS (multi-AZ)?

Amazon EFS is multi-AZ, but SQLite on network file systems (NFS) is not reliable: locking and WAL durability depend on
the file system, and the SQLite documentation advises against it. NetCheck is a single-replica diagnostic tool; **EBS
gp3 + pinned zone + snapshots** is the supported combination. Real high availability would need a managed database
(out of scope for this version).

## 8. Exposure: NGINX Gateway Fabric or AWS Load Balancer Controller

NetCheck is published in **one** of two ways (the chart refuses both at the same time):

| | Option A — NGINX Gateway Fabric | Option B — AWS Load Balancer Controller (ALB) |
|---|---|---|
| Resource created by the chart | `HTTPRoute` on your existing Gateway | `Ingress` of class `alb` (the controller creates an ALB) |
| TLS | Certificate of the Gateway HTTPS listener | **ACM** certificate on the ALB |
| Values | `httpRoute.enabled: true` (default) | `httpRoute.enabled: false` + `ingress.enabled: true` |
| `auth.trustedProxyCidrs` | Gateway Pod CIDR (usually the VPC) | ALB subnet CIDRs (usually the VPC) |

Only follow the subsection of the option you choose.

### 8A. Option A — NGINX Gateway Fabric

You manage the Gateway; NetCheck only creates the **HTTPRoute**.

```bash
# 8A.1 Gateway API installed
kubectl get crd httproutes.gateway.networking.k8s.io

# 8A.2 Your Gateways
kubectl get gateway -A
export GW_NAME=<gateway-name>
export GW_NS=<gateway-namespace>

# 8A.3 Listeners: note the NAME of the HTTPS listener
kubectl -n "$GW_NS" get gateway "$GW_NAME" \
  -o jsonpath='{range .spec.listeners[*]}{.name}{"  "}{.protocol}{"  "}{.hostname}{"\n"}{end}'

# 8A.4 allowedRoutes of the HTTPS listener
kubectl -n "$GW_NS" get gateway "$GW_NAME" -o jsonpath='{.spec.listeners[?(@.protocol=="HTTPS")].allowedRoutes}'; echo

# 8A.5 Load balancer address (for DNS, step 17)
kubectl -n "$GW_NS" get gateway "$GW_NAME" -o jsonpath='{.status.addresses[*].value}'; echo
```

- `allowedRoutes.namespaces.from: Same` → the Gateway **rejects** the route. Change it to `All` or `Selector`; with
  `Selector`, add the expected label to the NetCheck namespace (step 12).
- The HTTPS listener **certificate** must cover the NetCheck DNS name (e.g. `netcheck.example.com`).
- Passwords travel through this route: **HTTPS only**.

### 8B. Option B — AWS Load Balancer Controller (ALB)

The chart creates an `Ingress` with `ingressClassName: alb`. The AWS Load Balancer Controller creates an **Application
Load Balancer** with an HTTPS:443 listener (ACM certificate), an HTTP:80 listener that only redirects to HTTPS, and an
**ip** target group pointing straight at the NetCheck Pod IP (health check on `/healthz`).

**8B.1 Check the controller.**

```bash
kubectl get deployment -n kube-system aws-load-balancer-controller
kubectl get ingressclass alb -o jsonpath='{.spec.controller}'; echo     # must be ingress.k8s.aws/alb
```

If it is missing, install it (with its IAM role through Pod Identity):

```bash
# Official controller IAM policy (download the one of the version you install)
export ALB_CTRL_VERSION=<v2.x.y>            # version approved by your team
curl -fsSLo alb-iam-policy.json \
  https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/${ALB_CTRL_VERSION}/docs/install/iam_policy.json
aws iam create-policy --policy-name "${CLUSTER_NAME}-alb-controller" --policy-document file://alb-iam-policy.json

# Role trusted by EKS Pod Identity (same ebs-csi-trust.json as step 6.2)
aws iam create-role --role-name "${CLUSTER_NAME}-alb-controller" \
  --assume-role-policy-document file://ebs-csi-trust.json
aws iam attach-role-policy --role-name "${CLUSTER_NAME}-alb-controller" \
  --policy-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${CLUSTER_NAME}-alb-controller"
aws eks create-pod-identity-association --cluster-name "$CLUSTER_NAME" --namespace kube-system \
  --service-account aws-load-balancer-controller \
  --role-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:role/${CLUSTER_NAME}-alb-controller"

# Controller
helm repo add eks https://aws.github.io/eks-charts && helm repo update eks
VPC_ID=$(aws eks describe-cluster --name "$CLUSTER_NAME" --query cluster.resourcesVpcConfig.vpcId --output text)
helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller -n kube-system \
  --set clusterName="$CLUSTER_NAME" --set region="$AWS_REGION" --set vpcId="$VPC_ID" \
  --version <chart-version-matching-ALB_CTRL_VERSION> --set serviceAccount.create=true --set serviceAccount.name=aws-load-balancer-controller --wait
kubectl get ingressclass alb
```

> Use the controller version your platform team has approved; the IAM policy must match that same version.

**8B.2 Subnets.** The controller picks subnets by their tags:

| Scheme (`ingress.alb.scheme`) | Tag required on the subnets |
|---|---|
| `internal` (recommended: reachable only from the VPC, VPN or Direct Connect) | `kubernetes.io/role/internal-elb = 1` (private subnets) |
| `internet-facing` | `kubernetes.io/role/elb = 1` (public subnets) |

```bash
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'Subnets[].{id:SubnetId,az:AvailabilityZone,cidr:CidrBlock,tags:Tags[?starts_with(Key,`kubernetes.io/role`)]}' --output table
```

At least **two zones** are required. If you do not want to rely on tags, list the subnets in `ingress.alb.subnets`.
Write down their CIDRs: they go in `networkPolicy.loadBalancerCidrs` if you enable the optional NetworkPolicy.

**8B.3 ACM certificate.** The ALB terminates TLS with an ACM certificate **in the same region** covering the NetCheck
name:

```bash
aws acm list-certificates --region "$AWS_REGION" \
  --query 'CertificateSummaryList[].{arn:CertificateArn,domain:DomainName,status:Status}' --output table
# If missing, request it (DNS validation) and wait for ISSUED:
# aws acm request-certificate --domain-name netcheck.example.com --validation-method DNS --region "$AWS_REGION"
export ACM_ARN=<certificate-arn>
```

**8B.4 ALB values** (in `values-eks.yaml`, step 13):

```yaml
httpRoute:
  enabled: false
ingress:
  enabled: true
  className: alb
  hosts: [netcheck.example.com]
  alb:
    scheme: internal                         # or internet-facing
    certificateArns: [arn:aws:acm:eu-west-1:123456789012:certificate/xxxx]
    sslRedirect: true                        # HTTP:80 only redirects to HTTPS
    # inboundCidrs: [10.0.0.0/8]             # who may reach the ALB (default 0.0.0.0/0)
    # groupName: internal-platform           # share one ALB with other Ingresses
    # wafv2AclArn: arn:aws:wafv2:...         # optional AWS WAF
```

Annotations generated by the chart: `scheme`, `target-type: ip`, `certificate-arn`, `ssl-policy`
(`ELBSecurityPolicy-TLS13-1-2-2021-06`), `listen-ports`, `ssl-redirect`, `healthcheck-path: /healthz` and, when set,
`group.name`, `subnets`, `security-groups`, `inbound-cidrs`, `wafv2-acl-arn` and `tags`. `ingress.annotations` adds or
overrides any of them.

With `internet-facing`, restrict `ingress.alb.inboundCidrs` to your corporate ranges and consider AWS WAF: the sign-in
page would be exposed to the Internet.

## 9. VPC network data

```bash
VPC_ID=$(aws eks describe-cluster --name "$CLUSTER_NAME" --query cluster.resourcesVpcConfig.vpcId --output text)
# VPC CIDR(s)
aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --query 'Vpcs[0].CidrBlockAssociationSet[].CidrBlock' --output text
# Service CIDR
aws eks describe-cluster --name "$CLUSTER_NAME" --query cluster.kubernetesNetworkConfig.serviceIpv4Cidr --output text
```

| Data | Used in |
|---|---|
| VPC CIDR | `auth.trustedProxyCidrs` (Gateway or ALB Pod/subnet IPs with VPC CNI) |
| Service CIDR and corporate ranges | Only if you decide to restrict `destinations.allowCidrs` (step 13) |

## 10. Container images: Docker Hub or an ECR mirror

NetCheck publishes public, multi-architecture (`amd64`, `arm64`) images on Docker Hub and, with the same digests, on
GitHub Container Registry:

| Image | Docker Hub (chart default) | GHCR |
|---|---|---|
| Application (API, UI and controller) | `docker.io/hgeorge123/netcheck` | `ghcr.io/hgeorge123/netcheck` |
| Probe (static Go binary, no shell) | `docker.io/hgeorge123/netcheck-probe` | `ghcr.io/hgeorge123/netcheck-probe` |

Each chart version already points to the images of its release on Docker Hub, pinned by digest: by default you do
not set any image values. Nodes in private subnets reach Docker Hub through a NAT Gateway. If your nodes have **no
Internet egress**, or your policy requires images from your own account, mirror them to ECR:

```bash
for repo in netcheck netcheck-probe; do
  aws ecr create-repository --region "$AWS_REGION" --repository-name "$repo" \
    --image-tag-mutability IMMUTABLE \
    --image-scanning-configuration scanOnPush=true \
    --encryption-configuration encryptionType=AES256
done
```

**Immutable** tags prevent overwriting a published version. Nodes pull from same-account ECR with their role
(`AmazonEC2ContainerRegistryReadOnly`). If ECR is in **another account**, add a repository policy allowing
`ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` to the node role.

To build the images yourself instead, see [install.md](install.md), step 4.

## 11. Image digests

NetCheck is **always deployed by digest**. The chart of each release carries them; read them from it (they are
also listed in the [GitHub release](https://github.com/hgeorge123/netcheck/releases)):

<!-- x-release-please-start-version -->
```bash
helm show values oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 | grep -A3 -E '^(image|probeImage):'
export APP_DIGEST=sha256:...      # image.digest
export PROBE_DIGEST=sha256:...    # probeImage.digest
```
<!-- x-release-please-end -->

You only need these variables for an **ECR mirror**. Copy both images with
[crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane) (or `skopeo copy --all`), which keeps
every architecture and the same digest, and check the scan:

<!-- x-release-please-start-version -->
```bash
aws ecr get-login-password --region "$AWS_REGION" | crane auth login "$ECR" -u AWS --password-stdin
crane copy "docker.io/hgeorge123/netcheck@$APP_DIGEST" "$ECR/netcheck:0.2.5"
crane copy "docker.io/hgeorge123/netcheck-probe@$PROBE_DIGEST" "$ECR/netcheck-probe:0.2.5"
crane digest "$ECR/netcheck:0.2.5"             # must equal $APP_DIGEST
crane digest "$ECR/netcheck-probe:0.2.5"       # must equal $PROBE_DIGEST

for r in netcheck netcheck-probe; do
  aws ecr describe-image-scan-findings --region "$AWS_REGION" --repository-name "$r" \
    --image-id imageTag=0.2.5 --query 'imageScanFindings.findingSeverityCounts'
done
```
<!-- x-release-please-end -->

## 12. NetCheck namespace

Choose **one** option:

**Option A — you create it (`namespace.create: false`, default):**

```bash
kubectl create namespace "$NC_NS"
kubectl label namespace "$NC_NS" pod-security.kubernetes.io/enforce=restricted
# Only if the listener uses allowedRoutes with Selector:
# kubectl label namespace "$NC_NS" <key>=<value>
```

**Option B — the chart creates it (`namespace.create: true`):** the chart creates `namespace.name` with Pod Security
`restricted` and the labels in `namespace.labels`. Helm stores the release in an existing namespace (e.g. `default`), and
`helm uninstall` would also delete the namespace and everything in it.

In both cases the chart creates **no NetworkPolicy** in that namespace (unless `networkPolicy.enabled: true`), and the
namespace is **not available for tests** except to users with the corresponding checkbox.

## 13. The `values-eks.yaml` file

<!-- x-release-please-start-version -->
```bash
helm pull oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 --untar
cp netcheck/values-eks.example.yaml values-eks.yaml
```
<!-- x-release-please-end -->

Fill every `<...>`:

| Value | Example | Source |
|---|---|---|
| `clusterId` | `my-cluster` | `$CLUSTER_NAME` (shown in the UI) |
| `image.*` / `probeImage.*` | Leave commented out | The chart already points to its images by digest. Only for an ECR mirror: its repositories and the digests of step 11 |
| `auth.trustedProxyCidrs` | `[10.0.0.0/16]` | VPC CIDR (step 9): covers the Gateway Pods and the ALB subnets |
| `auth.bootstrapAdmin.password` | Leave it empty | A random password is generated on the first install and never changed by upgrades. Or use `existingSecret` (step 18) |
| `namespace.create` / `namespace.name` | `false` / `""` | Step 12 |
| `namespaceScope.mode` | `all` | `all`: every namespace, including future ones (ClusterRole). `list`: only `namespaceScope.namespaces` (per-namespace Roles, no cluster permissions) |
| `namespaceScope.exclude` | `[amazon-cloudwatch, karpenter, <gateway-ns>]` | Platform namespaces nobody may use (also enforced by admission). `kube-system`, `kube-public`, `kube-node-lease` and `default` always are. Afterwards administrators can **add** exclusions in the web (**Administration → Namespaces**) without redeploying |
| `destinations.*` | Default: any IP, name and port | **Initial policy**. Afterwards it is changed in the web, **Administration → Destination policy**, without redeploying |
| `destinationsManagedBy` | `ui` (default) | `ui`: the policy is edited in the web. `helm`: the values win on every start and the web is read-only |
| `protectPlatformDestinations` | `true` (default) | Keeps EC2 metadata and the API server blocked. Do not change it |
| `persistence.createStorageClass.zones` | `[eu-west-1a]` | EBS zone (step 7.3) |
| `httpRoute.enabled` | `true` (option A) / `false` (option B) | Step 8 |
| `httpRoute.hostnames` | `[netcheck.example.com]` | DNS name (option A) |
| `httpRoute.parentRefs` | `name: $GW_NAME`, `namespace: $GW_NS`, `sectionName: <HTTPS listener>` | Step 8A |
| `ingress.enabled` | `false` (option A) / `true` (option B) | Step 8 |
| `ingress.hosts` | `[netcheck.example.com]` | DNS name (option B) |
| `ingress.alb.scheme` / `ingress.alb.certificateArns` | `internal` / `[arn:aws:acm:…]` | Step 8B |

Always denied, even if inside `allowCidrs`: EC2 metadata (`169.254.169.254`, `fd00:ec2::254`), loopback, link-local,
multicast and the API server internal IP.

**Destination policy.** By default NetCheck allows **any name, IP and port** by default
(`allowCidrs: [0.0.0.0/0, ::/0]`, `allowHostnameSuffixes: ["*"]`, `allowPorts: 1–65535`), for example
`www.google.com:443` or an on-premises server. These stay **always denied** (`protectPlatformDestinations: true`):

| Destination | Why |
|---|---|
| EC2 metadata (`169.254.169.254`, `fd00:ec2::254`) | From a Pod it could expose the node IAM credentials and instance data |
| Kubernetes API server (`kubernetes` Service IP and `kubeApiServerCidrs`) | Prevents using probes against the control plane |
| Loopback, link-local, multicast and reserved ranges | Not real network destinations; they only open abuse paths |

With `destinationsManagedBy: ui` (default) these values are only the **initial** policy: they are copied to the
database on the first start and then an administrator changes it in **Administration → Destination policy** (audited,
effective immediately). Platform protections are only controlled from Helm.

Every resolved IP is checked again inside the probe, so a name resolving to the metadata service or the API server is
blocked too (*DNS rebinding* defence). To **restrict** destinations, replace the lists, for example:

```yaml
destinations:
  allowCidrs: [10.0.0.0/16, 172.20.0.0/16]
  allowHostnameSuffixes: [.svc.cluster.local, .corp.example.com]
  allowPorts: [{from: 80, to: 80}, {from: 443, to: 443}]
```

Internet egress from the source namespace also depends on its NetworkPolicies, the NAT Gateway and Security Groups. As
an extra safeguard, configure the nodes with **IMDSv2 required and `HttpPutResponseHopLimit: 1`** (launch template),
so no Pod can reach the metadata service whatever NetCheck's configuration.

Values you usually keep: `limits` (7 checks per test, 10 s per check, 90 s per Job, 3 concurrent Jobs per namespace and
10 globally), `retention` (30/90 days), `auth` (60 min idle, 12 h session, 15 min lockout after 5 failures),
`persistence.size` (2 GiB).

Full example:

```yaml
environment: production
clusterId: my-cluster
# image / probeImage: not needed, the chart already pins its images by digest
auth:
  trustedProxyCidrs: [10.0.0.0/16]
namespaceScope:
  mode: all
  exclude: [amazon-cloudwatch, amazon-guardduty, karpenter, nginx-gateway]
# destinations: default is any destination (metadata and API server always denied)
persistence:
  size: 2Gi
  createStorageClass:
    enabled: true
    zones: [eu-west-1a]
httpRoute:
  enabled: true
  hostnames: [netcheck.example.com]
  parentRefs:
    - name: shared-gateway
      namespace: nginx-gateway
      sectionName: https
```

## 14. Validate with `--dry-run=server`

<!-- x-release-please-start-version -->
```bash
helm upgrade --install netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 -n "$NC_NS" -f values-eks.yaml --dry-run=server > /tmp/netcheck-render.yaml
echo $?    # 0 = OK
```
<!-- x-release-please-end -->

The chart queries the cluster and **fails with a clear message** if something is missing:

| Message | Step |
|---|---|
| `VPC CNI network policy is disabled` | 5 |
| `CSIDriver ebs.csi.aws.com not found` | 6 |
| `Gateway <ns>/<name> not found` | 8A (`httpRoute.parentRefs`) |
| `the cluster has no Gateway API` | 8A (or use option B with `httpRoute.enabled: false`) |
| `httpRoute.enabled and ingress.enabled are mutually exclusive` | 8: choose only one option |
| `preflight: IngressClass alb not found` | 8B.1 |
| `ingress.alb.certificateArns is required` | 8B.3 |
| `... is required` | 13 |
| `kube-system is not allowed` / `default is not allowed` | 13 (`namespaceScope`) |

## 15. Install

<!-- x-release-please-start-version -->
```bash
# Option A (namespace created by you)
helm upgrade --install netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 -n "$NC_NS" -f values-eks.yaml --wait --timeout 10m

# Option B (namespace created by the chart)
# helm upgrade --install netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 -n default -f values-eks.yaml \
#   --set namespace.create=true --set namespace.name="$NC_NS" --wait --timeout 10m
```
<!-- x-release-please-end -->

Keep `values-eks.yaml` in your configuration repository (it holds no secrets: the initial password lives only in the cluster).

## 16. Verify the installation

```bash
kubectl -n "$NC_NS" get pods,pvc,svc,httproute,ingress
kubectl -n "$NC_NS" logs deploy/netcheck | head -20

# Option A: HTTPRoute accepted by the Gateway (Accepted=True, ResolvedRefs=True)
kubectl -n "$NC_NS" get httproute netcheck \
  -o jsonpath='{range .status.parents[*].conditions[*]}{.type}={.status} {.reason}{"\n"}{end}'

# Option B: ALB address (takes 2-3 minutes) and target health (healthy)
kubectl -n "$NC_NS" get ingress netcheck -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'; echo
kubectl -n "$NC_NS" describe ingress netcheck | tail -5      # controller events
TG=$(aws elbv2 describe-target-groups --query "TargetGroups[?contains(TargetGroupName,'netcheck')].TargetGroupArn" --output text)
aws elbv2 describe-target-health --target-group-arn "$TG" --query 'TargetHealthDescriptions[].TargetHealth.State'

# Volume zone and Pod placement (must match)
kubectl get pv "$(kubectl -n "$NC_NS" get pvc netcheck-data -o jsonpath='{.spec.volumeName}')" \
  -o jsonpath='{.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values}'; echo
kubectl -n "$NC_NS" get pod -l app.kubernetes.io/name=netcheck -o wide

# Admission policies
kubectl get validatingadmissionpolicy | grep netcheck

# The controller can NOT create Pods, read Secrets or change RBAC (expected: no, no, no)
for v in "create pods" "list secrets" "create clusterrolebindings"; do
  echo -n "$v: "; kubectl auth can-i $v -A --as=system:serviceaccount:$NC_NS:netcheck-controller
done

# No NetworkPolicy created by the chart (expected: No resources found)
kubectl -n "$NC_NS" get networkpolicy

# No IAM role bound to NetCheck (expected: empty)
aws eks list-pod-identity-associations --cluster-name "$CLUSTER_NAME" --namespace "$NC_NS" --query associations --output text
```

## 17. DNS

Create in Route 53 (or your DNS) a record for the NetCheck name:

- **Option A:** pointing to the Gateway address (step 8A.5).
- **Option B:** pointing to the ALB DNS name (`kubectl -n "$NC_NS" get ingress netcheck -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'`).

For an AWS load balancer use an **alias** record (A/AAAA) or a `CNAME`. With `scheme: internal`, the record must live
in a **private** hosted zone associated with the VPC (or resolve from your corporate network).

```bash
nslookup netcheck.example.com
curl -sI https://netcheck.example.com/ | head -1      # HTTP/2 200
```

## 18. First sign-in (default user and password)

| User | Initial password |
|---|---|
| `admin` | Generated randomly on the first install (or the one in `auth.bootstrapAdmin.password` / `existingSecret`). Read it with the command below |

```bash
kubectl -n "$NC_NS" get secret netcheck-bootstrap-admin -o jsonpath='{.data.password}' | base64 -d; echo
```

1. Open `https://netcheck.example.com` **right after installing** and change the password. Anyone who can read the
   Secret could sign in until then.
2. The UI is in **English** by default. For Spanish choose **Español** in the **Language** selector before signing in; it
   is saved in your account.
3. Sign in as `admin`. NetCheck **forces a password change** (at least 12 characters) before anything else.
4. Check **Administration → System and versions**: it must show version `0.2.5` and the image digests of the chart. <!-- x-release-please-version -->
5. Create the users ([admin guide](admin-guide.md), Part II).

The Secret password only creates the first administrator; afterwards it is no longer valid, but the Secret is kept for
emergency recovery.

## 19. Smoke test and calibration

1. **Allowed vs. blocked:** pick two namespaces towards the same service, one whose NetworkPolicy allows egress and one
   that denies it. Run a **TCP** test with the service port from both: *Succeeded* in the first, *Timed out* in the
   second.
2. **ICMP:** run **Ping** to a Pod IP from a namespace without policies: it must get replies. If you get "ICMP is not
   permitted inside the probe", review third-party admission policies (step 22).
3. **Calibrate `settleSeconds`:** repeat the blocked test with `--set probe.settleSeconds=0` several times. If any run
   succeeds, the probe measured before the policy was applied: go back to 3–5 s.
4. **Pod rescheduling:** `kubectl -n "$NC_NS" rollout restart deploy/netcheck` and check the Pod returns to the volume's
   zone with the history intact.

## 20. IAM roles summary

| Component | IAM role? |
|---|---|
| NetCheck (controller) | **No.** It does not call AWS APIs |
| Probes (`netcheck-probe`) | **No, never.** Admission policies reject a probe ServiceAccount with IRSA |
| EBS CSI driver | **Yes**, `AmazonEBSCSIDriverPolicy` (step 6) |
| AWS Load Balancer Controller (option B) | **Yes**, its official policy (step 8B.1) |
| Nodes | None for NetCheck; ECR read (`AmazonEC2ContainerRegistryReadOnly`) only with an ECR mirror |
| Installer | Step 2 |

## 21. Upgrade, roll back and uninstall

<!-- x-release-please-start-version -->
```bash
# Upgrade: the new chart version brings the digests of its images
# (with an ECR mirror, copy the new images first: step 11)
helm upgrade netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 0.2.5 -n "$NC_NS" -f values-eks.yaml \
  --wait --timeout 10m

# Always pass -f values-eks.yaml (or --reset-then-reuse-values). Do NOT use --reuse-values: it skips the
# chart's new default values and the templates may fail or render incomplete.

# Helm deployment history and rollback
helm history netcheck -n "$NC_NS"
helm rollback netcheck <REVISION> -n "$NC_NS" --wait

# Uninstall (PVC, Secret and StorageClass are kept on purpose)
helm uninstall netcheck -n "$NC_NS"
```
<!-- x-release-please-end -->

The UI shows the running version and the version history in **Administration → System and versions**.

## 22. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Pod `Pending` with `volume node affinity conflict` | No nodes in the EBS zone | Step 7.2: capacity in that zone |
| PVC `Pending` | EBS CSI driver missing or without role | Step 6; `kubectl -n $NC_NS describe pvc netcheck-data` |
| `ImagePullBackOff` | Node cannot reach Docker Hub (no NAT), Docker Hub rate limits, cannot read the ECR mirror, or wrong digest | Step 10; check digests |
| `CrashLoopBackOff` | Invalid configuration | `kubectl -n $NC_NS logs deploy/netcheck --previous` |
| HTTPRoute `Accepted=False` | `allowedRoutes` or `sectionName` | Step 8A |
| Ingress without address | Controller missing, without IAM permissions or no tagged subnets | `kubectl -n $NC_NS describe ingress netcheck`; step 8B |
| ALB answers 502/503 | Target `unhealthy`: the ALB Security Group cannot reach the Pod (8080) or the Pod is not ready | `aws elbv2 describe-target-health`; check Security Groups for Pods |
| "Not allowed by the NetCheck destination policy" | Protected destination, or restricted in **Administration → Destination policy** | The message gives the exact reason |
| Every test ends in "Infrastructure error" | No API server access or quota | Pod logs; `kubectl -n <ns> describe job` |
| "ICMP is not permitted inside the probe" | Kyverno/Gatekeeper blocks the `net.ipv4.ping_group_range` sysctl | Allow that safe sysctl for the probe |
| Ping gets no reply but TCP works | ICMP filtered | Expected |
| Many `429` at sign-in | Wrong `trustedProxyCidrs` | Gateway Pod CIDR |

---

## Appendix A. Local laboratory (before EKS)

Needs Docker, kind, kubectl and Helm, and a checkout of the repository. Creates a **local** kind cluster with Calico (which enforces
NetworkPolicies), a local registry and sample namespaces (`nc-allow`, `nc-deny`, `nc-open`, `nc-target`):

```bash
bash test/integration/lab.sh up        # cluster + Calico + fixtures
bash test/integration/lab.sh gateway   # (optional) NGINX Gateway Fabric + lab HTTPS Gateway (the ALB only exists on AWS)
bash test/integration/lab.sh deploy    # builds the images and installs the chart
kubectl --context kind-netcheck-lab -n netcheck port-forward svc/netcheck 8080:8080
```

Open `http://localhost:8080` (or `https://netcheck.lab.test:8443` with the Gateway). User `admin`, password in the
Secret `netcheck-bootstrap-admin` (the lab does not force the change; EKS does). To remove everything:
`bash test/integration/lab.sh down`.

## Appendix B. Final checklist

- [ ] Kubernetes ≥ 1.30 and EC2 Linux nodes in the chosen zone.
- [ ] VPC CNI with `--enable-network-policy=true`.
- [ ] EBS CSI driver active with its IAM role.
- [ ] `persistence.createStorageClass.zones` pinned to a zone with nodes (recommended).
- [ ] Images deployed by **digest** (the chart defaults, or an ECR mirror with the scan reviewed).
- [ ] `values-eks.yaml` complete; `--dry-run=server` without errors.
- [ ] Only one exposure enabled: HTTPRoute `Accepted=True` (A) or ALB target `healthy` (B); DNS resolves; HTTPS answers 200.
- [ ] `admin` password changed right after installing.
- [ ] Controller `can-i` answers `no`; no IAM associations; no NetworkPolicy created.
- [ ] Smoke test (allowed/blocked/ICMP) passed and EBS snapshots scheduled.
