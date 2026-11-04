# Security model

NetCheck lets people create Pods in other teams' namespaces and send traffic to destinations they choose. That is
powerful, so the design assumes that any single layer can fail and stacks several of them. This page explains each
layer, the risks it addresses and what remains.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Summary

| Layer | What it guarantees |
|---|---|
| Probe sandbox | The probe is a fixed Go binary without a shell, non-root, read-only, with no capabilities, no token and no credentials |
| Admission policies | Even a stolen controller token can only create probe Jobs with the pinned image and the safe template |
| Least-privilege RBAC | The controller cannot create Pods directly, read Secrets, exec or change RBAC |
| Destination policy | Cloud metadata, the API server, loopback and link-local are always denied; every resolved IP is checked inside the probe |
| Namespace exclusions | System namespaces, the NetCheck namespace and the ones you exclude are never used as sources |
| Authentication | Local accounts (argon2id, lockout, rate limiting, mandatory change of initial passwords) and optional single sign-on (OIDC with PKCE); server-side sessions; API tokens limited to tests |
| Evidence integrity | NetCheck never fabricates output: what was not measured is not shown |
| Supply chain | Images and chart built only by the release workflow, scanned for vulnerabilities, signed with Sigstore, with SBOM and provenance |

## 1. The probe

Every test runs in a short-lived Job in the source namespace. The Pod template is built in code
([internal/k8s/jobs.go](../internal/k8s/jobs.go)) and cannot be influenced by users beyond the validated test
specification:

- **Image pinned by digest** (`probeImage.digest`): a static Go binary in a distroless base, with **no shell** and no
  other tools. It does not run commands; it implements DNS, TCP, UDP, HTTP/HTTPS, ping and traceroute with Go primitives.
- **Fixed UDP datagrams:** the UDP check only sends an empty datagram, a standard DNS query for the root zone or an
  NTP client request, at most three per check. Users cannot choose the content, so the probe cannot be used for
  reflection or amplification attacks.
- **Security context:** `runAsNonRoot` (UID 65532), `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`. It complies with Pod Security `restricted`.
- **No identity:** a dedicated `netcheck-probe` ServiceAccount with `automountServiceAccountToken: false`. The
  controller refuses to use it if someone attached a cloud IAM role (IRSA annotation) to it.
- **No host access:** no `hostNetwork`, `hostPID`, `hostIPC`, host ports or volumes.
- **ICMP without privileges:** ping and traceroute use Linux *ping sockets*, enabled by the safe sysctl
  `net.ipv4.ping_group_range` restricted to the probe's own group. No `NET_RAW`.
- **Bounded:** CPU, memory and ephemeral storage limits, `activeDeadlineSeconds`, `backoffLimit: 0`, a maximum number
  of checks per test and of concurrent Jobs per namespace and in total.
- **Specification:** passed as an immutable JSON environment variable (`NETCHECK_SPEC`) and validated again by the
  probe. No ConfigMaps, no arguments, no user-controlled headers or bodies.
- **Extra certificate authorities:** the authorities administrators add for HTTPS (corporate PKI, firewalls that
  decrypt TLS on the path) and those of the proxy a check goes through travel in that same specification, only for
  tests with an HTTPS check. The authorities of a proxy are trusted only by checks through that proxy, so an
  unexpected interception on a direct path is still reported. They are public certificates, never
  keys; the probe parses them again, accepts only CA certificates and **adds** them to the public authorities without
  replacing them. Adding them needs no volume, no ConfigMap, no change to the admission policies and no custom image.
- **Output:** the probe prints a single structured result line; the controller reads it through the API server
  (`pods/log`), not over the network, and then deletes the Job.

## 2. Admission policies

`jobs/create` in RBAC allows *any* Pod template: an attacker with the controller token could otherwise run an
arbitrary image with `hostNetwork` or mount Secrets. Two native `ValidatingAdmissionPolicies` (no webhook, no CRDs)
apply **only to the controller's ServiceAccount**:

- **Jobs:** exact probe image by digest, the `netcheck-probe` ServiceAccount, no token, no volumes, init or ephemeral
  containers, no `env.valueFrom` / `envFrom` (which would read Secrets through the kubelet), the restricted security
  context, only the allowed sysctl, required labels and a bounded deadline.
- **ServiceAccounts:** only `netcheck-probe`, without a token and without IAM annotations.
- Both **deny** `kube-system`, `kube-public`, `kube-node-lease`, `default`, the NetCheck namespace and every namespace
  in `namespaceScope.exclude`.

The chart refuses to install without them unless you explicitly disable `admissionPolicy.enabled`. If your cluster
uses Kyverno or Gatekeeper, you can port the same rules there as an extra layer.

## 3. RBAC

| Mode | Objects | Permissions |
|---|---|---|
| `all` (default) | ClusterRole + ClusterRoleBinding | `jobs` create/get/list/watch/delete, `pods` get/list/watch, `pods/log` get, `networkpolicies` get/list, `namespaces` get/list/watch, `serviceaccounts` get/create, `resourcequotas` and `limitranges` list |
| `list` | Role + RoleBinding per listed namespace | The same, without cluster-wide rights; probe ServiceAccounts are created by the chart |

Never granted: `pods/create`, `pods/exec`, `secrets`, RBAC objects, NetworkPolicy or quota changes, or admission policies.
Quotas and LimitRanges are only read, to tell before creating a Job whether the probe fits in the source namespace.
Verify it after installing:

```bash
for v in "create pods" "list secrets" "create clusterrolebindings"; do
  kubectl auth can-i $v -A --as=system:serviceaccount:netcheck:netcheck-controller
done   # no, no, no
```

Residual risks, accepted and documented:

- RBAC cannot filter by label, so a compromised controller could delete other Jobs or read other Pods' logs in source
  namespaces. The code only touches resources labelled as NetCheck runs.
- A compromised controller can start probe Jobs (only with the pinned image and template) in any non-excluded
  namespace and create empty `netcheck-probe` ServiceAccounts.

## 4. Destination policy

The probe could otherwise be used as an SSRF proxy. Protections:

- **Platform protections** (`protectPlatformDestinations: true`, set only in Helm and never stored in the database or
  editable in the web): cloud metadata (`169.254.169.254`, `fd00:ec2::254`), the Kubernetes API server (the
  `kubernetes` Service IP detected at startup plus `kubeApiServerCidrs`), loopback, link-local, multicast and reserved
  ranges. Deny always wins over allow.
- **Configurable policy:** allowed host name suffixes, allowed networks, denied networks and allowed ports. By default
  any name, IP and port is allowed, because NetCheck is a troubleshooting tool. Administrators can restrict it in the
  web (audited, effective for the next test) or manage it from Helm with `destinationsManagedBy: helm`.
- **DNS rebinding:** a host name can pass the suffix check and resolve to a forbidden IP. The probe resolves from the
  source namespace, checks **every resolved IP** against the policy and connects to the validated IP.
- **Parsing tricks:** IPv4-mapped IPv6 (`::ffff:169.254.169.254`) is unmapped, IPv6 zones and non-canonical forms are
  rejected, values starting with `-` or containing whitespace or control characters are rejected.
- **HTTP:** redirects are not followed (the `Location` is reported), URLs with credentials or query strings are
  rejected, there are no custom headers or bodies.
- **Proxies:** TCP, HTTP and HTTPS checks may go through an HTTP proxy, only when the user chooses it: a shared proxy
  of the administrators (only administrators change them; each is shared with every user or kept for administrators)
  or a personal proxy, which only its owner sees, changes and uses. Every proxy is a destination like any other: its
  address and port must pass the policy (platform protections included) when it is saved and on every test, and every
  IP it resolves to is checked before the probe connects. The destination itself is then checked **by name and port
  only**, because the proxy, not the probe, resolves it: a personal proxy reaches whatever that proxy reaches, so keep
  the destination policy restrictive enough. Proxy changes are audited with name, address and authority fingerprints.
  A test through a personal proxy shown to anyone but its author (administrators) hides the proxy's name, address,
  IPs and authorities. The authorities of a proxy are trusted only for checks through it. The probe never sends proxy
  credentials and ignores `HTTP_PROXY`/`HTTPS_PROXY`: without a proxy chosen, it always tests the direct path.

Defense in depth on AWS: require **IMDSv2 with `HttpPutResponseHopLimit: 1`** on the nodes, so no Pod can reach the
instance metadata whatever NetCheck's configuration.

## 5. Namespaces

- Never available as sources: `kube-system`, `kube-public`, `kube-node-lease`, `default` (chart, admission and API).
- The NetCheck namespace is hidden from everyone, administrators included, except accounts with "Allow tests in the
  NetCheck namespace".
- `namespaceScope.exclude` (Helm) is enforced by the API **and** by admission.
- Administrators can **add** exclusions in the web. They cannot remove Helm or system exclusions: that would require
  NetCheck to modify its own admission policies, which is a privilege escalation.
- The chart creates **no NetworkPolicy** by default. Source namespaces need none (the probe accepts no connections and
  is read through the API server). An optional policy for the NetCheck namespace is available with
  `networkPolicy.enabled`.

## 6. Authentication and sessions

NetCheck has its own user database (no external identity provider is required):

- Passwords hashed with **argon2id** (19 MiB, 2 iterations, 1 thread), 12–128 characters, different from the username,
  no composition rules (NIST SP 800-63B). Never logged.
- Server-side sessions: a random 256-bit token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie; only its SHA-256
  is stored. Idle (60 min) and absolute (12 h) expiry.
- Account lockout after 5 failures for 15 minutes and a per-IP rate limit. The client IP is taken from
  `X-Forwarded-For` **only** when the connection comes from `auth.trustedProxyCidrs`.
- Generic sign-in errors, with the hashing cost paid for unknown users too (no user enumeration).
- Temporary passwords (new users, resets, the initial admin) must be changed before anything else.
- Changing or resetting a password, or disabling or deleting a user, ends their sessions.
- CSRF: mutating endpoints require JSON and reject cross-site `Origin` / `Sec-Fetch-Site`.
- Authorization is checked on every request in the backend. Users read only the tests they started (administrators read
  every test); anyone else's test answers `404`, exactly like a test that does not exist.
- Two roles: `admin` and `user`. The last active administrator cannot be removed, disabled or demoted.
- **No built-in MFA for local accounts.** Use single sign-on (below) so the MFA of your identity provider applies, or
  put NetCheck behind your SSO proxy. Mitigations for local accounts: lockout, rate limiting, mandatory HTTPS and
  sign-in auditing.

**Single sign-on (optional, [sso.md](sso.md)).** OpenID Connect authorization code flow with PKCE (S256); the `state`
is bound to the browser by a short-lived `HttpOnly` cookie and the ID token must carry the one-time `nonce`, the
expected issuer and audience and a valid signature. NetCheck keeps no provider token: after the sign-in the person has
a normal NetCheck session. The callback always lands on the NetCheck home page (no open redirect). With `email` as the
username, addresses the provider marks as unverified are refused. Permissions come only from access rules written by
administrators; no rule, no access. SSO accounts have no password and can never use the password form; a username
already used by a local account is refused instead of being merged. The bundled Dex runs non-root with a read-only
file system and no Kubernetes token, its connector credentials come from a Secret, and NetCheck reaches it inside the
cluster for the token exchange.

**API tokens.** Random 256-bit tokens with the `nck_` prefix (easy to detect if leaked), stored as SHA-256, shown
once, with a mandatory expiry of at most a year and at most 20 per user. A token acts as its owner but only on the
test endpoints (run, read results, list namespaces and the catalog): it cannot manage users, tokens, rules or
settings. It stops working when it expires or is revoked, when the account is disabled or must change its password,
and when an SSO account loses its access rule. Creation and revocation are audited.

**Initial administrator.** `admin`, with a random 24-character password that the chart generates on the first install
(unless you set `auth.bootstrapAdmin.password` or `existingSecret`). Upgrades never change the Secret, and the
application only uses it when no administrator exists or during the break-glass recovery, so existing passwords are
never reset. It must be changed at first sign-in; do it right after installing, because until then anyone who can read
the Secret could use it.

## 7. Audit

The `audit_events` table records sign-ins (successful and failed), sign-outs, password changes, user changes,
recoveries and ended sessions, API tokens, access rules, tests started or rejected, destination policy, retention and
namespace changes, trusted certificate authorities (subject and fingerprint), shared and personal proxies (name and
address), and probe security events. It never contains passwords, tokens or certificate PEM. Logs are JSON with a
`request_id` per request.

## 8. Evidence integrity

NetCheck is used to open firewall tickets and to argue about root causes, so it never shows what it did not measure:

- No simulated results: without a reachable cluster a run ends as an *infrastructure error*.
- The "equivalent command" is labelled as an approximation; the probe does not run it.
- The firewall ticket report reproduces command output only with measured values and states that it comes from the
  probe. It does **not** produce an `ifconfig` of the server: the probe has no access to the host, so it shows the real
  Pod and node IPs from the Kubernetes API instead and explains which one the firewall will see.
- An HTTP 4xx/5xx answer is reported as established connectivity with an application warning, not as a network failure.

## 9. Limits of what a result means

The result belongs to the **probe Pod**. It can differ from your application when security groups for Pods,
`ClusterNetworkPolicy`, service meshes, policies with specific selectors, or ingress rules on the destination side are
involved. The fidelity notice on each result points this out. In CNIs that apply policies to new Pods asynchronously,
`probe.settleSeconds` (3 s by default) avoids a false "allowed" result; calibrate it as described in
[install.md](install.md#12-smoke-test).

## 10. Verifying releases

Every release is built by the [release workflow](../.github/workflows/release.yml) from the tagged commit, with no
manual steps. Before a release can be merged its images are scanned with [Grype](https://github.com/anchore/grype): a
High or Critical vulnerability that already has a fix blocks it. Pull requests that add a dependency with a known High
or Critical vulnerability fail the `dependencies` check, and `govulncheck` fails the build when the code calls a known
vulnerable Go function. The images carry an SBOM and SLSA build provenance, and the images and the chart are signed with
[Sigstore](https://www.sigstore.dev/) keyless signing, bound to that workflow. The release notes list every digest.

Verify an image signature (the same command works for `netcheck-probe` and for the GHCR copies):

```bash
cosign verify docker.io/hgeorge123/netcheck@sha256:<digest> \
  --certificate-identity https://github.com/hgeorge123/netcheck/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verify the chart signature:

```bash
cosign verify ghcr.io/hgeorge123/charts/netcheck@sha256:<chart-digest> \
  --certificate-identity https://github.com/hgeorge123/netcheck/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verify the build provenance with the GitHub CLI, or read the SBOM:

```bash
gh attestation verify oci://docker.io/hgeorge123/netcheck@sha256:<digest> --owner hgeorge123
docker buildx imagetools inspect docker.io/hgeorge123/netcheck@sha256:<digest> --format '{{ json .SBOM }}'
```

To enforce this in your cluster, admission controllers such as the Sigstore policy-controller or Kyverno can require
these signatures for the NetCheck images.

### netcheck-cli binaries

The CLI binaries are built by [tools/build-cli.sh](../tools/build-cli.sh) and released with a checksums file and build
provenance (`gh attestation verify <file> --owner hgeorge123`). The Windows binary also carries a version resource
(product, version, company, copyright), the NetCheck icon and an `asInvoker` manifest
([cmd/netcheck-cli/winres/winres.json](../cmd/netcheck-cli/winres/winres.json), embedded with
[go-winres](https://github.com/tc-hib/go-winres) pinned by version), and keeps its symbols: stripped Go executables
without metadata are often flagged by antivirus heuristics.

**Authenticode signing (maintainers).** The release signs the Windows binary with
[Azure Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/) when these repository **variables**
(Settings → Secrets and variables → Actions → Variables) are set; without them the binary is published unsigned:

| Variable | Value |
|---|---|
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | App registration with a federated credential for this repository (subject `repo:hgeorge123/netcheck:ref:refs/heads/main`) and the *Artifact Signing Certificate Profile Signer* role. Sign-in uses OIDC: no client secret |
| `AZURE_ARTIFACT_SIGNING_ENDPOINT` | Endpoint of the signing account, e.g. `https://eus.codesigning.azure.net/` |
| `AZURE_ARTIFACT_SIGNING_ACCOUNT` | Signing account name |
| `AZURE_ARTIFACT_SIGNING_PROFILE` | Certificate profile name (public trust) |

The signature is timestamped and checked in the workflow (`Get-AuthenticodeSignature` must be `Valid`) before the
checksums and the provenance are computed, so both cover the signed binary.
