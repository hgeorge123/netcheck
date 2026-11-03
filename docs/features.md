# Features

Everything NetCheck does today, grouped by area. Each entry links to the guide that explains how to use it.

## Contents

1. [Checks](#1-checks)
2. [Results and diagnosis](#2-results-and-diagnosis)
3. [Firewall ticket mode](#3-firewall-ticket-mode)
4. [Dashboard and history](#4-dashboard-and-history)
5. [Pipelines and the command line](#5-pipelines-and-the-command-line)
6. [Accounts and sign-in](#6-accounts-and-sign-in)
7. [Administration from the web](#7-administration-from-the-web)
8. [Security](#8-security)
9. [Installation and operations](#9-installation-and-operations)
10. [Interface](#10-interface)

## 1. Checks

Every test runs from the source namespace you pick, in a short-lived probe Pod subject to that namespace's
NetworkPolicies, DNS and routes. Up to seven checks run one after another in the same Pod.

| Feature | What it does | How to use it |
|---|---|---|
| DNS | Resolves a name (A/AAAA and CNAME), IPv4 and IPv6, IPv4 only or IPv6 only | [User guide §4.2](user-guide.md#42-checks) |
| TCP | Opens a TCP connection to a port | [User guide §4.2](user-guide.md#42-checks) |
| UDP | Generic port, DNS server or NTP server (stratum, reference and clock offset) | [User guide §4.2.1](user-guide.md#421-udp) |
| HTTP | GET or HEAD to a port and path; redirects are shown, not followed | [User guide §4.2](user-guide.md#42-checks) |
| HTTPS | The same over TLS, verifying the certificate; TLS version, certificate name, issuer and expiry in the result | [User guide §4.2](user-guide.md#42-checks) |
| Certificate problems | Expired, not yet valid, issued for another name, untrusted authority or self-signed: all of them are named in the result | [User guide §5.2](user-guide.md#52-interpreting-each-check) |
| Corporate certificate authorities | HTTPS trusts your corporate PKI or the authority of a TLS inspection proxy on top of the public ones, and the result says when one was used. No custom image | [Admin guide §18](admin-guide.md#18-certificate-authorities) |
| Through a proxy | TCP, HTTP and HTTPS optionally go through a shared or personal HTTP proxy (CONNECT tunnel or forwarded request), with the proxy's own certificate authority if it inspects TLS; the result says whether the proxy was unreachable, refused, required authentication or could not reach the destination | [User guide §4.2](user-guide.md#42-checks), [CLI `--proxy`](cli.md#4-run-a-test) |
| My proxies | Each user's own proxies, visible and usable only by them; others only see that a test used a personal proxy | [User guide §4.2](user-guide.md#42-checks) |
| Ignore certificate errors | HTTPS goes on despite certificate problems (like `curl --insecure`); the result is a warning that still lists them | [User guide §4.2](user-guide.md#42-checks), [CLI `--ignore-tls-errors`](cli.md#4-run-a-test) |
| Ping | 1 to 10 ICMP echo requests with loss and RTT, without privileges (no `NET_RAW`, no root) | [User guide §5.3](user-guide.md#53-ping-and-traceroute) |
| Traceroute | ICMP traceroute up to 30 hops, without privileges | [User guide §5.3](user-guide.md#53-ping-and-traceroute) |
| Timeouts | Per-check timeout, 5 s by default and 10 s at most (configurable limits) | [User guide §4.2](user-guide.md#42-checks) |
| Destination checked before sending | A destination or port the policy does not allow is rejected without sending any traffic, with the exact reason | [User guide §4.4](user-guide.md#44-request-preview-and-running-the-test) |

## 2. Results and diagnosis

| Feature | What it does | How to use it |
|---|---|---|
| Readable diagnosis | Every check says what the result means and what it does not mean (a timeout is not proof of a NetworkPolicy block; an HTTP 503 is not a network failure) | [User guide §5.2](user-guide.md#52-interpreting-each-check) |
| Overall status | Passed, connectivity failures or infrastructure error (NetCheck could not run the test: not a network result) | [User guide §5.1](user-guide.md#51-overall-status) |
| Equivalent command | A command to reproduce each check by hand (`curl`, `nc`, `dig`…) | [User guide §5.5](user-guide.md#55-check-details) |
| Fidelity notice | Whether the namespace's egress policies apply to the probe exactly as to your workloads | [User guide §5.4](user-guide.md#54-fidelity-notice) |
| Path | Probe Pod, node, measured hops and destination, showing where the traffic stops | [User guide §5.6](user-guide.md#56-path) |
| What is missing | Nothing, a suggested egress NetworkPolicy built from the measured IPs and ports, or no NetworkPolicy change because the block is outside the cluster | [User guide §5.7](user-guide.md#57-what-is-missing) |
| Firewall request | Ready-to-send text for the firewall team: source Pod and node IPs, what got no answer and what works | [User guide §5.7](user-guide.md#57-what-is-missing) |
| Quota check | Before starting the probe, tells whether it fits in the namespace's ResourceQuota and LimitRange, and names the one that blocks it | [Admin guide, troubleshooting](admin-guide.md#8-troubleshooting) |
| Run again and Copy JSON | Reopens the form with the same values; copies the full result | [User guide §5](user-guide.md#5-reading-the-result) |

## 3. Firewall ticket mode

| Feature | What it does | How to use it |
|---|---|---|
| One-click ticket output | `date`, `hostname`, `ping`, `traceroute`, `telnet` and `curl -v` against a destination and port, in one block | [User guide §4.3](user-guide.md#43-firewall-ticket-troubleshooting) |
| Copy or download | **Copy report** and **Download .txt** to attach to the ticket | [User guide §4.3](user-guide.md#43-firewall-ticket-troubleshooting) |
| IP seen by the firewall | The real Pod and node IPs from the Kubernetes API, and which one the firewall sees (SNAT) | [User guide §4.3](user-guide.md#43-firewall-ticket-troubleshooting) |
| Measured values only | Nothing invented: what the probe does not measure is left out | [Security model §8](security.md#8-evidence-integrity) |

## 4. Dashboard and history

| Feature | What it does | How to use it |
|---|---|---|
| Dashboard | Your tests of the last 24 hours by status and method, your namespaces and your latest tests | [User guide §3](user-guide.md#3-dashboard) |
| Test history | Your own tests only, private to each user (administrators: every test), with filters and configurable columns | [User guide §6](user-guide.md#6-test-history) |
| Data retention | Technical output and history are deleted after a configurable number of days | [Admin guide §12](admin-guide.md#12-data-retention) |

## 5. Pipelines and the command line

| Feature | What it does | How to use it |
|---|---|---|
| API tokens | Personal tokens (30 to 365 days, shown once) that can only run and read tests | [User guide §8](user-guide.md#8-api-tokens-and-the-command-line), [CLI guide §2](cli.md#2-create-an-api-token) |
| `netcheck-cli` | Runs a test, waits for the result and exits with a code a pipeline can act on (0, 1, 2, 3) | [CLI guide](cli.md) |
| Binaries | Linux, macOS and Windows binaries attached to every release, with checksums and provenance | [CLI guide §1](cli.md#1-get-the-cli) |
| Token administration | Administrators list and revoke every token; expired tokens are deleted automatically | [Admin guide §17](admin-guide.md#17-api-tokens) |

## 6. Accounts and sign-in

| Feature | What it does | How to use it |
|---|---|---|
| Local accounts | `admin` and `user` roles, per-user namespaces (a list or all, including future ones) | [Admin guide §4](admin-guide.md#4-creating-a-user) |
| Generated initial password | The chart creates a random `admin` password on new installs and never changes it on upgrades | [Installation §11](install.md#11-first-sign-in) |
| Password rules | At least 12 characters, mandatory change of temporary passwords, argon2id hashing | [User guide §2.2](user-guide.md#22-first-sign-in-mandatory-password-change) |
| Lockout and rate limiting | 5 failed attempts lock the account for 15 minutes; per-IP rate limiting | [User guide §2.1](user-guide.md#21-signing-in-and-language) |
| Sessions | Server-side sessions, 60 minutes idle and 12 hours at most; administrators see and end them | [Admin guide §9](admin-guide.md#9-active-sessions) |
| Single sign-on | Any OpenID Connect provider (Entra ID, Okta, Keycloak, Google…) | [SSO guide §3](sso.md#3-an-oidc-provider-entra-id-okta-keycloak-google) |
| Bundled Dex | GitHub, GitLab, LDAP or Active Directory, SAML and others through Dex | [SSO guide §2](sso.md#2-github-ldap-and-others-through-the-bundled-dex) |
| Access rules | Role and namespaces per group, per user or for any authenticated user, defined before the first sign-in | [Admin guide §16](admin-guide.md#16-access-rules-single-sign-on), [SSO guide §4](sso.md#4-access-rules-who-gets-what) |
| Administrator recovery | Restores the initial `admin` password from the Secret when every administrator is locked out | [Admin guide, recovering access](admin-guide.md#5-recovering-administrator-access) |

## 7. Administration from the web

Changes apply at once, without redeploying, and are audited.

| Feature | What it does | How to use it |
|---|---|---|
| Users | Create, edit, reset passwords, unlock, disable and delete | [Admin guide §3–8](admin-guide.md#3-user-list) |
| Namespaces | Exclude namespaces (also ones that do not exist yet) and include them again | [Admin guide §10](admin-guide.md#10-namespaces) |
| Destination policy | Allowed names, networks and ports, denied networks, presets, and a check that sends no traffic; optionally managed with Helm instead | [Admin guide §11](admin-guide.md#11-destination-policy) |
| Certificate authorities | Add or remove trusted authorities (PEM) with subject, expiry and fingerprint; optionally managed with Helm instead | [Admin guide §18](admin-guide.md#18-certificate-authorities) |
| Proxies | Shared HTTP proxies for TCP, HTTP and HTTPS, for every user or administrators only, each with optional certificate authorities; optionally managed with Helm instead | [Admin guide §19](admin-guide.md#19-proxies) |
| Data retention | Days of technical output and of history | [Admin guide §12](admin-guide.md#12-data-retention) |
| System and versions | Running version, image digests, chart version and the history of every version deployed | [Admin guide §13](admin-guide.md#13-system-and-versions) |
| Audit log | Sign-ins, user, policy, namespace, retention, rule and token changes | [Admin guide, audit and logs](admin-guide.md#6-audit-and-logs) |
| Safety rules | Nobody can lock themselves out; the last administrator cannot be removed | [Admin guide §14](admin-guide.md#14-safety-rules) |

## 8. Security

| Feature | What it does | Where it is explained |
|---|---|---|
| Probe sandbox | Shell-less Go binary pinned by digest, non-root, read-only, no capabilities, no token, no cloud credentials | [Security model §1](security.md#1-the-probe) |
| Admission policies | Native `ValidatingAdmissionPolicies` limit what the controller can create even if its token leaks | [Security model §2](security.md#2-admission-policies) |
| Least-privilege RBAC | The controller cannot create Pods directly, read Secrets, exec or change RBAC | [Security model §3](security.md#3-rbac) |
| Platform protections | Cloud metadata, the API server, loopback and link-local are always denied; every resolved IP is checked inside the probe | [Security model §4](security.md#4-destination-policy) |
| Protected namespaces | System namespaces and the NetCheck namespace are never used as sources (unless allowed per user) | [Security model §5](security.md#5-namespaces) |
| Signed releases | Images and chart scanned with Grype, signed with Sigstore, with SBOM and SLSA provenance | [Security model §10](security.md#10-verifying-releases) |

## 9. Installation and operations

| Feature | What it does | How to use it |
|---|---|---|
| One Helm chart | One Pod with SQLite on a persistent volume; images deployed by digest | [Installation](install.md) |
| Gateway API | Exposed with an `HTTPRoute` of any Gateway API implementation | [Installation §6](install.md#6-choose-how-to-expose-netcheck) |
| Ingress | AWS Load Balancer Controller or any Ingress controller (ingress-nginx, Traefik, HAProxy, AKS application routing) | [Installation §6](install.md#6-choose-how-to-expose-netcheck) |
| Amazon EKS | VPC CNI network policy, EBS, ALB or Gateway API, with preflight checks | [EKS guide](install-eks.md) |
| Azure AKS | Network policy engine, Azure Disk and ZRS, Gateway API or Ingress | [AKS guide](install-aks.md) |
| Preflight checks | `helm install` and `helm upgrade` verify the cluster prerequisites first | [Installation §8](install.md#8-validate-against-the-cluster) |
| NetworkPolicies | The chart protects the NetCheck namespace and explains which policies other namespaces need | [Admin guide §1.1](admin-guide.md#11-how-a-test-runs-from-another-namespace-and-which-networkpolicies-are-needed) |
| Limits | Checks per test, timeouts, output size and concurrent tests per namespace and in total | [Installation §7](install.md#7-write-your-values-file) |
| Log level | `debug`, `info`, `warn` or `error` | [Admin guide, audit and logs](admin-guide.md#6-audit-and-logs) |
| Upgrades and backups | `helm upgrade` keeps data and passwords; volume snapshots for backups | [Admin guide, upgrading](admin-guide.md#1-upgrading), [backups](admin-guide.md#3-backups) |
| Local laboratory | A kind cluster with Calico and sample namespaces to try NetCheck on a laptop | [Installation appendix](install.md#appendix-try-it-locally-with-kind) |

## 10. Interface

| Feature | What it does | How to use it |
|---|---|---|
| Languages | English and Spanish, saved in each account | [User guide §2.4](user-guide.md#24-user-menu-preferences-and-sign-out) |
| Console layout | Side navigation, breadcrumbs and a help panel on every page | [User guide §2.3](user-guide.md#23-page-layout) |
| Live result | The result page refreshes by itself while the probe works | [User guide §5](user-guide.md#5-reading-the-result) |
