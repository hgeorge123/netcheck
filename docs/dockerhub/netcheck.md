<p align="center">
  <img src="https://raw.githubusercontent.com/hgeorge123/netcheck/main/docs/brand/netcheck-logo.png" alt="NetCheck" width="320">
</p>

**NetCheck** answers a question every platform team hears daily: *"Can my application in namespace X reach host Y on
port Z?"* It runs network checks **from inside the Kubernetes namespace you pick**, so the result reflects the same
NetworkPolicies, DNS and routes your workloads get, and it explains the result in plain language.

This image contains the NetCheck **application**: REST API, web interface and Kubernetes controller, in one Go binary.
Each test runs in a short-lived probe Pod that uses the
[`hgeorge123/netcheck-probe`](https://hub.docker.com/r/hgeorge123/netcheck-probe) image.

- **Source code and documentation:** <https://github.com/hgeorge123/netcheck>
- **License:** Apache 2.0

## Features

- DNS, TCP, UDP (generic, DNS or NTP), HTTP, HTTPS, ping and traceroute checks; ICMP without privileges.
- Corporate certificate authorities trusted by HTTPS without a custom image, and optional HTTP proxies for TCP, HTTP
  and HTTPS: shared by the administrators or personal to each user, with their own certificate authorities.
- Firewall ticket mode: one block of `date`, `hostname`, `ping`, `traceroute`, `telnet` and `curl -v` output.
- Readable diagnosis, equivalent command and NetworkPolicy fidelity notice for every result, plus what is missing:
  nothing, a suggested NetworkPolicy or a request for the firewall team.
- Local users with `admin` and `user` roles, per-user namespaces, private test history and audit log; single sign-on
  with OpenID Connect or, through the bundled Dex, GitHub, LDAP and SAML.
- API tokens and `netcheck-cli` to check connectivity from pipelines.
- Destination policy, namespace exclusions, certificate authorities, proxies and data retention managed from the web.
- English and Spanish interface.

The complete list is in [docs/features.md](https://github.com/hgeorge123/netcheck/blob/main/docs/features.md).

## Install with Helm

Do not run this image on its own: install NetCheck with its Helm chart, which pins both images by digest and creates
the RBAC, the admission policies and the storage it needs.

<!-- x-release-please-start-version -->
```bash
helm upgrade --install netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 1.1.2 \
  --namespace netcheck -f values.yaml
```
<!-- x-release-please-end -->

Requirements: Kubernetes 1.30+, a CNI that enforces NetworkPolicy and a `ReadWriteOnce` StorageClass. Follow the
[installation guide](https://github.com/hgeorge123/netcheck/blob/main/docs/install.md) or the
[Amazon EKS guide](https://github.com/hgeorge123/netcheck/blob/main/docs/install-eks.md).

## Tags

| Tag | Meaning |
|---|---|
| `X.Y.Z` | A release (tags are immutable); see the [changelog](https://github.com/hgeorge123/netcheck/blob/main/CHANGELOG.md) |

Images are built for `linux/amd64` and `linux/arm64`. The same images, with the same digests, are on
`ghcr.io/hgeorge123/netcheck`.

## Verify the image

Every release is built by GitHub Actions, carries an SBOM and build provenance, and is signed with Sigstore:

<!-- x-release-please-start-version -->
```bash
cosign verify hgeorge123/netcheck:1.1.2 \
  --certificate-identity https://github.com/hgeorge123/netcheck/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
<!-- x-release-please-end -->

More in [verifying releases](https://github.com/hgeorge123/netcheck/blob/main/docs/security.md#10-verifying-releases).
