<p align="center">
  <img src="https://raw.githubusercontent.com/hgeorge123/netcheck/main/docs/brand/netcheck-logo.png" alt="NetCheck" width="320">
</p>

This image is the **probe** of [NetCheck](https://hub.docker.com/r/hgeorge123/netcheck), a tool that runs network
connectivity checks from inside Kubernetes namespaces. For each test, NetCheck starts a short-lived Job with this image
in the namespace the user picked, reads the result through the Kubernetes API and deletes the Job.

- **Source code and documentation:** <https://github.com/hgeorge123/netcheck>
- **License:** Apache 2.0

## What it is

- A static Go binary on a distroless base, with **no shell** and no other tools. It runs no commands: it implements
  DNS, TCP, UDP, HTTP, HTTPS, ping and traceroute with Go primitives. UDP datagrams are fixed (empty, a DNS query
  or an NTP request), never user data.
- It runs as non-root (UID 65532), with a read-only root filesystem, no capabilities, no service account token and no
  cloud credentials. ICMP uses unprivileged ping sockets, so it needs no `NET_RAW`.
- It checks every resolved IP against the destination policy before connecting; the cloud metadata service and the
  Kubernetes API server are always denied.

## How to use it

You do not run this image yourself. The NetCheck Helm chart pins it by digest, and Kubernetes admission policies only
allow the NetCheck controller to create Jobs with exactly that image and a locked-down Pod template:

<!-- x-release-please-start-version -->
```bash
helm upgrade --install netcheck oci://ghcr.io/hgeorge123/charts/netcheck --version 0.5.0 \
  --namespace netcheck -f values.yaml
```
<!-- x-release-please-end -->

See the [installation guide](https://github.com/hgeorge123/netcheck/blob/main/docs/install.md) and the
[security model](https://github.com/hgeorge123/netcheck/blob/main/docs/security.md).

## Tags

| Tag | Meaning |
|---|---|
| `X.Y.Z` | A release (tags are immutable); see the [changelog](https://github.com/hgeorge123/netcheck/blob/main/CHANGELOG.md) |

Images are built for `linux/amd64` and `linux/arm64`. The same images, with the same digests, are on
`ghcr.io/hgeorge123/netcheck-probe`.

## Verify the image

<!-- x-release-please-start-version -->
```bash
cosign verify hgeorge123/netcheck-probe:0.5.0 \
  --certificate-identity https://github.com/hgeorge123/netcheck/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
<!-- x-release-please-end -->
