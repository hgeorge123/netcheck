# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-02

First public release.

### Added

- Network checks from any allowed source namespace using short-lived probe Jobs: DNS, TCP, HTTP, HTTPS, ping and
  traceroute (ICMP without privileges through ping sockets).
- Firewall ticket troubleshooting mode: one combined output of `date`, `hostname`, `ping`, `traceroute`, `telnet` and
  `curl -v` with measured values, plus the probe Pod and node IPs.
- Diagnosis of each check with an equivalent command, detailed timings and a NetworkPolicy fidelity notice.
- Local users with `admin` and `user` roles, per-user namespaces (fixed list or dynamic "all"), argon2id passwords,
  account lockout, rate limiting and mandatory change of temporary passwords.
- Administration pages: users, active sessions, namespaces (web exclusions), destination policy, data retention, and
  system and versions with the version history.
- Destination policy editable in the web, with platform protections (cloud metadata, API server, loopback,
  link-local) that cannot be removed from the web.
- Data retention editable in the web (`retention.*` values are the initial setting).
- English and Spanish interface; the language is stored per user.
- Helm chart with values validation, cluster preflight checks, least-privilege RBAC (`all` or `list` mode), two
  `ValidatingAdmissionPolicies`, optional NetworkPolicy for the NetCheck namespace, and exposure through a Gateway API
  `HTTPRoute` or an AWS Load Balancer Controller `Ingress`.
- Multi-architecture images (`amd64`, `arm64`) on Docker Hub and GitHub Container Registry, and the chart as an
  OCI artifact. Each published chart version points to the images of its release by digest, so no image values are
  needed to install it.
- Local kind + Calico laboratory and integration tests.

[Unreleased]: https://github.com/hgeorge123/netcheck/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hgeorge123/netcheck/releases/tag/v0.2.0
