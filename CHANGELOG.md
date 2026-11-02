# Changelog

## [0.2.5](https://github.com/hgeorge123/netcheck/compare/v0.2.4...v0.2.5) (2026-11-02)


### Bug Fixes

* **deps:** build on Debian 13 (trixie) base images ([b58fb92](https://github.com/hgeorge123/netcheck/commit/b58fb923019e32b869b8063779e6f54a5f9bb847))
* **release:** block merging the release pull request until its images are pinned ([a11c835](https://github.com/hgeorge123/netcheck/commit/a11c835ef85220bae1979c8ca9238c483213657a))

## [0.2.4](https://github.com/hgeorge123/netcheck/compare/v0.2.3...v0.2.4) (2026-11-02)


### Bug Fixes

* **release:** pin the release images in the git tag ([d8a7ecc](https://github.com/hgeorge123/netcheck/commit/d8a7ecc4a4c3e1a94029013ba58b966594efd6ef))

## [0.2.3](https://github.com/hgeorge123/netcheck/compare/v0.2.2...v0.2.3) (2026-11-02)


### Bug Fixes

* **deps:** build with Go 1.27.3 and golang.org/x/net 0.62.0 ([8951ed1](https://github.com/hgeorge123/netcheck/commit/8951ed1787c1dbf8c71c3cc95b2aad3110b07f20))

## [0.2.2](https://github.com/hgeorge123/netcheck/compare/v0.2.1...v0.2.2) (2026-11-02)


### Bug Fixes

* **chart:** ship ready-to-use image values with every release ([9c52a3b](https://github.com/hgeorge123/netcheck/commit/9c52a3b784618bb294a6ba229b4165ffbb8da4d6))

## [0.2.1](https://github.com/hgeorge123/netcheck/compare/v0.2.0...v0.2.1) (2026-11-02)


### Bug Fixes

* **release:** publish the image repositories in the chart ([06b220f](https://github.com/hgeorge123/netcheck/commit/06b220fb787cae5d63a858f41e7d71cece669b79))

## [0.2.0](https://github.com/hgeorge123/netcheck/compare/v0.1.0...v0.2.0) (2026-11-02)


### Features

* add a firewall ticket mode with one combined date, hostname, ping, traceroute, telnet and curl output ([2d67649](https://github.com/hgeorge123/netcheck/commit/2d67649eb8ecf123264add42e6c1c88df4f5249f))
* add English and Spanish interface with the language stored per user ([2d67649](https://github.com/hgeorge123/netcheck/commit/2d67649eb8ecf123264add42e6c1c88df4f5249f))
* add local users with admin and user roles, per-user namespaces, lockout and mandatory password change ([2d67649](https://github.com/hgeorge123/netcheck/commit/2d67649eb8ecf123264add42e6c1c88df4f5249f))
* automate releases with signed images and charts ([2d67649](https://github.com/hgeorge123/netcheck/commit/2d67649eb8ecf123264add42e6c1c88df4f5249f))
* explain every result with a diagnosis, an equivalent command and a NetworkPolicy fidelity notice ([2d67649](https://github.com/hgeorge123/netcheck/commit/2d67649eb8ecf123264add42e6c1c88df4f5249f))
* manage destination policy, namespace exclusions and data retention from the web without redeploying ([2d67649](https://github.com/hgeorge123/netcheck/commit/2d67649eb8ecf123264add42e6c1c88df4f5249f))
* run DNS, TCP, HTTP, HTTPS, ping and traceroute checks from any allowed namespace using short-lived probe Jobs ([2d67649](https://github.com/hgeorge123/netcheck/commit/2d67649eb8ecf123264add42e6c1c88df4f5249f))
* ship a Helm chart with least-privilege RBAC, ValidatingAdmissionPolicies and Gateway API or ALB exposure ([2d67649](https://github.com/hgeorge123/netcheck/commit/2d67649eb8ecf123264add42e6c1c88df4f5249f))
