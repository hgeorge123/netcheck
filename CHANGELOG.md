# Changelog

## [1.1.0](https://github.com/hgeorge123/netcheck/compare/v1.0.3...v1.1.0) (2026-11-03)


### Features

* optional HTTP proxy for TCP and HTTPS checks ([2075a36](https://github.com/hgeorge123/netcheck/commit/2075a363143306714e07dfaae48d7a320d3d7b21))
* trust corporate certificate authorities in HTTPS checks ([a3091b6](https://github.com/hgeorge123/netcheck/commit/a3091b6b126e2955dfb905fe0f7704e1b3826d0f))


### Documentation

* mention trusted certificate authorities and proxies in the feature summaries ([4234751](https://github.com/hgeorge123/netcheck/commit/423475171d5426baa56486c8db876c47507b7215))

## [1.0.3](https://github.com/hgeorge123/netcheck/compare/v1.0.2...v1.0.3) (2026-11-03)


### Bug Fixes

* **auth:** warn when the bootstrap Secret no longer matches the initial admin ([85c5bf8](https://github.com/hgeorge123/netcheck/commit/85c5bf89cadfcf9e20f990e0e02a753971246011))

## [1.0.2](https://github.com/hgeorge123/netcheck/compare/v1.0.1...v1.0.2) (2026-11-03)


### Bug Fixes

* **ui:** edit access rules without sending read-only fields ([4a876f0](https://github.com/hgeorge123/netcheck/commit/4a876f0d750ef8b0e8e3283d4933676d0c3cb5f0))

## [1.0.1](https://github.com/hgeorge123/netcheck/compare/v1.0.0...v1.0.1) (2026-11-03)


### Documentation

* list every feature with a link to how to use it ([457a61b](https://github.com/hgeorge123/netcheck/commit/457a61bf620d45afbdc601ec8c3ff1853f2063aa))

## [1.0.0](https://github.com/hgeorge123/netcheck/compare/v0.7.0...v1.0.0) (2026-11-03)


### Features

* **probe:** explain certificate problems and allow ignoring them for HTTPS ([03b5930](https://github.com/hgeorge123/netcheck/commit/03b5930853802bb4193be6717f1d44670d47314a))


### Miscellaneous

* release 1.0.0 ([1d3d764](https://github.com/hgeorge123/netcheck/commit/1d3d76433b045fb8dd50c1b94cd13d4c300b11a5))

## [0.7.0](https://github.com/hgeorge123/netcheck/compare/v0.6.0...v0.7.0) (2026-11-03)


### Features

* **chart:** expose NetCheck with any Ingress controller and document AKS ([8465fea](https://github.com/hgeorge123/netcheck/commit/8465fea46ff07f7e52545be43b590b0f690ac72f))

## [0.6.0](https://github.com/hgeorge123/netcheck/compare/v0.5.0...v0.6.0) (2026-11-03)


### Features

* API tokens and netcheck-cli to run tests from pipelines ([7506337](https://github.com/hgeorge123/netcheck/commit/7506337d809e535e455071af16e5e87b3d805def))
* **auth:** sign in with OpenID Connect and grant access with rules ([3efdf41](https://github.com/hgeorge123/netcheck/commit/3efdf41b9d1eed23db58d1fa3cafb09a6dcc7acc))
* **chart:** configure single sign-on and bundle Dex for GitHub, LDAP or SAML ([03a2bd2](https://github.com/hgeorge123/netcheck/commit/03a2bd2ac7171f1b427071211621b384d1729e7d))
* **ui:** show the measured path and what is missing for a blocked test ([4c36de2](https://github.com/hgeorge123/netcheck/commit/4c36de202304b66be7d7b1fbaa872cc64f0fbfe3))
* **ui:** sign in with single sign-on and manage access rules ([2fed08c](https://github.com/hgeorge123/netcheck/commit/2fed08c92206b0d9c09fa374e01adc0ac9100373))


### Bug Fixes

* **deps:** update go-jose to v4.1.6 ([ad8956d](https://github.com/hgeorge123/netcheck/commit/ad8956daf5d4b3cb9f2e740c45866bba7dfc5892))


### Documentation

* single sign-on with LDAP or Active Directory, tested in the lab ([140b770](https://github.com/hgeorge123/netcheck/commit/140b77056a4af05c6bff6735bff462eb0571020d))
* single sign-on, access rules, API tokens and netcheck-cli ([ca8fc7c](https://github.com/hgeorge123/netcheck/commit/ca8fc7c108526647cd4053f4133feb9b7e8d7e0a))

## [0.5.0](https://github.com/hgeorge123/netcheck/compare/v0.4.1...v0.5.0) (2026-11-02)


### Features

* check namespace quotas before starting the probe ([07fbde8](https://github.com/hgeorge123/netcheck/commit/07fbde85eb2fea01bf83fa374a60d02ff25bbdbf))


### Bug Fixes

* **probe:** accept a slow UDP reply to an earlier datagram ([8e16153](https://github.com/hgeorge123/netcheck/commit/8e161536beb4e9573e7febc8bca20a1e03c37aac))
* **ui:** round the UDP reply time ([2c11b99](https://github.com/hgeorge123/netcheck/commit/2c11b991ffdfd4fb8671aa09ee8b2d51c3288091))


### Documentation

* refresh the screenshots and show the UDP check ([2796136](https://github.com/hgeorge123/netcheck/commit/27961365a9b0945976d5ac79c3b2e384ec3970b1))

## [0.4.1](https://github.com/hgeorge123/netcheck/compare/v0.4.0...v0.4.1) (2026-11-02)


### Documentation

* draw the architecture and the life of a test as diagrams ([f970bcc](https://github.com/hgeorge123/netcheck/commit/f970bcc226d156e5751442d5af0381daf824f627))
* replace the component diagram with a static image ([c49158c](https://github.com/hgeorge123/netcheck/commit/c49158c2126c43fc80a11aef9b05b25e15b21be3))

## [0.4.0](https://github.com/hgeorge123/netcheck/compare/v0.3.0...v0.4.0) (2026-11-02)


### Features

* make the log level configurable ([0d81fd5](https://github.com/hgeorge123/netcheck/commit/0d81fd5017514a412ff1715f496dbcff258a454a))

## [0.3.0](https://github.com/hgeorge123/netcheck/compare/v0.2.5...v0.3.0) (2026-11-02)


### Features

* add UDP checks for generic ports, DNS servers and NTP servers ([3e5c12b](https://github.com/hgeorge123/netcheck/commit/3e5c12b2a31f277bf68e4beea5626a3ae049879a))
* **chart:** generate the initial admin password on new installs ([95c6926](https://github.com/hgeorge123/netcheck/commit/95c6926206d7bd3065c410289a214e91ff87880a))
* **ui:** show the language selector in the top-right corner of the sign-in page ([3e5c12b](https://github.com/hgeorge123/netcheck/commit/3e5c12b2a31f277bf68e4beea5626a3ae049879a))

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
