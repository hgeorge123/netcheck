# netcheck-cli: tests from pipelines

`netcheck-cli` runs a NetCheck test from a CI/CD pipeline or a terminal, waits for the result and exits with a code
your pipeline can act on. Typical use: before deploying an application, check that its namespace can reach the
database, the queue and the external APIs it needs, and stop the deployment if it cannot.

It uses an **API token** and the NetCheck API, so it needs no access to the Kubernetes cluster.

## 1. Get the CLI

Every [NetCheck release](https://github.com/hgeorge123/netcheck/releases) attaches the CLI for Linux, macOS and Windows
(amd64 and arm64), a checksums file and build provenance:

```bash
VERSION=0.5.0 # x-release-please-version
curl -fsSLO "https://github.com/hgeorge123/netcheck/releases/download/v${VERSION}/netcheck-cli_${VERSION}_linux_amd64"
curl -fsSLO "https://github.com/hgeorge123/netcheck/releases/download/v${VERSION}/netcheck-cli_${VERSION}_checksums.txt"
sha256sum --check --ignore-missing "netcheck-cli_${VERSION}_checksums.txt"
install -m 0755 "netcheck-cli_${VERSION}_linux_amd64" /usr/local/bin/netcheck-cli
netcheck-cli version
```

To verify that the binary was built by the NetCheck release workflow:

```bash
gh attestation verify "netcheck-cli_${VERSION}_linux_amd64" --owner hgeorge123
```

## 2. Create an API token

In NetCheck, open the **user menu → API tokens → Create token**, give it a name (for example *payments deploy
pipeline*) and an expiry (30 to 365 days). The token is shown **once**: store it in the secrets of your pipeline.

A token:

- acts **as you**: the same namespaces and the same destination policy;
- can only **run and read tests**: it cannot manage users, tokens or settings;
- stops working when it expires, when it is revoked, or when your account is disabled (or, for SSO accounts, loses its
  access rule).

Administrators see and revoke every token in **Administration → API tokens**. For a pipeline, consider a dedicated
NetCheck user that only has the namespaces the pipeline tests.

## 3. Configure

| Variable | Meaning |
|---|---|
| `NETCHECK_URL` | NetCheck address, for example `https://netcheck.example.com`. HTTPS is required (except `localhost`) |
| `NETCHECK_TOKEN` | The API token (`nck_…`). Pass it as a secret, never on the command line |
| `NETCHECK_CA_FILE` | Optional PEM bundle, when NetCheck uses a certificate from a private certificate authority |

## 4. Run a test

```bash
netcheck-cli run -n payments -t db.corp.example -c dns -c tcp:5432
```

```
NetCheck test a7adc451: payments -> db.corp.example
https://netcheck.example.com/#/runs/a7adc45133ba8fddb4c317d82542f954
  DNS       succeeded             3 ms     DNS resolution succeeded from the source Pod.
  TCP 5432  timed_out  10.30.5.8  5003 ms  Timed out without an answer.
Result: connectivity failures
```

The link opens the full result in NetCheck, with the path, the diagnosis and what is missing (a suggested
NetworkPolicy or a request for the firewall team).

| Flag | Meaning |
|---|---|
| `-n`, `--namespace` | Source namespace (one you are allowed to use) |
| `-t`, `--target` | Destination host name or IP |
| `-c`, `--check` | A check, repeatable (up to 7 per test), see below |
| `--timeout` | Seconds per check (default: the server default, 5) |
| `--wait` | Maximum time to wait for the result (default `5m`) |
| `--json` | Print the full result as JSON instead of the table |

Checks:

| Check | Meaning |
|---|---|
| `dns` | Resolve the target |
| `tcp:PORT` | Open a TCP connection |
| `udp:PORT` | Generic UDP port (an answer means open; silence is inconclusive) |
| `udp-dns[:PORT]` | A DNS server over UDP (default 53) |
| `udp-ntp[:PORT]` | An NTP server (default 123) |
| `http[:PORT][/PATH]` | HTTP GET (default port 80) |
| `https[:PORT][/PATH]` | HTTPS GET with certificate verification (default 443) |
| `ping[:COUNT]` | ICMP echo |
| `traceroute[:MAXHOPS]` | ICMP traceroute |

Other commands: `netcheck-cli namespaces` lists the namespaces you can test from, `netcheck-cli version` prints the
version.

## 5. Exit codes

| Code | Meaning | Typical pipeline action |
|---|---|---|
| `0` | Every check passed | Continue |
| `1` | Connectivity failures: the network blocked or did not answer | Stop the deployment |
| `2` | NetCheck could not run the test (infrastructure error, for example a full namespace quota), or `--wait` ran out | Retry or alert the platform team; it is not a network result |
| `3` | Usage, configuration, authentication or API error (bad flag, revoked token, destination denied by the policy…) | Fix the pipeline |

## 6. Examples

GitHub Actions:

```yaml
- name: Check connectivity before deploying
  env:
    NETCHECK_URL: https://netcheck.example.com
    NETCHECK_TOKEN: ${{ secrets.NETCHECK_TOKEN }}
  run: netcheck-cli run -n payments -t db.corp.example -c dns -c tcp:5432 -c https:443/health
```

GitLab CI:

```yaml
connectivity:
  stage: pre-deploy
  variables:
    NETCHECK_URL: https://netcheck.example.com
  script:
    - netcheck-cli run -n payments -t db.corp.example -c tcp:5432
```

(`NETCHECK_TOKEN` as a masked CI/CD variable.)

A JSON result for later processing:

```bash
netcheck-cli run -n payments -t api.partner.example -c https --json > netcheck-result.json
```
