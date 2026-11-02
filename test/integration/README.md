# Integration tests

## 1. Local laboratory: kind + Calico

kind with its default CNI (`kindnet`) does **not** enforce NetworkPolicy. `kind/kind-config.yaml` disables the default
CNI and `lab.sh` installs Calico (pinned version), a local registry and the fixtures in `manifests/lab.yaml`:

| Namespace | Policies | Expected result |
|---|---|---|
| `nc-allow` | `podSelector: {}`: deny egress + DNS + TCP 8080 to `nc-target` | `echo.nc-target:8080`: DNS ok, TCP ok, HTTP 200; ping gets no reply (ICMP not allowed); fidelity `namespace-wide-likely` |
| `nc-deny` | `podSelector: {}`: deny egress + DNS; an **additive** policy for `app=legacy` → echo | DNS ok, TCP `timed_out`; fidelity `specific-selectors-detected` |
| `nc-open` | none | ping and traceroute to the echo Pod succeed; fidelity `no-native-egress-policies` |

The namespaces enforce Pod Security `restricted`, to show that the probe complies with the profile without exceptions
(ping and traceroute included, without `NET_RAW`). As in production, the chart creates **no** NetworkPolicy in the
`netcheck` namespace.

```bash
bash test/integration/lab.sh up        # registry + kind + Calico + fixtures
bash test/integration/lab.sh gateway   # optional: NGINX Gateway Fabric + HTTPS Gateway (netcheck.lab.test)
bash test/integration/lab.sh deploy    # build, push and helm upgrade --install by digest
kubectl --context kind-netcheck-lab -n netcheck port-forward svc/netcheck 8080:8080
# If the admin password was already changed, export NETCHECK_ADMIN_PASSWORD; otherwise it is read from the Secret.
NETCHECK_URL=http://127.0.0.1:8080 go test -tags integration -count=1 -v ./test/integration/...
bash test/integration/lab.sh down
```

`networkpolicy_test.go` (build tag `integration`) checks:

- the same destination is allowed from `nc-allow` and blocked from `nc-deny` (DNS keeps working);
- the fidelity notice;
- ping and traceroute **without privileges** from `nc-open`, and filtered ping with working TCP from `nc-allow`;
- per-check ports (TCP without a port, ping with a port and a disallowed port are rejected);
- `default`, `kube-system`, `netcheck` and `nc-target` are not offered; the `netcheck` namespace only with
  `allowNetcheckNamespace`;
- the per-user language, active sessions and the running version;
- rejection of the metadata destination (`169.254.169.254`);
- impersonating the controller ServiceAccount: a `hostNetwork` Job with an arbitrary image is rejected by the
  ValidatingAdmissionPolicy, and `pods/create`, `secrets/list` and Jobs in `kube-system` are `Forbidden`;
- users restricted to their namespaces and the dynamic "all namespaces" with new namespaces;
- cleanup of the probe Jobs.

The test refuses to run against an API server that is not local.

**Limitation:** Calico validates standard NetworkPolicy semantics, **not** the specifics of other CNIs such as the
Amazon VPC CNI.

## 2. Testing on Amazon EKS with the VPC CNI

Prerequisites:

1. A **non-production** EKS cluster.
2. The `vpc-cni` add-on with network policy enabled (`enableNetworkPolicy: "true"`) and the network policy agent
   running on the nodes. Without it no NetworkPolicy is enforced.
3. The same fixtures (`manifests/lab.yaml`), with the `agnhost` image reachable from the cluster.
4. NetCheck installed by digest following [docs/install-eks.md](../../docs/install-eks.md).

Measurements worth repeating on each new CNI or cluster before trusting the results:

- **Policy programming delay:** repeat the blocked test with `probe.settleSeconds` = 0, 1, 2 and 5 and check whether a
  freshly created probe sees allowed traffic before its policies are programmed (VPC CNI *standard* mode). Set
  `settleSeconds` from the data.
- **Security groups for Pods:** if workloads use them, document which security group the probe gets.
- **ICMP:** check ping and traceroute through security groups and NetworkPolicies.
