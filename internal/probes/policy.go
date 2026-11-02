package probes

import (
	"fmt"
	"net/netip"
	"strings"
)

// BuiltinDenyCIDRs are always denied, regardless of configuration. The
// config loader merges them into every policy; they cannot be removed.
var BuiltinDenyCIDRs = []string{
	"0.0.0.0/8",              // "this" network
	"127.0.0.0/8",            // loopback
	"169.254.0.0/16",         // link-local, includes cloud metadata 169.254.169.254
	"224.0.0.0/4",            // multicast
	"240.0.0.0/4",            // reserved + broadcast
	"::/128",                 // unspecified
	"::1/128",                // loopback
	"fe80::/10",              // link-local
	"ff00::/8",               // multicast
	"fd00:ec2::254/128",      // AWS IMDS over IPv6
	"64:ff9b::a9fe:a9fe/128", // NAT64 form of 169.254.169.254
}

// PortRange is an inclusive range of allowed TCP ports.
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// DestinationPolicy is the serializable destination allowlist. Deny always
// wins over allow; an empty allowlist denies everything.
type DestinationPolicy struct {
	AllowCIDRs            []string    `json:"allowCidrs"`
	DenyCIDRs             []string    `json:"denyCidrs"`
	AllowHostnameSuffixes []string    `json:"allowHostnameSuffixes"`
	AllowPorts            []PortRange `json:"allowPorts"`
}

// DeniedError reports a destination rejected by policy. It is a policy
// decision, never a network result.
type DeniedError struct {
	Reason string
}

func (e *DeniedError) Error() string { return "destination denied by policy: " + e.Reason }

// CompiledPolicy is a parsed DestinationPolicy ready for evaluation.
type CompiledPolicy struct {
	allow    []netip.Prefix
	deny     []netip.Prefix
	suffixes []string
	anyHost  bool
	ports    []PortRange
}

// Compile parses and validates the policy.
func (p DestinationPolicy) Compile() (*CompiledPolicy, error) {
	c := &CompiledPolicy{}
	var err error
	if c.allow, err = parsePrefixes(p.AllowCIDRs); err != nil {
		return nil, fmt.Errorf("allowCidrs: %w", err)
	}
	if c.deny, err = parsePrefixes(p.DenyCIDRs); err != nil {
		return nil, fmt.Errorf("denyCidrs: %w", err)
	}
	for _, s := range p.AllowHostnameSuffixes {
		s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
		if s == "*" {
			c.anyHost = true
			continue
		}
		if _, err := normalizeHostname(strings.TrimPrefix(s, ".")); err != nil || s == "" {
			return nil, fmt.Errorf("allowHostnameSuffixes: invalid suffix %q", s)
		}
		c.suffixes = append(c.suffixes, s)
	}
	for _, r := range p.AllowPorts {
		if r.From < 1 || r.To > 65535 || r.From > r.To {
			return nil, fmt.Errorf("allowPorts: invalid range %d-%d", r.From, r.To)
		}
		c.ports = append(c.ports, r)
	}
	return c, nil
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", s)
		}
		if pfx.Addr().Is4In6() {
			return nil, fmt.Errorf("IPv4-mapped CIDR %q not supported, use the IPv4 form", s)
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

// WithBuiltinDenies returns a copy of p with BuiltinDenyCIDRs and extra
// denies appended (deduplicated).
func (p DestinationPolicy) WithBuiltinDenies(extra ...string) DestinationPolicy {
	return p.WithDenies(append(append([]string(nil), BuiltinDenyCIDRs...), extra...)...)
}

// WithDenies returns a copy of p with the given denies appended (deduplicated).
func (p DestinationPolicy) WithDenies(extra ...string) DestinationPolicy {
	seen := map[string]bool{}
	var deny []string
	for _, list := range [][]string{p.DenyCIDRs, extra} {
		for _, s := range list {
			if s != "" && !seen[s] {
				seen[s] = true
				deny = append(deny, s)
			}
		}
	}
	p.DenyCIDRs = deny
	return p
}

// CheckIP evaluates a concrete destination address. IPv4-mapped IPv6
// addresses are unmapped first so ::ffff:169.254.169.254 cannot bypass denies.
func (c *CompiledPolicy) CheckIP(addr netip.Addr) error {
	if !addr.IsValid() {
		return &DeniedError{Reason: "invalid address"}
	}
	if addr.Zone() != "" {
		return &DeniedError{Reason: "IPv6 zones are not allowed"}
	}
	addr = addr.Unmap()
	for _, p := range c.deny {
		if p.Contains(addr) {
			return &DeniedError{Reason: fmt.Sprintf("%s is in denied range %s", addr, p)}
		}
	}
	for _, p := range c.allow {
		if p.Contains(addr) {
			return nil
		}
	}
	return &DeniedError{Reason: fmt.Sprintf("%s is not in any allowed range", addr)}
}

// CheckHostname evaluates a normalized hostname against the suffix allowlist.
// Passing this check only allows resolution; every resolved IP must still
// pass CheckIP before connecting.
func (c *CompiledPolicy) CheckHostname(host string) error {
	if c.anyHost {
		return nil
	}
	for _, s := range c.suffixes {
		if strings.HasPrefix(s, ".") {
			if strings.HasSuffix(host, s) {
				return nil
			}
			continue
		}
		if host == s || strings.HasSuffix(host, "."+s) {
			return nil
		}
	}
	return &DeniedError{Reason: fmt.Sprintf("hostname %q does not match any allowed suffix", host)}
}

// CheckPort evaluates a destination port.
func (c *CompiledPolicy) CheckPort(port int) error {
	for _, r := range c.ports {
		if port >= r.From && port <= r.To {
			return nil
		}
	}
	return &DeniedError{Reason: fmt.Sprintf("port %d is not allowed", port)}
}

// CheckHost dispatches to CheckIP or CheckHostname depending on the target.
func (c *CompiledPolicy) CheckHost(t Target) error {
	if t.IsIP {
		addr, err := netip.ParseAddr(t.Host)
		if err != nil {
			return &DeniedError{Reason: "invalid address"}
		}
		return c.CheckIP(addr)
	}
	return c.CheckHostname(t.Host)
}
