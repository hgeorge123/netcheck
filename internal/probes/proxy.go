package probes

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
)

// Proxy is an HTTP proxy a TCP, HTTP or HTTPS check may go through instead of
// the direct path; it is always optional and chosen per check. Administrators
// define shared proxies and every user may define personal ones.
type Proxy struct {
	// ID identifies a stored proxy; checks name it by ID (or by name).
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	// Personal marks a user's own proxy: only that user sees its details.
	Personal bool `json:"personal,omitempty"`
	// TrustedCAs are PEM authorities trusted only for HTTPS checks through
	// this proxy (for example the authority of a proxy that inspects TLS).
	TrustedCAs []string `json:"trustedCas,omitempty"`
}

// Limits of the proxies and of the authorities of each proxy.
const (
	MaxProxies         = 20
	MaxPersonalProxies = 10
	MaxProxyCAs        = 10
	MaxProxyCABytes    = 16 << 10
)

var proxyNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// Address is host:port of the proxy.
func (p Proxy) Address() string { return net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) }

// ProxyAllowed reports whether a check method may go through a proxy: TCP
// and HTTPS in a CONNECT tunnel, HTTP as a request forwarded by the proxy.
func ProxyAllowed(m Method) bool { return m == MethodTCP || m == MethodHTTP || m == MethodHTTPS }

// NormalizeProxies validates a list of proxies with distinct names and
// returns them normalized; never nil.
func NormalizeProxies(in []Proxy) ([]Proxy, error) {
	if len(in) > MaxProxies {
		return nil, fieldErr("proxies", "too_many_proxies", "at most %d proxies", MaxProxies)
	}
	out := make([]Proxy, 0, len(in))
	seen := map[string]bool{}
	for i, p := range in {
		field := fmt.Sprintf("proxies[%d]", i)
		n, err := NormalizeProxy(p)
		if err != nil {
			fe := err.(FieldError)
			fe.Field = field + "." + fe.Field
			return nil, fe
		}
		if seen[n.Name] {
			return nil, fieldErr(field+".name", "duplicate_proxy_name", "proxy %q is defined twice", n.Name)
		}
		seen[n.Name] = true
		out = append(out, n)
	}
	return out, nil
}

// NormalizeProxy validates one proxy: name, host, port and authorities (one
// PEM each afterwards). Errors name the field: name, host, port or
// certificates.
func NormalizeProxy(p Proxy) (Proxy, error) {
	if !proxyNamePattern.MatchString(p.Name) {
		return Proxy{}, fieldErr("name", "invalid_proxy_name", "the name must be 1-32 lowercase letters, digits or dashes")
	}
	t, err := ParseTarget(p.Host)
	if err != nil {
		return Proxy{}, fieldErr("host", "invalid_proxy_host", "the proxy host must be a host name or an IP address")
	}
	if err := ValidatePort(p.Port); err != nil {
		return Proxy{}, fieldErr("port", "invalid_port", "the proxy port must be between 1 and 65535")
	}
	cas, err := NormalizeTrustedCAs(p.TrustedCAs)
	if err != nil {
		fe := err.(FieldError)
		fe.Field = "certificates"
		return Proxy{}, fe
	}
	total := 0
	for _, c := range cas {
		total += len(c)
	}
	switch {
	case len(cas) > MaxProxyCAs:
		return Proxy{}, fieldErr("certificates", "too_many_certificates", "at most %d certificates per proxy", MaxProxyCAs)
	case total > MaxProxyCABytes:
		return Proxy{}, fieldErr("certificates", "certificates_too_large", "the certificates of a proxy take more than %d KiB", MaxProxyCABytes>>10)
	case len(cas) == 0:
		cas = nil
	}
	return Proxy{ID: p.ID, Name: p.Name, Host: t.Host, Port: p.Port, Personal: p.Personal, TrustedCAs: cas}, nil
}

func (p Proxy) equal(q Proxy) bool {
	return p.ID == q.ID && p.Name == q.Name && p.Host == q.Host && p.Port == q.Port && p.Personal == q.Personal &&
		slices.Equal(p.TrustedCAs, q.TrustedCAs)
}

// CheckProxy checks the proxy endpoint against the destination policy: the
// Pod connects to it, so it must be a destination users may reach.
func (c *CompiledPolicy) CheckProxy(p Proxy) error {
	t, err := ParseTarget(p.Host)
	if err != nil {
		return err
	}
	if err := c.CheckHost(t); err != nil {
		return proxyDenied(p, err)
	}
	if err := c.CheckPort(p.Port); err != nil {
		return proxyDenied(p, err)
	}
	return nil
}

func proxyDenied(p Proxy, err error) error {
	if de, ok := err.(*DeniedError); ok {
		return &DeniedError{Reason: fmt.Sprintf("proxy %s (%s): %s", p.Name, p.Address(), de.Reason)}
	}
	return err
}
