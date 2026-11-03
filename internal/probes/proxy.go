package probes

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
)

// Proxy is an HTTP proxy defined by administrators. TCP and HTTPS checks may
// go through one (a CONNECT tunnel) instead of the direct path; it is always
// optional and chosen per check.
type Proxy struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// MaxProxies bounds the list of proxies.
const MaxProxies = 20

var proxyNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// Address is host:port of the proxy.
func (p Proxy) Address() string { return net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) }

// ProxyAllowed reports whether a check method may go through a proxy: only
// TCP and HTTPS, which a CONNECT tunnel carries as they are.
func ProxyAllowed(m Method) bool { return m == MethodTCP || m == MethodHTTPS }

// NormalizeProxies validates the proxies defined by administrators and
// returns them with lowercase host names; never nil.
func NormalizeProxies(in []Proxy) ([]Proxy, error) {
	if len(in) > MaxProxies {
		return nil, fieldErr("proxies", "too_many_proxies", "at most %d proxies", MaxProxies)
	}
	out := make([]Proxy, 0, len(in))
	seen := map[string]bool{}
	for i, p := range in {
		field := fmt.Sprintf("proxies[%d]", i)
		n, err := normalizeProxy(p)
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

func normalizeProxy(p Proxy) (Proxy, error) {
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
	return Proxy{Name: p.Name, Host: t.Host, Port: p.Port}, nil
}

// checkProxy checks the proxy endpoint against the destination policy: the
// Pod connects to it, so it must be a destination users may reach.
func (c *CompiledPolicy) checkProxy(p Proxy) error {
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
