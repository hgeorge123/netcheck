package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hgeorge123/netcheck/internal/probes"
)

// runRequest is the body of POST /api/v1/runs.
type runRequest struct {
	Namespace      string                `json:"namespace"`
	Target         string                `json:"target"`
	TimeoutSeconds int                   `json:"timeoutSeconds,omitempty"`
	Checks         []probes.CheckRequest `json:"checks"`
}

func number(name, v string, min, max int) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be a number from %d to %d, got %q", name, min, max, v)
	}
	return n, nil
}

// parseCheck turns "tcp:5432", "https:8443/health", "udp-dns" ... into a
// check request. The server validates it again.
func parseCheck(s string) (probes.CheckRequest, error) {
	s = strings.TrimSpace(s)
	spec, path := s, ""
	// http[:PORT][/PATH]: split the path off before reading the port.
	if strings.HasPrefix(s, "http") {
		if i := strings.Index(s, "/"); i >= 0 {
			spec, path = s[:i], s[i:]
		}
	}
	kind, rest, _ := strings.Cut(spec, ":")
	port := func(def int, required bool) (int, error) {
		if rest == "" {
			if required {
				return 0, fmt.Errorf("check %q needs a port, e.g. %s:443", s, kind)
			}
			return def, nil
		}
		return number("the port of "+s, rest, 1, 65535)
	}
	var c probes.CheckRequest
	var err error
	switch kind {
	case "dns":
		if rest != "" {
			return c, fmt.Errorf("check %q: dns takes no port", s)
		}
		c = probes.CheckRequest{Method: probes.MethodDNS}
	case "tcp":
		c = probes.CheckRequest{Method: probes.MethodTCP}
		c.Port, err = port(0, true)
	case "udp", "udp-dns", "udp-ntp":
		proto, def, required := probes.UDPGeneric, 0, true
		if kind == "udp-dns" {
			proto, def, required = probes.UDPDNS, 53, false
		} else if kind == "udp-ntp" {
			proto, def, required = probes.UDPNTP, 123, false
		}
		c = probes.CheckRequest{Method: probes.MethodUDP, UDP: &probes.UDPOptions{Protocol: proto}}
		c.Port, err = port(def, required)
	case "http", "https":
		def := 80
		if kind == "https" {
			def = 443
		}
		c = probes.CheckRequest{Method: probes.Method(kind)}
		c.Port, err = port(def, false)
		if path != "" {
			c.HTTP = &probes.HTTPOptions{Method: "GET", Path: path}
		}
	case "ping":
		c = probes.CheckRequest{Method: probes.MethodPing}
		if rest != "" {
			n, perr := number("the ping count", rest, 1, 10)
			c.Ping, err = &probes.PingOptions{Count: n}, perr
		}
	case "traceroute":
		c = probes.CheckRequest{Method: probes.MethodTraceroute}
		if rest != "" {
			n, perr := number("the traceroute hops", rest, 1, 30)
			c.Traceroute, err = &probes.TracerouteOptions{MaxHops: n}, perr
		}
	default:
		return c, fmt.Errorf("unknown check %q (dns, tcp, udp, udp-dns, udp-ntp, http, https, ping or traceroute)", s)
	}
	return c, err
}
