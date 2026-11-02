package diagnostics

import "fmt"

// Severity values map to UI status indicators.
const (
	SeveritySuccess = "success"
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"
)

// Diagnosis is an orientative interpretation of one check. It never claims a
// specific cause (e.g. "this NetworkPolicy blocked you") without evidence.
// Summary/Detail are English for API consumers; the UI translates by
// Category (and HTTPStatus).
type Diagnosis struct {
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Summary    string `json:"summary"`
	Detail     string `json:"detail"`
	Conclusive bool   `json:"conclusive"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
}

type text struct{ summary, detail string }

var texts = map[string]text{
	CategoryDestinationDenied:    {"Destination denied by the NetCheck policy.", "No traffic was sent. This is a platform policy decision, not a network result."},
	CategoryDNSNXDomain:          {"DNS: the name does not exist (NXDOMAIN).", "A resolution problem (name, search domain or zone). It does not indicate a NetworkPolicy block by itself."},
	CategoryDNSServFail:          {"DNS: the server returned an error (SERVFAIL/REFUSED).", "The resolver answered but could not resolve. Check CoreDNS, forwarders or the authoritative zone."},
	CategoryDNSTimeout:           {"DNS: timed out waiting for the resolver.", "A policy blocking egress to DNS (UDP/TCP 53), a degraded CoreDNS or filtering. Cause undetermined."},
	CategoryDNSNoAddress:         {"DNS: the name exists but has no address of the requested family.", "Check the A/AAAA records and the selected IPv4/IPv6 family."},
	CategoryDNSError:             {"DNS: resolution error.", ""},
	CategoryTCPRefused:           {"Connection refused (RST).", "The packet reached a stack that refused it: check there is a listener on that port or the Service endpoints. Some policies or firewalls also reject."},
	CategoryTimeout:              {"Timed out without an answer.", "Undetermined cause: NetworkPolicy (source or destination), Security Groups, NACLs, routes, the destination Pod or filtering on the path. A timeout alone does not prove a NetworkPolicy block."},
	CategoryNoRoute:              {"No route to host.", "The network stack reported the host as unreachable (EHOSTUNREACH)."},
	CategoryNetUnreachable:       {"Network unreachable.", "There is no route to that network from the source Pod (ENETUNREACH). Check the IPv4/IPv6 family and routes."},
	CategoryConnReset:            {"Connection reset by the peer.", "A stack that cut the connection was reached: the application, a proxy or a middlebox."},
	CategoryTLSCert:              {"TLS: the certificate is not valid for this destination.", "Trust, name (SAN) or chain failure. TCP connectivity exists; this is not a network block."},
	CategoryTLSHandshake:         {"TLS: handshake failed.", "TCP connected but TLS negotiation failed (version, cipher, SNI, or the port does not speak TLS)."},
	CategoryHTTPProtocol:         {"HTTP: invalid response.", "TCP connected but the answer is not valid HTTP; the port may speak another protocol (or HTTPS)."},
	CategoryUDPPortClosed:        {"UDP port closed (ICMP port unreachable).", "The datagram reached the destination host, which answered that nothing listens on that port. The network path is not blocked."},
	CategoryUDPNoReply:           {"No UDP reply: inconclusive.", "UDP has no handshake: many services ignore unexpected datagrams and firewalls usually drop them silently, so the port may be open or filtered. Use the DNS or NTP mode when the service supports it."},
	CategoryUDPUnexpected:        {"Something answered on this UDP port, but not with the expected protocol.", "The UDP path to the port is open; the service is not the expected DNS or NTP server."},
	CategoryICMPNoReply:          {"No ICMP echo reply.", "ICMP is often filtered (NetworkPolicies, Security Groups, firewalls) even when TCP works. Not conclusive for TCP/HTTP traffic."},
	CategoryICMPUnreachable:      {"ICMP destination unreachable.", "A router or the destination answered that it cannot deliver the packet (code shown in the details)."},
	CategoryICMPNotPermitted:     {"ICMP is not permitted inside the probe.", "The node did not allow unprivileged ICMP sockets (net.ipv4.ping_group_range). This is a platform issue, not a network result."},
	CategoryTracerouteIncomplete: {"Traceroute did not reach the destination.", "Hops shown as * did not answer; that does not prove loss. Firewalls and NetworkPolicies often drop ICMP while allowing TCP."},
	CategoryAdmissionRejected:    {"The cluster refused to create the probe.", "Admission (Pod Security, ValidatingAdmissionPolicy, ResourceQuota or LimitRange) rejected the Job. Not a network result."},
	CategoryInfraError:           {"NetCheck infrastructure error.", "The probe could not run or returned no result. Not a network result."},
	CategoryProbeOutputInvalid:   {"The probe did not return a valid structured result.", "Not a network result. Check the probe logs and image version."},
}

// Diagnose interprets a check outcome. httpStatus is only used for HTTP(S).
func Diagnose(method, category string, httpStatus int) Diagnosis {
	d := Diagnosis{Category: category, Severity: SeverityError}
	switch category {
	case CategoryOK:
		d.Severity = SeveritySuccess
		switch method {
		case "dns":
			d.Summary, d.Detail = "DNS resolution succeeded from the source Pod.", "The Pod resolver returned addresses. It does not guarantee the destination accepts connections."
		case "tcp":
			d.Summary, d.Detail = "TCP connection established.", "The TCP path is open for this Pod and port. It does not guarantee the application is healthy."
		case "udp":
			d.Summary, d.Detail = "The destination answered over UDP.", "The UDP path to this port is open and a service replied."
		case "ping":
			d.Summary, d.Detail = "All ICMP echo requests were answered.", "ICMP reachability only; TCP ports may still be filtered."
		case "traceroute":
			d.Summary, d.Detail = "Traceroute reached the destination.", "Path observed with ICMP; TCP traffic may take other paths or be filtered."
		default:
			d.Summary = "Check succeeded."
		}
		return d
	case CategoryHTTPResponse:
		return diagnoseHTTP(httpStatus)
	case CategoryICMPPartialLoss:
		d.Severity = SeverityWarning
		d.Summary, d.Detail = "Some ICMP echo requests were not answered.", "Partial loss or ICMP rate limiting on the path. Reachability exists."
		return d
	}
	t, ok := texts[category]
	if !ok {
		d.Summary = "Unclassified error."
		return d
	}
	d.Summary, d.Detail = t.summary, t.detail
	switch category {
	case CategoryDestinationDenied, CategoryInfraError, CategoryProbeOutputInvalid, CategoryICMPNotPermitted, CategoryTracerouteIncomplete,
		CategoryUDPNoReply, CategoryUDPUnexpected:
		d.Severity = SeverityWarning
	}
	d.Conclusive = category == CategoryDestinationDenied || category == CategoryAdmissionRejected
	return d
}

func diagnoseHTTP(code int) Diagnosis {
	d := Diagnosis{Category: CategoryHTTPResponse, HTTPStatus: code}
	d.Summary = fmt.Sprintf("HTTP answered %d: network and HTTP connectivity are established.", code)
	switch {
	case code >= 200 && code < 300:
		d.Severity = SeveritySuccess
	case code >= 300 && code < 400:
		d.Severity = SeverityInfo
		d.Detail = "Redirect not followed by design; check the Location header."
	case code == 401 || code == 403:
		d.Severity = SeverityWarning
		d.Detail = "Application authentication or authorization problem, not a network one."
	case code == 404:
		d.Severity = SeverityWarning
		d.Detail = "Path not found in the application; check the path or virtual host."
	case code >= 400 && code < 500:
		d.Severity = SeverityWarning
		d.Detail = "Application request error."
	case code >= 500:
		d.Severity = SeverityWarning
		d.Detail = "Server or intermediate proxy error (e.g. 502/503/504 from a load balancer)."
	default:
		d.Severity = SeverityInfo
	}
	return d
}
