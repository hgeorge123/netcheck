// Package probes defines the fixed probe catalog, the immutable spec sent to
// the probe Job and the structured result contract shared by the controller
// and the probe runner.
package probes

import "time"

const (
	// SchemaVersion identifies the spec/result contract between controller and probe.
	SchemaVersion = "netcheck.probe/v2"
	// ResultPrefix marks the final structured line printed by the probe on stdout.
	ResultPrefix = "NETCHECK_RESULT "
	// SpecEnvVar carries the JSON spec into the probe container.
	SpecEnvVar = "NETCHECK_SPEC"
)

// Method is a probe method from the fixed allowlist catalog.
type Method string

const (
	MethodDNS        Method = "dns"
	MethodTCP        Method = "tcp"
	MethodHTTP       Method = "http"
	MethodHTTPS      Method = "https"
	MethodPing       Method = "ping"
	MethodTraceroute Method = "traceroute"
)

// Check status values reported by the probe for each check.
const (
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusTimedOut  = "timed_out"
)

// Target is a single validated destination: a canonical IP literal (no
// brackets, no zone) or a lowercase hostname without trailing dot.
type Target struct {
	Raw  string `json:"raw"`
	Host string `json:"host"`
	IsIP bool   `json:"isIp"`
}

// DNSOptions configures the DNS check.
type DNSOptions struct {
	// Family selects the address family requested: "ip" (both), "ip4" or "ip6".
	Family string `json:"family"`
}

// HTTPOptions configures HTTP and HTTPS checks. No custom headers or bodies
// are supported by design.
type HTTPOptions struct {
	Method string `json:"method"` // GET or HEAD
	Path   string `json:"path"`
}

// PingOptions configures the ICMP echo check.
type PingOptions struct {
	Count int `json:"count"`
}

// TracerouteOptions configures the ICMP traceroute check.
type TracerouteOptions struct {
	MaxHops int `json:"maxHops"`
}

// Check is one entry of the batch, executed sequentially by the probe.
type Check struct {
	ID         string             `json:"id"`
	Method     Method             `json:"method"`
	TimeoutMS  int                `json:"timeoutMs"`
	Port       int                `json:"port,omitempty"`
	DNS        *DNSOptions        `json:"dns,omitempty"`
	HTTP       *HTTPOptions       `json:"http,omitempty"`
	Ping       *PingOptions       `json:"ping,omitempty"`
	Traceroute *TracerouteOptions `json:"traceroute,omitempty"`
}

// Spec is the immutable description of a run. It is built and validated by
// the API and validated again by the probe before executing anything.
type Spec struct {
	SchemaVersion  string            `json:"schemaVersion"`
	RunID          string            `json:"runId"`
	Target         Target            `json:"target"`
	Checks         []Check           `json:"checks"`
	Policy         DestinationPolicy `json:"policy"`
	MaxOutputBytes int               `json:"maxOutputBytes"`
	SettleMS       int               `json:"settleMs"`
}

// SourceInfo describes where the probe actually ran.
type SourceInfo struct {
	Namespace string `json:"namespace"`
	PodName   string `json:"podName"`
	PodIP     string `json:"podIp"`
	NodeName  string `json:"nodeName"`
	// SATokenMounted reports whether a Kubernetes service account token was
	// found in the probe filesystem. It must always be false.
	SATokenMounted bool `json:"saTokenMounted"`
	// CloudCredentialsHint reports whether IRSA / EKS Pod Identity tokens or
	// AWS credential environment variables were injected. It must be false.
	CloudCredentialsHint bool `json:"cloudCredentialsHint"`
}

// ResolverInfo is the resolver configuration observed inside the probe Pod.
type ResolverInfo struct {
	Nameservers []string `json:"nameservers,omitempty"`
	Search      []string `json:"search,omitempty"`
	Ndots       int      `json:"ndots,omitempty"`
}

// Result is the structured document printed by the probe as its last line.
type Result struct {
	SchemaVersion string        `json:"schemaVersion"`
	RunID         string        `json:"runId"`
	Source        SourceInfo    `json:"source"`
	Resolver      ResolverInfo  `json:"resolver"`
	SettledMS     int           `json:"settledMs"`
	Checks        []CheckResult `json:"checks"`
	Error         string        `json:"error,omitempty"`
}

// CheckResult is the normalized outcome of a single check.
type CheckResult struct {
	ID          string            `json:"id"`
	Method      Method            `json:"method"`
	Status      string            `json:"status"`
	Category    string            `json:"category"`
	StartedAt   time.Time         `json:"startedAt"`
	FinishedAt  time.Time         `json:"finishedAt"`
	DurationMS  int64             `json:"durationMs"`
	ResolvedIPs []string          `json:"resolvedIps,omitempty"`
	DeniedIPs   []string          `json:"deniedIps,omitempty"`
	UsedIP      string            `json:"usedIp,omitempty"`
	Port        int               `json:"port,omitempty"`
	Error       string            `json:"error,omitempty"`
	Output      string            `json:"output,omitempty"`
	Truncated   bool              `json:"truncated,omitempty"`
	Equivalent  []string          `json:"equivalentArgv,omitempty"`
	DNS         *DNSResult        `json:"dns,omitempty"`
	HTTP        *HTTPResult       `json:"http,omitempty"`
	Ping        *PingResult       `json:"ping,omitempty"`
	Traceroute  *TracerouteResult `json:"traceroute,omitempty"`
}

// DNSResult holds DNS specific evidence.
type DNSResult struct {
	CNAME     string   `json:"cname,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Family    string   `json:"family"`
}

// HTTPResult holds HTTP specific evidence.
type HTTPResult struct {
	URL           string `json:"url"`
	Method        string `json:"method"`
	StatusCode    int    `json:"statusCode,omitempty"`
	Proto         string `json:"proto,omitempty"`
	Location      string `json:"location,omitempty"`
	TLSVersion    string `json:"tlsVersion,omitempty"`
	TLSPeerCN     string `json:"tlsPeerCn,omitempty"`
	TLSNotAfter   string `json:"tlsNotAfter,omitempty"`
	ConnectMS     int64  `json:"connectMs,omitempty"`
	TLSMS         int64  `json:"tlsMs,omitempty"`
	FirstByteMS   int64  `json:"firstByteMs,omitempty"`
	BodyBytes     int64  `json:"bodyBytes,omitempty"`
	BodyTruncated bool   `json:"bodyTruncated,omitempty"`
}

// PingReply is one ICMP echo exchange.
type PingReply struct {
	Seq     int     `json:"seq"`
	RTTMS   float64 `json:"rttMs,omitempty"`
	Lost    bool    `json:"lost,omitempty"`
	ErrFrom string  `json:"errorFrom,omitempty"` // router that answered with an ICMP error
	ErrText string  `json:"error,omitempty"`
}

// PingResult holds ICMP echo statistics.
type PingResult struct {
	Transmitted int         `json:"transmitted"`
	Received    int         `json:"received"`
	LossPercent float64     `json:"lossPercent"`
	MinMS       float64     `json:"minMs,omitempty"`
	AvgMS       float64     `json:"avgMs,omitempty"`
	MaxMS       float64     `json:"maxMs,omitempty"`
	Replies     []PingReply `json:"replies"`
}

// TracerouteHop is one TTL step. Address is empty when nothing answered.
type TracerouteHop struct {
	TTL     int     `json:"ttl"`
	Address string  `json:"address,omitempty"`
	RTTMS   float64 `json:"rttMs,omitempty"`
	Note    string  `json:"note,omitempty"` // e.g. "destination unreachable (code 13)"
}

// TracerouteResult holds the observed path.
type TracerouteResult struct {
	Protocol string          `json:"protocol"` // icmp
	MaxHops  int             `json:"maxHops"`
	Reached  bool            `json:"reached"`
	Hops     []TracerouteHop `json:"hops"`
}
