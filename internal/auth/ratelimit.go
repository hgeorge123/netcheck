package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// RateLimiter is a fixed-window counter per key (client IP).
type RateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]windowCount
	now    func() time.Time
}

type windowCount struct {
	start time.Time
	n     int
}

// NewRateLimiter allows limit events per window per key.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{limit: limit, window: window, hits: map[string]windowCount{}, now: time.Now}
}

// Allow records an event for key and reports whether it is within the limit.
func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.hits) > 10000 {
		for k, w := range l.hits {
			if now.Sub(w.start) > l.window {
				delete(l.hits, k)
			}
		}
	}
	w := l.hits[key]
	if now.Sub(w.start) > l.window {
		w = windowCount{start: now}
	}
	w.n++
	l.hits[key] = w
	return w.n <= l.limit
}

// ClientIP returns the caller IP. X-Forwarded-For is honoured only when the
// direct peer is a trusted proxy, walking the chain from the right and
// skipping trusted hops, so clients cannot spoof their address.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !isTrusted(peer, trusted) {
		return host
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !isTrusted(a, trusted) {
			return a.Unmap().String()
		}
	}
	return peer.Unmap().String()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
