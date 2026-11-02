// Package scheduler enforces concurrency limits and drives the run
// lifecycle: create Job, observe, collect, persist, clean up, recover.
package scheduler

import "sync"

// Limiter bounds concurrent probe Jobs per namespace and globally.
type Limiter struct {
	mu     sync.Mutex
	perNS  int
	global int
	counts map[string]int
	total  int
}

// NewLimiter returns a Limiter with the given bounds.
func NewLimiter(perNamespace, global int) *Limiter {
	return &Limiter{perNS: perNamespace, global: global, counts: map[string]int{}}
}

// TryAcquire reserves a slot for namespace ns, or reports false if a limit
// would be exceeded. Callers must Release exactly once on success.
func (l *Limiter) TryAcquire(ns string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.global || l.counts[ns] >= l.perNS {
		return false
	}
	l.counts[ns]++
	l.total++
	return true
}

// ForceAcquire reserves a slot ignoring limits. Used only when resuming Jobs
// that already exist after a controller restart.
func (l *Limiter) ForceAcquire(ns string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[ns]++
	l.total++
}

// Release frees a slot of namespace ns.
func (l *Limiter) Release(ns string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ns] > 0 {
		l.counts[ns]--
		l.total--
	}
}

// InUse returns the slots in use for ns and globally.
func (l *Limiter) InUse(ns string) (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[ns], l.total
}
