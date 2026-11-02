//go:build !linux

package runner

// dialICMP is only implemented on Linux, where the probe runs. Other
// platforms (developer workstations) report ICMP as not permitted.
func dialICMP(bool) (ICMPConn, error) { return nil, ErrICMPNotPermitted }
