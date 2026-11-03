// Command netcheck-cli runs NetCheck tests from pipelines and terminals with
// an API token, waits for the result and exits with a code a pipeline can
// act on:
//
//	0  every check passed
//	1  connectivity failures (the network answered with a block or nothing)
//	2  NetCheck could not run the test, or the wait timed out
//	3  usage, authentication or API errors
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
)

var version = "dev"

const usage = `netcheck-cli runs NetCheck connectivity tests from a pipeline or a terminal.

Usage:
  netcheck-cli run -n NAMESPACE -t TARGET -c CHECK [-c CHECK...] [flags]
  netcheck-cli namespaces
  netcheck-cli version

Environment:
  NETCHECK_URL      NetCheck address, e.g. https://netcheck.example.com
  NETCHECK_TOKEN    API token (create it in NetCheck: user menu > API tokens)
  NETCHECK_CA_FILE  PEM bundle to trust, for a private certificate authority

Checks (-c, repeatable):
  dns                     resolve the target
  tcp:PORT                open a TCP connection
  udp:PORT                generic UDP port (silence is inconclusive)
  udp-dns[:PORT]          DNS server over UDP (default 53)
  udp-ntp[:PORT]          NTP server (default 123)
  http[:PORT][/PATH]      HTTP GET (default 80)
  https[:PORT][/PATH]     HTTPS GET with certificate verification (default 443)
  ping[:COUNT]            ICMP echo
  traceroute[:MAXHOPS]    ICMP traceroute

Example:
  netcheck-cli run -n payments -t db.corp.example -c dns -c tcp:5432 -c https:8443/health

Flags of run: --timeout SECONDS, --wait DURATION (default 5m), --json, --ignore-tls-errors (HTTPS goes
on despite certificate problems, which are still reported), --proxy NAME (TCP and HTTPS checks go through
that proxy, configured by the administrators; the other checks stay direct).

Exit codes: 0 passed, 1 connectivity failures, 2 test not run or wait timed out, 3 usage or API error.
`

// exitError carries the process exit code.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }

func usageErr(format string, a ...any) error {
	return exitError{3, fmt.Errorf(format, a...)}
}

func main() {
	err := run(context.Background(), os.Args[1:], os.Getenv, os.Stdout)
	if err == nil {
		return
	}
	var ee exitError
	if !errors.As(err, &ee) {
		ee = exitError{3, err}
	}
	if ee.err != nil && ee.err.Error() != "" {
		fmt.Fprintln(os.Stderr, "netcheck-cli:", ee.err)
	}
	os.Exit(ee.code)
}

func run(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(out, usage)
		return nil
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(out, "netcheck-cli", version)
		return nil
	case "namespaces":
		c, err := newClient(getenv)
		if err != nil {
			return err
		}
		return listNamespaces(ctx, c, out)
	case "run":
		return runCommand(ctx, args[1:], getenv, out)
	}
	return usageErr("unknown command %q (run, namespaces or version)", args[0])
}

type checkList []string

func (c *checkList) String() string     { return strings.Join(*c, ",") }
func (c *checkList) Set(v string) error { *c = append(*c, v); return nil }

func runCommand(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var checks checkList
	ns := fs.String("n", "", "source namespace")
	fs.StringVar(ns, "namespace", "", "source namespace")
	target := fs.String("t", "", "destination host name or IP")
	fs.StringVar(target, "target", "", "destination host name or IP")
	fs.Var(&checks, "c", "check (repeatable)")
	fs.Var(&checks, "check", "check (repeatable)")
	timeout := fs.Int("timeout", 0, "seconds per check (default: the server default)")
	wait := fs.Duration("wait", 5*time.Minute, "maximum time to wait for the result")
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	ignoreTLS := fs.Bool("ignore-tls-errors", false, "HTTPS checks go on despite certificate problems (still reported)")
	proxy := fs.String("proxy", "", "TCP and HTTPS checks go through this configured proxy")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *ns == "" || *target == "" || len(checks) == 0 {
		return usageErr("-n NAMESPACE, -t TARGET and at least one -c CHECK are required (see netcheck-cli --help)")
	}
	req := runRequest{Namespace: *ns, Target: *target, TimeoutSeconds: *timeout}
	for _, s := range checks {
		c, err := parseCheck(s)
		if err != nil {
			return usageErr("%v", err)
		}
		if *ignoreTLS && c.Method == probes.MethodHTTPS {
			if c.HTTP == nil {
				c.HTTP = &probes.HTTPOptions{Method: "GET", Path: "/"}
			}
			c.HTTP.IgnoreTLSErrors = true
		}
		if *proxy != "" && probes.ProxyAllowed(c.Method) {
			c.Proxy = *proxy
		}
		req.Checks = append(req.Checks, c)
	}
	c, err := newClient(getenv)
	if err != nil {
		return err
	}
	return runTest(ctx, c, req, *wait, *asJSON, out)
}
