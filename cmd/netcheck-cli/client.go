package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(getenv func(string) string) (*client, error) {
	base := strings.TrimSuffix(strings.TrimSpace(getenv("NETCHECK_URL")), "/")
	token := strings.TrimSpace(getenv("NETCHECK_TOKEN"))
	u, err := url.Parse(base)
	if base == "" || err != nil || u.Host == "" {
		return nil, usageErr("set NETCHECK_URL to the NetCheck address, e.g. https://netcheck.example.com")
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return nil, usageErr("NETCHECK_URL must use https (the token would travel in clear text)")
	}
	if !strings.HasPrefix(token, "nck_") {
		return nil, usageErr("set NETCHECK_TOKEN to a NetCheck API token (user menu > API tokens)")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if f := getenv("NETCHECK_CA_FILE"); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, usageErr("NETCHECK_CA_FILE: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, usageErr("NETCHECK_CA_FILE: no PEM certificate found in %s", f)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &client{base: base, token: token, http: &http.Client{Timeout: 30 * time.Second, Transport: tr}}, nil
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"details"`
	} `json:"error"`
}

func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "netcheck-cli/"+version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return exitError{3, fmt.Errorf("cannot reach NetCheck at %s: %w", c.base, err)}
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var e apiError
		_ = json.Unmarshal(data, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = res.Status
		}
		for _, d := range e.Error.Details {
			msg += fmt.Sprintf("; %s: %s", d.Field, d.Message)
		}
		if res.StatusCode == http.StatusUnauthorized {
			msg += " (check NETCHECK_TOKEN: it may be revoked or expired)"
		}
		return exitError{3, fmt.Errorf("NetCheck answered %d: %s", res.StatusCode, msg)}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// runView is the part of GET /api/v1/runs/{id} the CLI prints.
type runView struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Namespace    string `json:"namespace"`
	Target       string `json:"target"`
	ErrorMessage string `json:"errorMessage"`
	Checks       []struct {
		Method     string `json:"method"`
		Status     string `json:"status"`
		DurationMs *int64 `json:"durationMs"`
		UsedIP     string `json:"usedIp"`
		Result     *struct {
			Port int `json:"port"`
		} `json:"result"`
		Diagnosis *struct {
			Summary string `json:"summary"`
		} `json:"diagnosis"`
	} `json:"checks"`
}

func terminal(status string) bool {
	switch status {
	case "succeeded", "failed", "infra_error", "cancelled":
		return true
	}
	return false
}

func runTest(ctx context.Context, c *client, req runRequest, wait time.Duration, asJSON bool, out io.Writer) error {
	var created struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/runs", req, &created); err != nil {
		return err
	}
	link := fmt.Sprintf("%s/#/runs/%s", c.base, created.ID)
	if !asJSON {
		fmt.Fprintf(out, "NetCheck test %s: %s -> %s\n%s\n", created.ID[:8], req.Namespace, req.Target, link)
	}
	deadline := time.Now().Add(wait)
	var raw json.RawMessage
	var r runView
	for {
		if err := c.do(ctx, http.MethodGet, "/api/v1/runs/"+url.PathEscape(created.ID), nil, &raw); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if terminal(r.Status) {
			break
		}
		if time.Now().After(deadline) {
			return exitError{2, fmt.Errorf("no result after %s; the test keeps running: %s", wait, link)}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if asJSON {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, raw, "", "  ")
		fmt.Fprintln(out, pretty.String())
	} else {
		printRun(out, r)
	}
	switch r.Status {
	case "succeeded":
		return nil
	case "failed":
		return exitError{1, errors.New("")}
	default:
		return exitError{2, errors.New("")}
	}
}

func printRun(out io.Writer, r runView) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, c := range r.Checks {
		name := strings.ToUpper(c.Method)
		if c.Result != nil && c.Result.Port > 0 {
			name += fmt.Sprintf(" %d", c.Result.Port)
		}
		dur := ""
		if c.DurationMs != nil {
			dur = fmt.Sprintf("%d ms", *c.DurationMs)
		}
		summary := ""
		if c.Diagnosis != nil {
			summary = c.Diagnosis.Summary
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", name, c.Status, c.UsedIP, dur, summary)
	}
	_ = w.Flush()
	result := map[string]string{"succeeded": "all checks passed", "failed": "connectivity failures",
		"infra_error": "NetCheck could not run the test (not a network result)", "cancelled": "cancelled"}[r.Status]
	fmt.Fprintf(out, "Result: %s\n", result)
	if r.ErrorMessage != "" {
		fmt.Fprintf(out, "  %s\n", r.ErrorMessage)
	}
}

func listNamespaces(ctx context.Context, c *client, out io.Writer) error {
	var res struct {
		Items []struct {
			Name   string `json:"name"`
			CanRun bool   `json:"canRun"`
		} `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/namespaces", nil, &res); err != nil {
		return err
	}
	for _, n := range res.Items {
		fmt.Fprintln(out, n.Name)
	}
	return nil
}
