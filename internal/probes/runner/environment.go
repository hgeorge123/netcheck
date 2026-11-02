package runner

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/hgeorge123/netcheck/internal/probes"
)

// Well known credential locations that must never be present in a probe Pod.
var (
	saTokenPaths    = []string{"/var/run/secrets/kubernetes.io/serviceaccount/token"}
	cloudTokenPaths = []string{
		"/var/run/secrets/eks.amazonaws.com/serviceaccount/token",                       // IRSA
		"/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token", // EKS Pod Identity
	}
	cloudEnvVars = []string{"AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_ACCESS_KEY_ID"}
)

// DetectSource reports where the probe runs, using Downward API variables.
func DetectSource(getenv func(string) string, exists func(string) bool) probes.SourceInfo {
	src := probes.SourceInfo{
		Namespace: getenv("POD_NAMESPACE"),
		PodName:   getenv("POD_NAME"),
		PodIP:     getenv("POD_IP"),
		NodeName:  getenv("NODE_NAME"),
	}
	for _, p := range saTokenPaths {
		src.SATokenMounted = src.SATokenMounted || exists(p)
	}
	for _, p := range cloudTokenPaths {
		src.CloudCredentialsHint = src.CloudCredentialsHint || exists(p)
	}
	for _, v := range cloudEnvVars {
		src.CloudCredentialsHint = src.CloudCredentialsHint || getenv(v) != ""
	}
	return src
}

// FileExists is the production implementation for DetectSource.
func FileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ParseResolvConf extracts nameservers, search domains and ndots.
func ParseResolvConf(content string) probes.ResolverInfo {
	var info probes.ResolverInfo
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") || strings.HasPrefix(fields[0], ";") {
			continue
		}
		switch fields[0] {
		case "nameserver":
			info.Nameservers = append(info.Nameservers, fields[1])
		case "search":
			info.Search = append([]string(nil), fields[1:]...)
		case "options":
			for _, o := range fields[1:] {
				if v, ok := strings.CutPrefix(o, "ndots:"); ok {
					if n, err := strconv.Atoi(v); err == nil {
						info.Ndots = n
					}
				}
			}
		}
	}
	return info
}
