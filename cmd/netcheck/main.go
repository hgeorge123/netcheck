// Command netcheck runs the NetCheck API, the probe Job controller and serves
// the Cloudscape frontend. One replica per cluster (SQLite on a RWO PVC).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/hgeorge123/netcheck/internal/api"
	"github.com/hgeorge123/netcheck/internal/auth"
	"github.com/hgeorge123/netcheck/internal/config"
	"github.com/hgeorge123/netcheck/internal/k8s"
	"github.com/hgeorge123/netcheck/internal/scheduler"
	"github.com/hgeorge123/netcheck/internal/store"
)

// Build information, injected with -ldflags "-X main.version=... -X main.commit=... -X main.buildDate=...".
var (
	version   = "dev"
	commit    = ""
	buildDate = ""
)

func main() {
	configPath := flag.String("config", "/etc/netcheck/config.yaml", "path to the configuration file")
	flag.Parse()

	// Info until the configuration is loaded, then its logLevel.
	level := new(slog.LevelVar)
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	if err := run(*configPath, log, level); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func kubeClient(cfg config.Config, log *slog.Logger) k8s.JobAPI {
	rc, err := rest.InClusterConfig()
	if err != nil && cfg.Environment == config.EnvDevelopment {
		// Local laboratories only: use the operator's kubeconfig.
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		rc, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	}
	if err != nil {
		log.Warn("kubernetes API not configured; runs will end as infra_error", "error", err)
		return nil
	}
	rc.Timeout = 15 * time.Second
	rc.QPS, rc.Burst = 20, 40
	rc.UserAgent = "netcheck-controller"
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		log.Warn("kubernetes client error; runs will end as infra_error", "error", err)
		return nil
	}
	return &k8s.Client{CS: cs}
}

// newOIDC returns the single sign-on client, or nil when it is disabled.
// The client secret comes from a Kubernetes Secret and is never logged.
func newOIDC(cfg config.Config, local *auth.LocalAuth, log *slog.Logger) *auth.OIDC {
	o := cfg.Auth.OIDC
	if !o.Enabled {
		return nil
	}
	log.Info("single sign-on enabled", "issuer", o.IssuerURL, "internal_url", o.InternalURL, "username_claim", o.UsernameClaim)
	return &auth.OIDC{Local: local, HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Config: auth.OIDCConfig{Issuer: o.IssuerURL, ClientID: o.ClientID, ClientSecret: os.Getenv("NETCHECK_OIDC_CLIENT_SECRET"),
			RedirectURL: o.RedirectURL, InternalURL: o.InternalURL, Scopes: o.Scopes, UsernameClaim: o.UsernameClaim, GroupsClaim: o.GroupsClaim}}
}

func run(configPath string, log *slog.Logger, level *slog.LevelVar) error {
	cfg, err := config.Load(configPath, os.Getenv)
	if err != nil {
		return err
	}
	level.Set(cfg.SlogLevel())
	if cfg.Environment == config.EnvDevelopment {
		log.Warn("DEVELOPMENT MODE: relaxed cookie/bootstrap settings may be active; never expose this instance")
	}
	if !cfg.ProtectPlatformDestinations {
		log.Warn("platform destination protections disabled: probes may reach cloud metadata, the API server, loopback and link-local addresses",
			"setting", "protectPlatformDestinations=false")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.Database.Path, cfg.Database.WAL)
	if err != nil {
		return err
	}
	defer st.Close()

	jobs := kubeClient(cfg, log)
	var namespaces auth.NamespaceSource = k8s.StaticNamespaces(cfg.NamespaceScope.Namespaces)
	if cfg.NamespaceScope.Mode == config.ScopeAll {
		namespaces = &k8s.ClusterNamespaces{API: jobs, Exclude: cfg.ExcludedNamespaces(), TTL: 30 * time.Second}
	}
	// Exclusions added by administrators in the web, on top of Helm and system.
	stored, err := st.ListNamespaceExclusions(ctx)
	if err != nil {
		return err
	}
	webExcluded := make([]string, len(stored))
	for i, e := range stored {
		webExcluded[i] = e.Name
	}
	visible := auth.NewWebExclusions(namespaces, webExcluded)
	nsAll := namespaces.(interface {
		All(context.Context) ([]string, error)
	}).All

	local := &auth.LocalAuth{
		Store:          st,
		Namespaces:     visible,
		SessionIdle:    time.Duration(cfg.Auth.SessionIdleMinutes) * time.Minute,
		SessionMax:     time.Duration(cfg.Auth.SessionMaxHours) * time.Hour,
		MaxFailures:    cfg.Auth.MaxFailedLogins,
		LockDuration:   time.Duration(cfg.Auth.LockoutMinutes) * time.Minute,
		CookieSecure:   cfg.Auth.CookieSecure,
		LoginLimiter:   auth.NewRateLimiter(cfg.Auth.LoginAttemptsPerIPMin, time.Minute),
		TrustedProxies: cfg.TrustedProxies(),
	}
	// The initial admin password comes from a Kubernetes Secret and is only
	// used when no admin exists yet. It is never logged.
	if os.Getenv("NETCHECK_RECOVER_BOOTSTRAP_ADMIN") == "true" {
		// Break-glass: only reachable by whoever can change the Deployment.
		if err := local.RecoverBootstrapAdmin(ctx, cfg.Auth.BootstrapAdmin.Username, os.Getenv("NETCHECK_BOOTSTRAP_ADMIN_PASSWORD")); err != nil {
			return fmt.Errorf("admin recovery: %w", err)
		}
		log.Warn("RECOVERY: bootstrap admin reset to the Secret password; disable auth.bootstrapAdmin.recoverOnStart now",
			"username", cfg.Auth.BootstrapAdmin.Username)
	}
	created, err := local.EnsureBootstrapAdmin(ctx, cfg.Auth.BootstrapAdmin.Username, os.Getenv("NETCHECK_BOOTSTRAP_ADMIN_PASSWORD"),
		cfg.Auth.BootstrapAdmin.ForcePasswordChange)
	if err != nil {
		return fmt.Errorf("bootstrap admin: %w (set NETCHECK_BOOTSTRAP_ADMIN_PASSWORD)", err)
	}
	if created {
		log.Info("bootstrap admin created", "username", cfg.Auth.BootstrapAdmin.Username, "must_change_password", cfg.Auth.BootstrapAdmin.ForcePasswordChange)
	}

	limiter := scheduler.NewLimiter(cfg.Limits.MaxConcurrentPerNamespace, cfg.Limits.MaxConcurrentGlobal)
	exec := &scheduler.Executor{
		Ctx:                       ctx,
		Store:                     st,
		Jobs:                      jobs,
		Limiter:                   limiter,
		ReadFidelity:              cfg.NetworkPolicyRead,
		ManageProbeServiceAccount: cfg.NamespaceScope.Mode == config.ScopeAll,
		Log:                       log,
		JobOptions: k8s.JobOptions{
			Image:                   cfg.Probe.Image,
			ServiceAccountName:      cfg.Probe.ServiceAccountName,
			RunAsUser:               cfg.Probe.RunAsUser,
			CPURequest:              cfg.Probe.CPURequest,
			CPULimit:                cfg.Probe.CPULimit,
			MemoryRequest:           cfg.Probe.MemoryRequest,
			MemoryLimit:             cfg.Probe.MemoryLimit,
			EphemeralStorageLimit:   cfg.Probe.EphemeralStorageLimit,
			ActiveDeadlineSeconds:   int64(cfg.Limits.MaxJobSeconds),
			TTLSecondsAfterFinished: cfg.Probe.TTLSecondsAfterFinished,
			NodeSelector:            cfg.Probe.NodeSelector,
		},
	}
	if err := exec.Recover(ctx); err != nil {
		return err
	}

	go every(ctx, 5*time.Minute, func() {
		list, err := namespaces.Available(ctx)
		if err != nil {
			log.Warn("reconcile: namespace listing failed", "error", err)
			return
		}
		if cfg.OwnNamespace != "" {
			list = append(list, cfg.OwnNamespace) // usable by flagged users
		}
		exec.ReconcileOrphans(ctx, list)
	})
	go every(ctx, time.Hour, func() {
		if n, err := st.PurgeSessions(ctx, time.Now(), local.SessionIdle); err != nil {
			log.Error("session purge failed", "error", err)
		} else if n > 0 {
			log.Info("expired sessions purged", "count", n)
		}
		if n, err := st.PurgeAPITokens(ctx, time.Now()); err != nil {
			log.Error("api token purge failed", "error", err)
		} else if n > 0 {
			log.Info("expired api tokens purged", "count", n)
		}
	})
	// Retention: the Helm values seed it; administrators change it in the web
	// and the database copy wins. Purging hourly applies changes quickly.
	retention, err := api.LoadRetention(ctx, st, cfg.Retention.OutputDays, cfg.Retention.MetadataDays, time.Now())
	if err != nil {
		return err
	}
	go every(ctx, time.Hour, func() {
		now := time.Now()
		outputDays, metadataDays := retention.Days()
		blanked, deleted, err := st.Purge(ctx, now.AddDate(0, 0, -outputDays), now.AddDate(0, 0, -metadataDays))
		if err != nil {
			log.Error("retention purge failed", "error", err)
			return
		}
		if blanked > 0 || deleted > 0 {
			log.Info("retention purge", "outputs_blanked", blanked, "runs_deleted", deleted)
		}
	})

	// Image references come from the Deployment (chart) so the System page
	// shows exactly what runs.
	build := store.AppVersion{Version: version, Commit: commit, BuildDate: buildDate, Image: os.Getenv("NETCHECK_IMAGE"),
		ProbeImage: cfg.Probe.Image, ChartVersion: os.Getenv("NETCHECK_CHART_VERSION")}
	if err := st.RecordVersion(ctx, build, time.Now()); err != nil {
		log.Warn("could not record version history", "error", err)
	}
	log.Info("netcheck version", "version", version, "commit", commit, "build_date", buildDate, "chart", build.ChartVersion)

	// Destination policy: the Helm values seed it; with destinationsManagedBy=ui
	// administrators edit it in the web and the database copy wins.
	policies, err := api.LoadDestinationPolicies(ctx, st, cfg.Destinations, cfg.PlatformDenies,
		cfg.DestinationsManagedBy == config.DestinationsManagedByUI, time.Now())
	if err != nil {
		return err
	}

	srv := &api.Server{
		Version: build,
		OIDC:    newOIDC(cfg, local, log),
		SSOName: cfg.Auth.OIDC.ProviderName,
		Store:   st,
		Authn:   local,
		Local:   local,
		Authz:   &auth.Authorizer{Source: visible, OwnNamespace: cfg.OwnNamespace},
		NSAdmin: &api.NamespaceAdmin{All: nsAll, Web: visible, HelmExcluded: cfg.NamespaceScope.Exclude,
			System: config.SystemNamespaces},
		ScopeMode: cfg.NamespaceScope.Mode,
		Starter:   exec,
		Limiter:   limiter,
		Policies:  policies,
		Retention: retention,
		Limits:    cfg.ProbeLimits(),
		ClusterID: cfg.ClusterID,
		WebDir:    cfg.WebDir,
		Log:       log,
	}
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "environment", cfg.Environment, "cluster", cfg.ClusterID)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	// In-flight runs observe ctx cancellation and are resumed by Recover on
	// the next start; wait so SQLite is closed cleanly.
	exec.Wait()
	log.Info("shutdown complete")
	return nil
}

func every(ctx context.Context, d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	fn()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}
