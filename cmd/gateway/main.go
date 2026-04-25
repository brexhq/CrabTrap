package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/brexhq/CrabTrap/internal/admin"
	"github.com/brexhq/CrabTrap/internal/approval"
	"github.com/brexhq/CrabTrap/internal/builder"
	"github.com/brexhq/CrabTrap/internal/config"
	idb "github.com/brexhq/CrabTrap/internal/db"
	"github.com/brexhq/CrabTrap/internal/eval"
	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/internal/llmpolicy"
	"github.com/brexhq/CrabTrap/internal/metrics"
	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/internal/proxy"
)

var (
	configPath  = flag.String("config", "config/gateway.yaml", "Path to configuration file")
	devMode     = flag.Bool("dev", false, "Enable development mode (serve web UI from filesystem for live reload)")
	showVersion = flag.Bool("version", false, "Print build identification and exit")
)

// Build identification, injected at link time via -ldflags:
//   go build -ldflags "-X main.version=$(git describe --tags --always) -X main.commit=$(git rev-parse HEAD) -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
// These power the crabtrap_build_info metric when observability.metrics is enabled.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "create-admin-user" {
		runCreateAdminUser(os.Args[2:])
		return
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("crabtrap %s\n  commit:     %s\n  build date: %s\n  go:         %s\n",
			version, commit, buildDate, runtime.Version())
		return
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Configure structured logging level.
	var slogLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slogLevel})))

	// Open PostgreSQL pool and run migrations.
	if cfg.Database.URL == "" {
		slog.Error("database.url is required (set DATABASE_URL env var)")
		os.Exit(1)
	}
	ctx := context.Background()
	pool, err := idb.Open(ctx, cfg.Database.URL, cfg.Database.MaxConns, cfg.Database.MinConns)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	slog.Info("database connected")

	if err := idb.Migrate(ctx, pool); err != nil {
		slog.Error("migrations failed", "error", err)
		os.Exit(1)
	}
	slog.Info("migrations applied")

	// Build PG-backed components.
	pgAuditReader := admin.NewPGAuditReader(pool)
	pgUserStore := admin.NewPGUserStore(pool)
	pgPolicyStore := llmpolicy.NewPGStore(pool)
	pgEvalStore := eval.NewPGStore(pool)

	// Create approval manager.
	approvalManager := approval.NewManager()
	approvalManager.SetMode(cfg.Approval.Mode)

	// Initialize observability metrics when enabled. A nil registry is a no-op
	// for every call site, so disabling metrics does not need per-hook guards.
	// initMetrics never aborts startup: a metrics initialisation failure must
	// not bring down the LLM trust-boundary data plane.
	metricsRegistry := initMetrics(cfg.Observability.Metrics, version, commit, buildDate)
	approvalManager.SetObserver(metricsObserver{metricsRegistry})

	proxyServer, err := proxy.NewServer(cfg, pgUserStore, approvalManager, pgAuditReader)
	if err != nil {
		slog.Error("failed to create proxy server", "error", err)
		os.Exit(1)
	}
	proxyServer.SetLLMResponseWriter(pgEvalStore)
	proxyServer.SetRateLimitObserver(metricsObserver{metricsRegistry})

	// Initialize notification system.
	dispatcher := notifications.NewDispatcher()
	sseChannel := notifications.NewSSEChannel("web")
	dispatcher.RegisterChannel(sseChannel)

	// Wire dispatchers.
	proxyServer.GetAuditLogger().SetDispatcher(dispatcher)

	// Wire up LLM judge if enabled.
	var llmJudge *judge.LLMJudge
	var llmAgent *builder.PolicyAgent
	if cfg.LLMJudge.Enabled {
		evalAdapter, err := newLLMAdapter(cfg.LLMJudge, cfg.LLMJudge.EvalModel, cfg.LLMJudge.Timeout,
			llm.WithMaxConcurrency(cfg.LLMJudge.MaxConcurrency),
			llm.WithCircuitBreaker(cfg.LLMJudge.CircuitBreakerThreshold, cfg.LLMJudge.CircuitBreakerCooldown),
			llm.WithObserver(metricsObserver{metricsRegistry}, cfg.LLMJudge.Provider),
		)
		if err != nil {
			slog.Error("failed to create LLM adapter", "error", err)
			os.Exit(1)
		}
		llmJudge = judge.NewLLMJudge(evalAdapter)
		approvalManager.SetJudge(llmJudge, cfg.Approval.Mode, cfg.LLMJudge.FallbackMode)
		slog.Info("LLM judge enabled",
			"provider", cfg.LLMJudge.Provider,
			"model", cfg.LLMJudge.EvalModel,
			"mode", cfg.Approval.Mode,
			"fallback", cfg.LLMJudge.FallbackMode,
			"max_concurrency", cfg.LLMJudge.MaxConcurrency,
			"cb_threshold", cfg.LLMJudge.CircuitBreakerThreshold,
			"cb_cooldown", cfg.LLMJudge.CircuitBreakerCooldown,
		)

		fastAdapter, err := newLLMAdapter(cfg.LLMJudge, cfg.LLMJudge.FastModel, cfg.LLMJudge.Timeout)
		if err != nil {
			slog.Warn("failed to create fast LLM adapter for agent", "error", err)
		}
		// Policy agent uses the thinking model for the agent loop; 5-minute timeout for long synthesis.
		thinkingAdapter, err := newLLMAdapter(cfg.LLMJudge, cfg.LLMJudge.ThinkingModel, 5*time.Minute)
		if err != nil {
			slog.Warn("failed to create thinking LLM adapter for agent", "error", err)
		}
		if fastAdapter != nil && thinkingAdapter != nil {
			llmAgent = builder.NewPolicyAgent(pgAuditReader, fastAdapter, thinkingAdapter)
			slog.Info("policy agent enabled",
				"fast_model", cfg.LLMJudge.FastModel,
				"thinking_model", cfg.LLMJudge.ThinkingModel,
			)
		}
	}

	// serverCtx is cancelled when the server starts shutting down, allowing
	// background goroutines (e.g. eval runs) to exit cleanly.
	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	// Start admin API in background.
	adminServer := startAdminAPI(adminAPIConfig{
		auditReader:    pgAuditReader,
		dispatcher:     dispatcher,
		sseChannel:     sseChannel,
		tokenValidator: pgUserStore,
		userStore:      pgUserStore,
		policyStore:    pgPolicyStore,
		evalStore:      pgEvalStore,
		llmJudge:       llmJudge,
		agent:          llmAgent,
		serverCtx:      serverCtx,
		port:           8081,
		devMode:        *devMode,
		secureCookie:   cfg.Admin.SecureCookie,
	})

	// Start dedicated metrics listener when metrics are enabled. Hosting
	// /metrics on its own listener keeps Prometheus scrapers free of the admin
	// auth cookie and isolates the scrape surface from admin and proxy
	// traffic. The default loopback bind keeps it private without operator
	// action; operators who scrape from another host set listen explicitly.
	var metricsServer *http.Server
	if metricsRegistry != nil {
		metricsServer = startMetricsServer(cfg.Observability.Metrics.Listen, metricsRegistry.Handler())
	}

	// Start proxy server in background.
	go func() {
		if err := proxyServer.Start(); err != nil {
			slog.Error("failed to start proxy server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	slog.Info("received shutdown signal")

	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := proxyServer.Shutdown(shutCtx); err != nil {
		slog.Error("error during proxy shutdown", "error", err)
	}
	if err := adminServer.Shutdown(shutCtx); err != nil {
		slog.Error("error during admin API shutdown", "error", err)
	}
	if metricsServer != nil {
		if err := metricsServer.Shutdown(shutCtx); err != nil {
			slog.Warn("error during metrics listener shutdown", "error", err)
		}
	}
	if err := metricsRegistry.Shutdown(shutCtx); err != nil {
		slog.Warn("error during metrics shutdown", "error", err)
	}

	slog.Info("shutdown complete")
}

// metricsObserver adapts a *metrics.Registry to the small observer interfaces
// defined by approval, proxy, and llm. It is a value type so that a nil
// registry inside flows naturally through the Record* no-ops — no per-call-site
// nil checks needed at the call sites themselves.
type metricsObserver struct {
	r *metrics.Registry
}

func (o metricsObserver) OnApprovalDecision(outcome, mode string) {
	o.r.RecordApprovalDecision(context.Background(), outcome, mode)
}

func (o metricsObserver) OnApprovalLatency(mode, outcome string, d time.Duration) {
	o.r.RecordApprovalLatency(context.Background(), mode, outcome, d)
}

func (o metricsObserver) OnRateLimitHit() {
	o.r.RecordRateLimitHit(context.Background())
}

func (o metricsObserver) OnCircuitBreakerTrip(provider string) {
	o.r.RecordCircuitBreakerTrip(context.Background(), provider)
}

func (o metricsObserver) OnCircuitBreakerStateChange(provider string, open bool) {
	o.r.RecordCircuitBreakerState(context.Background(), provider, open)
}

func (o metricsObserver) OnJudgeLatency(provider, model string, d time.Duration) {
	o.r.RecordJudgeLatency(context.Background(), provider, model, d)
}

type adminAPIConfig struct {
	auditReader    admin.AuditReaderIface
	dispatcher     *notifications.Dispatcher
	sseChannel     *notifications.SSEChannel
	tokenValidator admin.WebTokenValidator
	userStore      admin.UserStore
	policyStore    llmpolicy.Store
	evalStore      eval.Store
	llmJudge       *judge.LLMJudge
	agent          *builder.PolicyAgent
	serverCtx      context.Context
	port           int
	devMode        bool
	secureCookie   bool // set Secure flag on auth cookies (enable behind TLS proxy)
}

// startAdminAPI starts the admin API server with web UI and SSE support
func startAdminAPI(cfg adminAPIConfig) *http.Server {
	mux := http.NewServeMux()

	// Create admin API
	api := admin.NewAPI(cfg.auditReader, cfg.dispatcher, cfg.sseChannel, cfg.tokenValidator, cfg.userStore)
	if cfg.policyStore != nil {
		api.SetLLMPolicyStore(cfg.policyStore)
	}
	if cfg.evalStore != nil && cfg.llmJudge != nil {
		api.SetEvalRunner(cfg.evalStore, cfg.llmJudge)
	}
	if cfg.agent != nil {
		api.SetAgent(cfg.agent)
	}
	if cfg.serverCtx != nil {
		api.SetServerContext(cfg.serverCtx)
	}
	api.SetSecureCookie(cfg.secureCookie)
	api.RegisterRoutes(mux)

	// Serve web UI (embedded in production, filesystem in dev mode)
	mux.Handle("/", serveWebUI(cfg.devMode))

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.port),
		Handler:      mux,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 10 * time.Minute, // SSE suggest-policy can stream for several minutes
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting admin API", "port", cfg.port)
		slog.Info("web UI available", "url", fmt.Sprintf("http://localhost:%d/", cfg.port))
		slog.Info("SSE events available", "url", fmt.Sprintf("http://localhost:%d/admin/events", cfg.port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("admin API error", "error", err)
		}
	}()

	return server
}

// metricsRegistryFactory wraps metrics.New so initMetrics can be tested
// against a simulated initialisation failure without depending on duplicate
// Prometheus registrations or other side-effects of the real constructor.
var metricsRegistryFactory = metrics.New

// initMetrics initialises observability metrics if enabled. Failures are
// logged at error level and the function returns nil — the gateway data plane
// (the LLM trust-boundary proxy) must never fail to start because the
// observability subsystem could not initialise. A nil *metrics.Registry is a
// valid no-op for every call site, so callers do not need to branch on the
// return value.
func initMetrics(cfg config.MetricsConfig, version, commit, buildDate string) *metrics.Registry {
	if !cfg.Enabled {
		return nil
	}
	r, err := metricsRegistryFactory()
	if err != nil {
		slog.Error("failed to initialise metrics; gateway will start without metrics", "error", err)
		return nil
	}
	r.RecordBuildInfo(version, commit, runtime.Version(), buildDate)
	slog.Info("observability metrics enabled",
		"listen", cfg.Listen,
		"version", version,
		"commit", commit,
		"build_date", buildDate,
	)
	return r
}

// startMetricsServer launches a dedicated HTTP server that serves only
// /metrics from the given handler on listen. Returning the server lets the
// caller participate in the existing graceful-shutdown plumbing.
func startMetricsServer(listen string, handler http.Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)

	server := &http.Server{
		Addr:         listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("starting metrics listener", "listen", listen, "endpoint", "/metrics")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics listener error", "error", err)
		}
	}()

	return server
}

// newLLMAdapter creates an LLM adapter based on the configured provider.
func newLLMAdapter(cfg config.LLMJudgeConfig, model string, timeout time.Duration, opts ...llm.ResilienceOption) (llm.Adapter, error) {
	switch cfg.Provider {
	case "bedrock-anthropic", "":
		return llm.NewBedrockAdapter(model, cfg.BedrockAWSRegion, timeout, opts...)
	case "anthropic":
		a, err := llm.NewAnthropicAdapter(model, cfg.AnthropicAPIKey, timeout, opts...)
		if err != nil {
			return nil, err
		}
		if cfg.AnthropicBaseURL != "" {
			a.SetBaseURL(cfg.AnthropicBaseURL)
		}
		return a, nil
	case "openai":
		a, err := llm.NewOpenAIAdapter(model, cfg.OpenAIAPIKey, timeout, opts...)
		if err != nil {
			return nil, err
		}
		if cfg.OpenAIBaseURL != "" {
			a.SetBaseURL(cfg.OpenAIBaseURL)
		}
		return a, nil
	default:
		return nil, fmt.Errorf("unknown LLM provider: %q", cfg.Provider)
	}
}
