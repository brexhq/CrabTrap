package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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
	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/internal/probes"
	"github.com/brexhq/CrabTrap/internal/proxy"
)

var (
	configPath = flag.String("config", "config/gateway.yaml", "Path to configuration file")
	devMode    = flag.Bool("dev", false, "Enable development mode (serve web UI from filesystem for live reload)")
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "create-admin-user" {
		runCreateAdminUser(os.Args[2:])
		return
	}

	flag.Parse()

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

	proxyServer, err := proxy.NewServer(cfg, pgUserStore, approvalManager, pgAuditReader)
	if err != nil {
		slog.Error("failed to create proxy server", "error", err)
		os.Exit(1)
	}
	proxyServer.SetLLMResponseWriter(pgEvalStore)

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

	// Wire up probe evaluator if enabled. Probes are global (they encode their
	// own policies) and run in parallel with the judge; any probe over its
	// threshold DENIES regardless of the judge's verdict.
	if cfg.Probes.Enabled {
		probeClient := probes.NewClient(
			cfg.Probes.Endpoint,
			cfg.Probes.Model,
			cfg.Probes.Timeout,
			cfg.Probes.MaxTokens,
			llm.WithMaxConcurrency(cfg.Probes.MaxConcurrency),
			llm.WithCircuitBreaker(cfg.Probes.CircuitBreakerThreshold, cfg.Probes.CircuitBreakerCooldown),
		)
		probeSpecs := make([]probes.Spec, len(cfg.Probes.Probes))
		for i, s := range cfg.Probes.Probes {
			probeSpecs[i] = probes.Spec{
				Name:        s.Name,
				Threshold:   s.Threshold,
				Aggregation: s.Aggregation,
			}
		}
		approvalManager.SetProbeRunner(probes.NewRunner(probeClient, probeSpecs, cfg.Probes.MaxBodyBytes))
		slog.Info("probe evaluator enabled",
			"endpoint", cfg.Probes.Endpoint,
			"model", cfg.Probes.Model,
			"probes", len(probeSpecs),
			"max_body_bytes", cfg.Probes.MaxBodyBytes,
			"timeout", cfg.Probes.Timeout,
			"max_concurrency", cfg.Probes.MaxConcurrency,
			"cb_threshold", cfg.Probes.CircuitBreakerThreshold,
			"cb_cooldown", cfg.Probes.CircuitBreakerCooldown,
		)
	}

	// serverCtx is cancelled when the server starts shutting down, allowing
	// background goroutines (e.g. eval runs) to exit cleanly.
	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	// Start admin API in background.
	adminServer := startAdminAPI(adminAPIConfig{
		auditReader:  pgAuditReader,
		dispatcher:   dispatcher,
		sseChannel:   sseChannel,
		tokenValidator:  pgUserStore,
		userStore:    pgUserStore,
		policyStore:  pgPolicyStore,
		evalStore:    pgEvalStore,
		llmJudge:     llmJudge,
		agent:        llmAgent,
		serverCtx:    serverCtx,
		port:         8081,
		devMode:      *devMode,
		secureCookie: cfg.Admin.SecureCookie,
	})

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

	slog.Info("shutdown complete")
}

type adminAPIConfig struct {
	auditReader  admin.AuditReaderIface
	dispatcher   *notifications.Dispatcher
	sseChannel   *notifications.SSEChannel
	tokenValidator  admin.WebTokenValidator
	userStore    admin.UserStore
	policyStore  llmpolicy.Store
	evalStore    eval.Store
	llmJudge     *judge.LLMJudge
	agent        *builder.PolicyAgent
	serverCtx    context.Context
	port         int
	devMode      bool
	secureCookie bool // set Secure flag on auth cookies (enable behind TLS proxy)
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
