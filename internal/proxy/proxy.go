package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/brexhq/CrabTrap/internal/admin"
	"github.com/brexhq/CrabTrap/internal/approval"
	"github.com/brexhq/CrabTrap/internal/audit"
	"github.com/brexhq/CrabTrap/internal/config"
)

// Server represents the HTTP proxy server
type Server struct {
	config            *config.Config
	tlsManager        *TLSManager
	approvalManager   *approval.Manager
	auditLogger       *audit.Logger
	auditReader       admin.AuditReaderIface
	userResolver      admin.UserResolver
	llmResponseWriter LLMResponseWriter   // optional; set via SetLLMResponseWriter
	rateLimitObserver RateLimitObserver   // optional; set via SetRateLimitObserver
	httpServer        *http.Server
	handler           *Handler // stored for shutdown cleanup (e.g. rate limiter)
}

// NewServer creates a new proxy server.
// userResolver may be nil if user identity resolution is disabled.
// auditReader may be nil in tests that don't need DB audit writes.
func NewServer(cfg *config.Config, userResolver admin.UserResolver, approvalManager *approval.Manager, auditReader admin.AuditReaderIface) (*Server, error) {
	// Ensure CA certificate exists, generating one if needed.
	if err := EnsureCACertificate(cfg.TLS.CACertPath, cfg.TLS.CAKeyPath); err != nil {
		return nil, fmt.Errorf("CA certificate setup: %w", err)
	}

	// Initialize TLS manager
	tlsManager, err := NewTLSManager(cfg.TLS.CACertPath, cfg.TLS.CAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS manager: %w", err)
	}
	if cfg.TLS.MaxCertCacheSize > 0 {
		tlsManager.SetMaxCertCacheSize(cfg.TLS.MaxCertCacheSize)
	}

	// Initialize audit logger
	auditLogger, err := audit.NewLogger(cfg.Audit.Output)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	return &Server{
		config:          cfg,
		tlsManager:      tlsManager,
		approvalManager: approvalManager,
		auditLogger:     auditLogger,
		auditReader:     auditReader,
		userResolver:    userResolver,
	}, nil
}

// Start starts the proxy server
func (s *Server) Start() error {
	// Create handler
	handler := NewHandler(s.tlsManager, s.approvalManager, s.auditLogger, s.auditReader, s.userResolver, s.config.Proxy.InsecureSkipUpstreamVerify)

	// Configure per-host TLS verification skip when insecure_skip_verify_hosts
	// is non-empty; this scopes the skip to listed hosts only.
	if len(s.config.Proxy.InsecureSkipVerifyHosts) > 0 {
		hostSet := make(map[string]bool, len(s.config.Proxy.InsecureSkipVerifyHosts))
		for _, h := range s.config.Proxy.InsecureSkipVerifyHosts {
			hostSet[strings.ToLower(h)] = true
		}
		handler.insecureSkipVerifyHosts = hostSet
		handler.initClient() // re-create HTTP client with per-host TLS dial
		slog.Warn("TLS certificate verification disabled for specific upstream hosts",
			"hosts", s.config.Proxy.InsecureSkipVerifyHosts)
	} else if s.config.Proxy.InsecureSkipUpstreamVerify {
		slog.Warn("InsecureSkipUpstreamVerify is enabled: TLS certificate verification is disabled for ALL upstream connections, exposing every upstream to MITM attacks. Consider using insecure_skip_verify_hosts to limit the scope to specific hosts.")
	}
	handler.llmResponseWriter = s.llmResponseWriter

	// Wire up per-IP rate limiting (disabled when rate_limit_per_ip is explicitly 0).
	if s.config.Proxy.RateLimitPerIP != nil && *s.config.Proxy.RateLimitPerIP > 0 {
		burst := s.config.Proxy.RateLimitBurst
		handler.rateLimiter = newIPRateLimiter(float64(*s.config.Proxy.RateLimitPerIP), burst)
		if s.rateLimitObserver != nil {
			handler.rateLimiter.setObserver(s.rateLimitObserver)
		}
		slog.Info("per-IP rate limiting enabled",
			"rate", *s.config.Proxy.RateLimitPerIP,
			"burst", burst,
		)
	}

	if len(s.config.Proxy.AllowedPrivateCIDRs) > 0 {
		for _, cidr := range s.config.Proxy.AllowedPrivateCIDRs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				// This shouldn't happen since config.validate() already checked
				return fmt.Errorf("bad allowed CIDR %q: %w", cidr, err)
			}
			handler.allowedPrivateCIDRs = append(handler.allowedPrivateCIDRs, network)
		}
		handler.initClient() // re-create HTTP client with updated CIDRs
		slog.Info("SSRF allowlist configured", "cidrs", s.config.Proxy.AllowedPrivateCIDRs)
	}

	// Store handler for shutdown cleanup.
	s.handler = handler

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Proxy.Port),
		Handler:      handler,
		ReadTimeout:  s.config.Proxy.ReadTimeout,
		WriteTimeout: s.config.Proxy.WriteTimeout,
		IdleTimeout:  s.config.Proxy.IdleTimeout,
	}

	slog.Info("starting CrabTrap", "port", s.config.Proxy.Port)
	slog.Info("approval timeout configured", "timeout", s.config.Approval.Timeout)

	// Start server
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("shutting down proxy server")

	// Shutdown HTTP server
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	// Close audit logger
	if err := s.auditLogger.Close(); err != nil {
		return fmt.Errorf("failed to close audit logger: %w", err)
	}

	slog.Info("proxy server shut down successfully")
	return nil
}

// GetApprovalManager returns the approval manager
func (s *Server) GetApprovalManager() *approval.Manager {
	return s.approvalManager
}

// GetAuditLogger returns the audit logger
func (s *Server) GetAuditLogger() *audit.Logger {
	return s.auditLogger
}

// SetLLMResponseWriter configures where llm_responses rows are written.
// Must be called before Start().
func (s *Server) SetLLMResponseWriter(w LLMResponseWriter) {
	s.llmResponseWriter = w
}

// SetRateLimitObserver attaches an optional observer invoked on every
// rate-limit rejection. Must be called before Start().
func (s *Server) SetRateLimitObserver(obs RateLimitObserver) {
	s.rateLimitObserver = obs
}
