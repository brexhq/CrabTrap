package config

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExpandEnvVars(t *testing.T) {
	os.Setenv("TEST_DB_URL", "postgres://localhost/test")
	defer os.Unsetenv("TEST_DB_URL")

	config := &Config{
		Database: DatabaseConfig{
			URL: "${TEST_DB_URL}",
		},
		TLS: TLSConfig{
			CACertPath: "./certs/${TEST_DB_URL}/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
	}

	config.expandEnvVars()

	if config.Database.URL != "postgres://localhost/test" {
		t.Errorf("Expected database URL to be expanded, got '%s'", config.Database.URL)
	}

	// Non-secret fields should remain unchanged
	if config.TLS.CACertPath != "./certs/${TEST_DB_URL}/ca.crt" {
		t.Errorf("Expected ca_cert_path to remain unchanged, got '%s'", config.TLS.CACertPath)
	}
}

func TestLoadWithEnvVars(t *testing.T) {
	os.Setenv("TEST_DB_URL", "postgres://localhost/test")
	defer os.Unsetenv("TEST_DB_URL")

	configContent := `
proxy:
  port: 8080

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough
  timeout: 30s

audit:
  output: stdout
  format: json

database:
  url: "${TEST_DB_URL}"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.Database.URL != "postgres://localhost/test" {
		t.Errorf("Expected database URL to be expanded, got '%s'", config.Database.URL)
	}
}

func TestValidateLLMModeRequiresJudgeEnabled(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "llm"},
		LLMJudge: LLMJudgeConfig{Enabled: false},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error when approval.mode=llm but llm_judge.enabled=false")
	}
}

func TestValidateLLMModeWithJudgeEnabled(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "llm"},
		LLMJudge: LLMJudgeConfig{Enabled: true},
	}

	if err := config.validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}
}

func TestValidatePassthroughMode(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}

	if err := config.validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}
}

func TestValidateApprovalModeRejectsUnknownValue(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "invalid"},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for unknown approval.mode")
	}
}

func TestValidateFallbackModeRejectsManual(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
		LLMJudge: LLMJudgeConfig{FallbackMode: "manual"},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for fallback_mode=manual (no longer supported)")
	}
}

func TestValidateJevRequiresAPIKey(t *testing.T) {
	config := &Config{
		Proxy:    ProxyConfig{Port: 8080},
		TLS:      TLSConfig{CACertPath: "./certs/ca.crt", CAKeyPath: "./certs/ca.key"},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "llm"},
		LLMJudge: LLMJudgeConfig{
			Enabled:  true,
			Provider: "bedrock-anthropic",
			Jev:      JevConfig{Enabled: true, AllowBelow: threshold(0.3), DenyAbove: threshold(0.7)},
		},
	}
	if err := config.validate(); err == nil {
		t.Fatal("expected error when jev enabled without api key")
	}
}

func TestValidateJevRejectsNegativeTimeout(t *testing.T) {
	config := &Config{
		Proxy:    ProxyConfig{Port: 8080},
		TLS:      TLSConfig{CACertPath: "./certs/ca.crt", CAKeyPath: "./certs/ca.key"},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "llm"},
		LLMJudge: LLMJudgeConfig{
			Enabled:  true,
			Provider: "bedrock-anthropic",
			Jev:      JevConfig{Enabled: true, APIKey: "k", Timeout: -5 * time.Second, DenyAbove: threshold(0.7)},
		},
	}
	if err := config.validate(); err == nil || !strings.Contains(err.Error(), "timeout must not be negative") {
		t.Fatalf("got err %v, want negative timeout error", err)
	}
}

func TestValidateJevBand(t *testing.T) {
	config := &Config{
		Proxy:    ProxyConfig{Port: 8080},
		TLS:      TLSConfig{CACertPath: "./certs/ca.crt", CAKeyPath: "./certs/ca.key"},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "llm"},
		LLMJudge: LLMJudgeConfig{
			Enabled:  true,
			Provider: "bedrock-anthropic",
			Jev:      JevConfig{Enabled: true, APIKey: "k", AllowBelow: threshold(0.8), DenyAbove: threshold(0.2)},
		},
	}
	if err := config.validate(); err == nil {
		t.Fatal("expected error for inverted jev band")
	}
}

func TestValidateJevOK(t *testing.T) {
	config := &Config{
		Proxy:    ProxyConfig{Port: 8080},
		TLS:      TLSConfig{CACertPath: "./certs/ca.crt", CAKeyPath: "./certs/ca.key"},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "llm"},
		LLMJudge: LLMJudgeConfig{
			Enabled:  true,
			Provider: "bedrock-anthropic",
			Jev:      JevConfig{Enabled: true, APIKey: "k", AllowBelow: threshold(0.3), DenyAbove: threshold(0.7)},
		},
	}
	if err := config.validate(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func threshold(v float64) *float64 { return &v }

func TestJevDefaults(t *testing.T) {
	config := &Config{LLMJudge: LLMJudgeConfig{Jev: JevConfig{Enabled: true}}}
	config.applyDefaults()

	if *config.LLMJudge.Jev.AllowBelow != 0 {
		t.Fatalf("allow_below=%v, want 0 (direct ALLOW is opt-in)", *config.LLMJudge.Jev.AllowBelow)
	}
	if *config.LLMJudge.Jev.DenyAbove != 0.7 {
		t.Fatalf("deny_above=%v, want 0.7", *config.LLMJudge.Jev.DenyAbove)
	}
	if config.LLMJudge.Jev.Model != "jev-1.13.0" {
		t.Fatalf("model=%q, want pinned jev-1.13.0", config.LLMJudge.Jev.Model)
	}
}

func TestJevThresholdsDefaultIndependently(t *testing.T) {
	tests := []struct {
		name                       string
		allowBelow, denyAbove      *float64
		wantAllowBelow, wantDenyAb float64
	}{
		{"both unset", nil, nil, 0, 0.7},
		{"only allow_below set", threshold(0.1), nil, 0.1, 0.7},
		{"only deny_above set", nil, threshold(0.9), 0, 0.9},
		{"both set", threshold(0.2), threshold(0.8), 0.2, 0.8},
		{"explicit zeros", threshold(0), threshold(0), 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{LLMJudge: LLMJudgeConfig{Jev: JevConfig{Enabled: true, AllowBelow: tt.allowBelow, DenyAbove: tt.denyAbove}}}
			config.applyDefaults()
			if got := config.LLMJudge.Jev; *got.AllowBelow != tt.wantAllowBelow || *got.DenyAbove != tt.wantDenyAb {
				t.Fatalf("got allow_below=%v deny_above=%v, want %v and %v", *got.AllowBelow, *got.DenyAbove, tt.wantAllowBelow, tt.wantDenyAb)
			}
		})
	}
}

func TestValidateJevThresholds(t *testing.T) {
	tests := []struct {
		name       string
		allowBelow float64
		denyAbove  float64
		wantErr    string
	}{
		{"equal bounds", 0.5, 0.5, ""},
		{"max bounds", 1, 1, ""},
		{"negative allow_below", -0.1, 0.7, "allow_below must be between"},
		{"allow_below above 1", 1.5, 1, "allow_below must be between"},
		{"negative deny_above", 0, -0.5, "deny_above must be between"},
		{"deny_above above 1", 0.2, 1.5, "deny_above must be between"},
		{"inverted", 0.8, 0.2, "allow_below must be <= deny_above"},
		{"NaN allow_below", math.NaN(), 0.7, "allow_below must be between"},
		{"NaN deny_above", 0.2, math.NaN(), "deny_above must be between"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Proxy:    ProxyConfig{Port: 8080},
				TLS:      TLSConfig{CACertPath: "./certs/ca.crt", CAKeyPath: "./certs/ca.key"},
				Audit:    AuditConfig{Format: "json"},
				Approval: ApprovalConfig{Mode: "llm"},
				LLMJudge: LLMJudgeConfig{
					Enabled:  true,
					Provider: "bedrock-anthropic",
					Jev:      JevConfig{Enabled: true, APIKey: "k", AllowBelow: threshold(tt.allowBelow), DenyAbove: threshold(tt.denyAbove)},
				},
			}
			err := config.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got err %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestJevThresholdsLoadFromYAML(t *testing.T) {
	base := `
proxy:
  port: 8080
tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key
approval:
  mode: llm
audit:
  format: json
database:
  url: "postgres://localhost/x"
llm_judge:
  enabled: true
  provider: openai
  openai_api_key: k
  jev:
    enabled: true
    api_key: k
`
	t.Run("only allow_below", func(t *testing.T) {
		cfg := mustLoadConfig(t, base+"    allow_below: 0.1\n")
		allowBelow, denyAbove := *cfg.LLMJudge.Jev.AllowBelow, *cfg.LLMJudge.Jev.DenyAbove
		if allowBelow != 0.1 || denyAbove != 0.7 {
			t.Fatalf("got %v and %v, want 0.1 and 0.7", allowBelow, denyAbove)
		}
	})
	t.Run("only deny_above", func(t *testing.T) {
		cfg := mustLoadConfig(t, base+"    deny_above: 0.9\n")
		allowBelow, denyAbove := *cfg.LLMJudge.Jev.AllowBelow, *cfg.LLMJudge.Jev.DenyAbove
		if allowBelow != 0 || denyAbove != 0.9 {
			t.Fatalf("got %v and %v, want 0 and 0.9", allowBelow, denyAbove)
		}
	})
	t.Run("explicit zero deny threshold", func(t *testing.T) {
		cfg := mustLoadConfig(t, base+"    allow_below: 0\n    deny_above: 0\n")
		if *cfg.LLMJudge.Jev.AllowBelow != 0 || *cfg.LLMJudge.Jev.DenyAbove != 0 {
			t.Fatal("explicit zero thresholds must survive loading and defaults")
		}
	})
}

func TestDefaultConfigIsValid(t *testing.T) {
	config := Default()
	if err := config.validate(); err != nil {
		t.Fatalf("Default() should produce a valid config, but validate() returned: %v", err)
	}
}

func TestObservabilityMetricsLoadFromYAML(t *testing.T) {
	configContent := `
proxy:
  port: 8080

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stderr
  format: json

database:
  url: "postgres://localhost/x"

observability:
  metrics:
    enabled: true
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "metrics-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Observability.Metrics.Enabled {
		t.Fatal("expected observability.metrics.enabled to be true")
	}
}

func TestObservabilityMetricsDefaultDisabled(t *testing.T) {
	cfg := Default()
	if cfg.Observability.Metrics.Enabled {
		t.Fatal("observability.metrics.enabled should default to false")
	}
}

func TestObservabilityMetricsListenDefaultsToLoopback(t *testing.T) {
	configContent := `
proxy:
  port: 8080
tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key
approval:
  mode: passthrough
audit:
  format: json
database:
  url: "postgres://localhost/x"
observability:
  metrics:
    enabled: true
`
	cfg := mustLoadConfig(t, configContent)
	if cfg.Observability.Metrics.Listen != "127.0.0.1:9090" {
		t.Fatalf("listen defaulted to %q, want %q", cfg.Observability.Metrics.Listen, "127.0.0.1:9090")
	}
}

func TestObservabilityMetricsListenHonorsExplicitValue(t *testing.T) {
	configContent := `
proxy:
  port: 8080
tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key
approval:
  mode: passthrough
audit:
  format: json
database:
  url: "postgres://localhost/x"
observability:
  metrics:
    enabled: true
    listen: "0.0.0.0:9999"
`
	cfg := mustLoadConfig(t, configContent)
	if cfg.Observability.Metrics.Listen != "0.0.0.0:9999" {
		t.Fatalf("listen = %q, want %q", cfg.Observability.Metrics.Listen, "0.0.0.0:9999")
	}
}

func TestObservabilityMetricsListenRejectsMalformedValue(t *testing.T) {
	configContent := `
proxy:
  port: 8080
tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key
approval:
  mode: passthrough
audit:
  format: json
database:
  url: "postgres://localhost/x"
observability:
  metrics:
    enabled: true
    listen: "not-a-host-port"
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "metrics-bogus-listen.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	_, err := Load(configPath)
	if err == nil {
		t.Fatal("expected validation error for malformed listen value")
	}
	if !strings.Contains(err.Error(), "listen") {
		t.Errorf("error should reference listen, got: %v", err)
	}
}

// mustLoadConfig writes content to a tmp file, loads it, and fails the test on error.
func mustLoadConfig(t *testing.T, content string) *Config {
	t.Helper()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestValidateApprovalModeRejectsManual(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "manual"},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for manual approval.mode (no longer supported)")
	}
}

func TestAllowedPrivateCIDRs_LoadFromYAML(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  allowed_private_cidrs:
    - "10.0.0.0/8"
    - "172.16.5.0/24"

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Proxy.AllowedPrivateCIDRs) != 2 {
		t.Fatalf("Expected 2 allowed CIDRs, got %d", len(cfg.Proxy.AllowedPrivateCIDRs))
	}
	if cfg.Proxy.AllowedPrivateCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("Expected first CIDR to be 10.0.0.0/8, got %q", cfg.Proxy.AllowedPrivateCIDRs[0])
	}
	if cfg.Proxy.AllowedPrivateCIDRs[1] != "172.16.5.0/24" {
		t.Errorf("Expected second CIDR to be 172.16.5.0/24, got %q", cfg.Proxy.AllowedPrivateCIDRs[1])
	}
}

func TestAllowedPrivateCIDRs_InvalidCIDRRejected(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  allowed_private_cidrs:
    - "not-a-cidr"

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatal("Expected validation error for invalid CIDR, got nil")
	}
}

func TestAllowedPrivateCIDRs_EmptyByDefault(t *testing.T) {
	cfg := Default()
	if len(cfg.Proxy.AllowedPrivateCIDRs) != 0 {
		t.Errorf("Expected no allowed CIDRs by default, got %v", cfg.Proxy.AllowedPrivateCIDRs)
	}
}

func TestInsecureSkipVerifyHosts_LoadFromYAML(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  insecure_skip_verify_hosts:
    - "internal.example.com"
    - "dev.local"

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Proxy.InsecureSkipVerifyHosts) != 2 {
		t.Fatalf("Expected 2 hosts, got %d", len(cfg.Proxy.InsecureSkipVerifyHosts))
	}
	if cfg.Proxy.InsecureSkipVerifyHosts[0] != "internal.example.com" {
		t.Errorf("Expected first host to be internal.example.com, got %q", cfg.Proxy.InsecureSkipVerifyHosts[0])
	}
	if cfg.Proxy.InsecureSkipVerifyHosts[1] != "dev.local" {
		t.Errorf("Expected second host to be dev.local, got %q", cfg.Proxy.InsecureSkipVerifyHosts[1])
	}
}

func TestInsecureSkipVerifyHosts_EmptyEntryRejected(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{
			Port:                    8080,
			InsecureSkipVerifyHosts: []string{"valid.example.com", ""},
		},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for empty host entry, got nil")
	}
}

func TestInsecureSkipVerifyHosts_PortEntryAccepted(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{
			Port:                    8080,
			InsecureSkipVerifyHosts: []string{"internal.example.com:9001", "dev.local"},
		},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}

	if err := config.validate(); err != nil {
		t.Fatalf("Expected host:port entry to be accepted, got: %v", err)
	}
}

func TestInsecureSkipVerifyHosts_EmptyByDefault(t *testing.T) {
	cfg := Default()
	if len(cfg.Proxy.InsecureSkipVerifyHosts) != 0 {
		t.Errorf("Expected no skip verify hosts by default, got %v", cfg.Proxy.InsecureSkipVerifyHosts)
	}
}

func intPtr(i int) *int { return &i }

func TestRateLimitPerIP_EnabledByDefault(t *testing.T) {
	cfg := Default()
	if cfg.Proxy.RateLimitPerIP == nil || *cfg.Proxy.RateLimitPerIP != 50 {
		t.Errorf("Expected rate_limit_per_ip to default to 50, got %v", cfg.Proxy.RateLimitPerIP)
	}
	if cfg.Proxy.RateLimitBurst != 100 {
		t.Errorf("Expected rate_limit_burst to default to 100, got %d", cfg.Proxy.RateLimitBurst)
	}
}

func TestRateLimitPerIP_ExplicitZeroDisables(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  rate_limit_per_ip: 0

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Proxy.RateLimitPerIP == nil || *cfg.Proxy.RateLimitPerIP != 0 {
		t.Errorf("Expected rate_limit_per_ip to be 0 (explicitly disabled), got %v", cfg.Proxy.RateLimitPerIP)
	}
}

func TestRateLimitPerIP_NegativeRejected(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080, RateLimitPerIP: intPtr(-1)},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}
	config.applyDefaults()

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for negative rate_limit_per_ip")
	}
}

func TestRateLimitBurst_NegativeRejected(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080, RateLimitBurst: -1},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}
	config.applyDefaults()

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for negative rate_limit_burst")
	}
}

func TestRateLimitPerIP_BurstDefaultApplied(t *testing.T) {
	config := Default()
	rate := 50
	config.Proxy.RateLimitPerIP = &rate
	config.Proxy.RateLimitBurst = 0
	config.applyDefaults()

	if config.Proxy.RateLimitBurst != 100 {
		t.Errorf("Expected burst to default to 100 when rate_limit_per_ip is set, got %d", config.Proxy.RateLimitBurst)
	}
}

func TestRateLimitPerIP_PositiveAccepted(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080, RateLimitPerIP: intPtr(50), RateLimitBurst: 100},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}
	config.applyDefaults()

	if err := config.validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}
}

func TestRateLimitPerIP_LoadFromYAML(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  rate_limit_per_ip: 75
  rate_limit_burst: 200

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Proxy.RateLimitPerIP == nil || *cfg.Proxy.RateLimitPerIP != 75 {
		t.Errorf("Expected rate_limit_per_ip 75, got %v", cfg.Proxy.RateLimitPerIP)
	}
	if cfg.Proxy.RateLimitBurst != 200 {
		t.Errorf("Expected rate_limit_burst 200, got %d", cfg.Proxy.RateLimitBurst)
	}
}
