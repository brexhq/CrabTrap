package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestDefaultConfigIsValid(t *testing.T) {
	config := Default()
	if err := config.validate(); err != nil {
		t.Fatalf("Default() should produce a valid config, but validate() returned: %v", err)
	}
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

func TestProbesConfig_Defaults(t *testing.T) {
	cfg := &Config{
		TLS: TLSConfig{CACertPath: "./ca.crt", CAKeyPath: "./ca.key"},
		Probes: ProbesConfig{
			Enabled:  true,
			Endpoint: "http://localhost:8000",
			Model:    "test-model",
			Probes: []ProbeSpec{
				{Name: "exfiltration", Threshold: 0.8},
			},
		},
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.Probes.Timeout == 0 {
		t.Error("Probes.Timeout should have a default")
	}
	if cfg.Probes.MaxTokens != 32 {
		t.Errorf("MaxTokens default = %d, want 32", cfg.Probes.MaxTokens)
	}
	if cfg.Probes.MaxBodyBytes != 8192 {
		t.Errorf("MaxBodyBytes default = %d, want 8192", cfg.Probes.MaxBodyBytes)
	}
	if cfg.Probes.Probes[0].Aggregation != "max" {
		t.Errorf("Aggregation default = %q, want max", cfg.Probes.Probes[0].Aggregation)
	}
}

func TestProbesConfig_ValidationErrors(t *testing.T) {
	baseTLS := TLSConfig{CACertPath: "./ca.crt", CAKeyPath: "./ca.key"}

	cases := []struct {
		name   string
		probes ProbesConfig
		errSub string
	}{
		{
			name:   "enabled without endpoint",
			probes: ProbesConfig{Enabled: true, Model: "m", Probes: []ProbeSpec{{Name: "x", Threshold: 0.5, Aggregation: "max"}}},
			errSub: "probes.endpoint is required",
		},
		{
			name:   "enabled without model",
			probes: ProbesConfig{Enabled: true, Endpoint: "http://x", Probes: []ProbeSpec{{Name: "x", Threshold: 0.5, Aggregation: "max"}}},
			errSub: "probes.model is required",
		},
		{
			name:   "enabled without probes list",
			probes: ProbesConfig{Enabled: true, Endpoint: "http://x", Model: "m"},
			errSub: "at least one probe",
		},
		{
			name:   "empty probe name",
			probes: ProbesConfig{Enabled: true, Endpoint: "http://x", Model: "m", Probes: []ProbeSpec{{Threshold: 0.5, Aggregation: "max"}}},
			errSub: "name is required",
		},
		{
			name: "duplicate probe name",
			probes: ProbesConfig{Enabled: true, Endpoint: "http://x", Model: "m", Probes: []ProbeSpec{
				{Name: "x", Threshold: 0.5, Aggregation: "max"},
				{Name: "x", Threshold: 0.6, Aggregation: "max"},
			}},
			errSub: "duplicate name",
		},
		{
			name:   "threshold out of range",
			probes: ProbesConfig{Enabled: true, Endpoint: "http://x", Model: "m", Probes: []ProbeSpec{{Name: "x", Threshold: 1.5, Aggregation: "max"}}},
			errSub: "threshold must be in [0, 1]",
		},
		{
			name:   "bad aggregation",
			probes: ProbesConfig{Enabled: true, Endpoint: "http://x", Model: "m", Probes: []ProbeSpec{{Name: "x", Threshold: 0.5, Aggregation: "median"}}},
			errSub: "aggregation must be one of",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{TLS: baseTLS, Probes: tc.probes}
			cfg.applyDefaults()
			err := cfg.validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSub)
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("error %q should contain %q", err.Error(), tc.errSub)
			}
		})
	}
}

func TestProbesConfig_DisabledSkipsValidation(t *testing.T) {
	cfg := &Config{
		TLS:    TLSConfig{CACertPath: "./ca.crt", CAKeyPath: "./ca.key"},
		Probes: ProbesConfig{Enabled: false}, // no endpoint, no probes — should be fine
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Errorf("validation should pass when probes disabled, got %v", err)
	}
}
