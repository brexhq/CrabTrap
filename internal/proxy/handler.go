package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/brexhq/CrabTrap/internal/admin"
	"github.com/brexhq/CrabTrap/internal/approval"
	"github.com/brexhq/CrabTrap/internal/audit"
	"github.com/brexhq/CrabTrap/pkg/types"
)

type contextKey int

const (
	contextKeyProxyAuth contextKey = iota
)

// maxBufferedBodySize is the maximum body size to buffer in memory for logging/processing.
// Uploads/downloads larger than this are streamed directly and only partially logged.
const maxBufferedBodySize = 10 * 1024 * 1024 // 10MB

// maxAuditBodySize is the maximum request body size to include in audit log
// entries. Bodies larger than this are truncated to avoid memory spikes when
// denied (or otherwise logged) requests carry large payloads.
const maxAuditBodySize = 8192 // 8KB

// blockedNetworks contains CIDR ranges that the proxy must not connect to
// by default (SSRF protection). These cover loopback, link-local, and
// RFC 1918 private address space for both IPv4 and IPv6.
var blockedNetworks []*net.IPNet

func init() {
	cidrs := []string{
		"0.0.0.0/8",      // "This network" — routes to loopback on Linux
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918 Class A
		"172.16.0.0/12",  // RFC 1918 Class B
		"192.168.0.0/16", // RFC 1918 Class C
		"169.254.0.0/16", // IPv4 link-local
		"100.64.0.0/10",  // Carrier-Grade NAT (RFC 6598)
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local (ULA)
		"fe80::/10",      // IPv6 link-local
		"64:ff9b::/96",   // NAT64 Well-Known Prefix (RFC 6052) — embeds IPv4 in last 4 bytes
		"2002::/16",      // 6to4 addressing (RFC 3056) — embeds IPv4 in bytes 2-5
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("bad blocked CIDR %q: %v", cidr, err))
		}
		blockedNetworks = append(blockedNetworks, network)
	}
}

// nat64Prefix and sixtofourPrefix are parsed once at init time for use in
// extractEmbeddedIPv4. They correspond to the NAT64 and 6to4 CIDR ranges
// added to blockedNetworks above.
var (
	nat64Prefix     *net.IPNet
	sixtofourPrefix *net.IPNet
)

func init() {
	_, nat64Prefix, _ = net.ParseCIDR("64:ff9b::/96")
	_, sixtofourPrefix, _ = net.ParseCIDR("2002::/16")
}

// extractEmbeddedIPv4 returns the IPv4 address embedded within an IPv6
// NAT64 (64:ff9b::/96) or 6to4 (2002::/16) address. If the address does
// not belong to either prefix, nil is returned.
//
//   - NAT64 (RFC 6052): the IPv4 address occupies the last 4 bytes (bytes 12-15).
//   - 6to4  (RFC 3056): the IPv4 address occupies bytes 2-5.
func extractEmbeddedIPv4(ip net.IP) net.IP {
	// Ensure we are working with a 16-byte representation.
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}

	if nat64Prefix.Contains(ip16) {
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	}
	if sixtofourPrefix.Contains(ip16) {
		return net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5])
	}
	return nil
}

// isBlockedIP returns true if the given IP falls within any blocked network,
// unless it is explicitly covered by one of the allowedCIDRs overrides.
// The unspecified address (0.0.0.0 / ::) is always blocked regardless of allowlist.
//
// For defense-in-depth, if the IP is a NAT64 or 6to4 address the function also
// extracts the embedded IPv4 address and checks it against the blocklist. This
// catches cases where the IPv6 representation itself falls within an allowed CIDR
// override (e.g. the entire NAT64 range) but the embedded IPv4 is private.
func isBlockedIP(ip net.IP, allowedCIDRs []*net.IPNet) bool {
	if ip.IsUnspecified() {
		return true
	}

	// IPv6 transition mechanisms (NAT64, 6to4) embed an IPv4 address inside
	// an IPv6 address. An attacker can bypass the IPv4 blocklist by encoding
	// a private IPv4 (e.g. 127.0.0.1) as 64:ff9b::7f00:1. To handle this:
	//
	//  1. The CIDR ranges 64:ff9b::/96 and 2002::/16 are in blockedNetworks
	//     as a catch-all safety net.
	//  2. When a NAT64/6to4 address is detected, we extract the embedded IPv4
	//     and delegate to isBlockedIP on that IPv4. If the embedded IPv4 is
	//     public, the address is allowed; if it is private, it is blocked.
	//
	// This dual approach provides defense-in-depth: the CIDR block catches
	// unknown transition-mechanism variants, while the extraction check allows
	// legitimate public IPv4 addresses encoded in NAT64/6to4.
	if embedded := extractEmbeddedIPv4(ip); embedded != nil {
		return isBlockedIP(embedded, allowedCIDRs)
	}

	for _, network := range blockedNetworks {
		if network.Contains(ip) {
			// Check if this IP is in an allowed CIDR override
			for _, allowed := range allowedCIDRs {
				if allowed.Contains(ip) {
					return false // Explicitly allowed
				}
			}
			return true
		}
	}

	return false
}

// safeDialContext resolves the target hostname, rejects connections where ANY
// resolved IP falls within blocked private/loopback/link-local ranges, and
// dials directly to a validated IP address. This eliminates the TOCTOU window
// that would exist if we resolved, checked, then dialed by hostname (which
// would trigger a second DNS lookup vulnerable to DNS rebinding).
// allowedCIDRs provides exemptions from the default blocklist.
func safeDialContext(ctx context.Context, network, addr string, allowedCIDRs []*net.IPNet) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safeDialContext: invalid address %q: %w", addr, err)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("safeDialContext: DNS lookup failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("safeDialContext: no addresses found for %q", host)
	}

	// Block if ANY resolved IP is private/loopback/link-local. A mixed-result
	// DNS response (public + private) is treated as suspicious.
	for _, ip := range ips {
		if isBlockedIP(ip.IP, allowedCIDRs) {
			return nil, fmt.Errorf("safeDialContext: blocked: %q resolves to private IP %s", host, ip.IP)
		}
	}

	// All IPs are public — dial directly to the first validated IP to avoid a
	// second DNS lookup (TOCTOU / DNS rebinding protection).
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// safeResolveAndCheckHost resolves a hostname, checks that no resolved IP
// falls within blocked ranges, and returns a validated IP address that callers
// must use for dialing. This prevents TOCTOU / DNS rebinding attacks by
// ensuring the checked IP is the same one used for the connection.
// allowedCIDRs provides exemptions from the default blocklist.
func safeResolveAndCheckHost(ctx context.Context, host string, allowedCIDRs []*net.IPNet) (net.IP, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %q", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip.IP, allowedCIDRs) {
			return nil, fmt.Errorf("blocked: %q resolves to private IP %s", host, ip.IP)
		}
	}
	return ips[0].IP, nil
}

// LLMResponseWriter persists an LLM response row and returns its ID.
// Satisfied by eval.PGStore.
type LLMResponseWriter interface {
	CreateLLMResponse(r types.LLMResponse) (string, error)
}

// Handler handles HTTP/HTTPS proxy requests
type Handler struct {
	tlsManager        *TLSManager
	approvalManager   *approval.Manager
	auditLogger       *audit.Logger
	auditReader       admin.AuditReaderIface
	userResolver      admin.UserResolver
	llmResponseWriter LLMResponseWriter // nil if llm_responses persistence disabled
	client            *http.Client

	// allowedPrivateCIDRs lists CIDR ranges exempted from the default SSRF
	// blocklist. IPs falling within these ranges will not be blocked even if
	// they match a blocked network (except for the unspecified address).
	allowedPrivateCIDRs []*net.IPNet

	// insecureSkipUpstreamVerify disables TLS certificate verification on
	// upstream (proxy-to-server) connections. When false (the default), Go's
	// standard TLS stack validates the upstream certificate against the system
	// trust store.
	insecureSkipUpstreamVerify bool

	// insecureSkipVerifyHosts limits TLS verification skip to the listed
	// hostnames. When non-empty, only connections to these hosts skip
	// certificate verification, regardless of insecureSkipUpstreamVerify.
	// When empty and insecureSkipUpstreamVerify is true, ALL hosts skip
	// verification (legacy global behaviour).
	insecureSkipVerifyHosts map[string]bool

	// rateLimiter performs per-source-IP rate limiting at the ServeHTTP entry
	// point. Nil when rate limiting is disabled (rate_limit_per_ip is 0).
	rateLimiter *ipRateLimiter
}

// NewHandler creates a new proxy handler.
// When insecureSkipUpstreamVerify is true, the proxy skips TLS certificate
// verification on upstream connections (for self-signed certs or testing).
func NewHandler(tlsManager *TLSManager, approvalManager *approval.Manager, auditLogger *audit.Logger, auditReader admin.AuditReaderIface, userResolver admin.UserResolver, insecureSkipUpstreamVerify bool) *Handler {
	h := &Handler{
		tlsManager:                 tlsManager,
		approvalManager:            approvalManager,
		auditLogger:                auditLogger,
		auditReader:                auditReader,
		userResolver:               userResolver,
		insecureSkipUpstreamVerify: insecureSkipUpstreamVerify,
	}

	// Create HTTP client with custom transport. The dial function is set via
	// initClient so it can reference h.allowedPrivateCIDRs.
	h.initClient()

	return h
}

// shouldSkipTLSVerify returns true if TLS certificate verification should be
// skipped for the given host and port. When insecureSkipVerifyHosts is
// non-empty, it checks for "host:port" first (port-specific match), then
// falls back to bare "host" (matches all ports). When the map is empty,
// the global insecureSkipUpstreamVerify flag is used.
func (h *Handler) shouldSkipTLSVerify(host, port string) bool {
	if len(h.insecureSkipVerifyHosts) > 0 {
		lower := strings.ToLower(host)
		if port != "" {
			if h.insecureSkipVerifyHosts[lower+":"+port] {
				return true
			}
		}
		return h.insecureSkipVerifyHosts[lower]
	}
	return h.insecureSkipUpstreamVerify
}

// initClient creates the HTTP client with the appropriate dialer based on
// the allowedPrivateCIDRs setting. Must be called after allowedPrivateCIDRs
// is set if non-default behaviour is desired.
func (h *Handler) initClient() {
	allowedCIDRs := h.allowedPrivateCIDRs
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return safeDialContext(ctx, network, addr, allowedCIDRs)
	}

	transport := &http.Transport{
		DialContext:           dialFunc,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if len(h.insecureSkipVerifyHosts) > 0 {
		// Per-host TLS verification: use DialTLSContext to decide per connection.
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			plainConn, err := safeDialContext(ctx, network, addr, allowedCIDRs)
			if err != nil {
				return nil, err
			}
			host, port, _ := net.SplitHostPort(addr)
			tlsCfg := &tls.Config{
				InsecureSkipVerify: h.shouldSkipTLSVerify(host, port),
				ServerName:         host,
			}
			tlsConn := tls.Client(plainConn, tlsCfg)
			// When DialTLSContext is set, Go skips its own TLSHandshakeTimeout,
			// so we enforce a 10s handshake deadline explicitly.
			hsCtx, hsCancel := context.WithTimeout(ctx, 10*time.Second)
			defer hsCancel()
			if err := tlsConn.HandshakeContext(hsCtx); err != nil {
				plainConn.Close()
				return nil, err
			}
			return tlsConn, nil
		}
	} else {
		// Global mode: single TLS config for all connections.
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: h.insecureSkipUpstreamVerify,
		}
	}

	h.client = &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

// multiReadCloser pairs an io.MultiReader (for reading) with the original response
// body (for closing), so that Close properly releases the underlying HTTP connection
// even when the body is not fully drained by the caller.
type multiReadCloser struct {
	io.Reader
	closer io.Closer
}

func (m *multiReadCloser) Close() error {
	return m.closer.Close()
}

// errorResponse builds a synthetic *http.Response that is safe to write directly
// to a raw TCP/TLS connection (e.g. via serveTLS). It sets ContentLength so the
// client knows when the body ends, and Connection: close so serveTLS does not
// loop waiting for a next request that will never come after an error.
func errorResponse(statusCode int, contentType, body string) *http.Response {
	b := []byte(body)
	h := make(http.Header)
	h.Set("Content-Type", contentType)
	h.Set("Connection", "close")
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		StatusCode:    statusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewReader(b)),
		Header:        h,
		ContentLength: int64(len(b)),
	}
}

// proxyAuth holds the credentials extracted from a Proxy-Authorization header.
// Format: Basic base64(gat_xxx:)
type proxyAuth struct {
	gatewayToken string // username position — must have gat_ prefix to be valid
}

// extractProxyAuth parses a Proxy-Authorization: Basic header.
// Username → gatewayToken (only set if it has the gat_ prefix).
// Returns an error if the header contains a non-Basic auth scheme (e.g. Bearer),
// so callers can reject unsupported schemes instead of silently treating the
// request as unauthenticated.
func extractProxyAuth(header string) (proxyAuth, error) {
	if header == "" {
		return proxyAuth{}, nil
	}
	// RFC 7235: auth-scheme comparison is case-insensitive.
	const prefixLen = len("Basic ")
	if len(header) < prefixLen || !strings.EqualFold(header[:prefixLen], "Basic ") {
		return proxyAuth{}, fmt.Errorf("unsupported auth scheme in Proxy-Authorization header: only Basic is supported")
	}
	encoded := header[prefixLen:]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return proxyAuth{}, nil
		}
	}
	colon := strings.IndexByte(string(decoded), ':')
	var username string
	if colon >= 0 {
		username = string(decoded[:colon])
	} else {
		username = string(decoded)
	}
	var auth proxyAuth
	if strings.HasPrefix(username, "gat_") {
		auth.gatewayToken = username
	}
	return auth, nil
}

// unsupportedAuthSchemeResponse returns a 407 response indicating that only Basic
// proxy authentication is supported. Used when the client sends a non-Basic scheme
// (e.g. Bearer) in the Proxy-Authorization header.
func unsupportedAuthSchemeResponse() *http.Response {
	body := []byte("Unsupported proxy authentication scheme. Only Basic authentication is supported. Set Proxy-Authorization: Basic base64(gat_xxx:) or HTTP_PROXY=http://gat_xxx:@host:port")
	h := make(http.Header)
	h.Set("Proxy-Authenticate", `Basic realm="CrabTrap"`)
	h.Set("Content-Type", "text/plain")
	h.Set("Connection", "close")
	return &http.Response{
		Status:        "407 Proxy Authentication Required",
		StatusCode:    http.StatusProxyAuthRequired,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewReader(body)),
		Header:        h,
		ContentLength: int64(len(body)),
	}
}

// proxyAuthRequiredResponse returns a 407 response requesting Basic proxy authentication.
func proxyAuthRequiredResponse() *http.Response {
	body := []byte("Proxy authentication required. Set Proxy-Authorization: Basic base64(gat_xxx:) or HTTP_PROXY=http://gat_xxx:@host:port")
	h := make(http.Header)
	h.Set("Proxy-Authenticate", `Basic realm="CrabTrap"`)
	h.Set("Content-Type", "text/plain")
	h.Set("Connection", "close")
	return &http.Response{
		Status:        "407 Proxy Authentication Required",
		StatusCode:    http.StatusProxyAuthRequired,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewReader(body)),
		Header:        h,
		ContentLength: int64(len(body)),
	}
}

// ServeHTTP handles proxy requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Per-IP rate limiting — checked first, before any expensive work
	// (request ID generation, TLS cert generation, LLM calls, etc.).
	if rateLimitMiddleware(h.rateLimiter, w, r) {
		return
	}

	// Generate request ID
	requestID := generateRequestID()

	startTime := time.Now()

	// Handle CONNECT method for HTTPS
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r, requestID, startTime)
		return
	}

	// Handle regular HTTP requests
	h.handleHTTP(w, r, requestID, startTime)
}

// handleConnect handles HTTPS CONNECT tunneling
func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request, requestID string, startTime time.Time) {
	// Extract proxy auth from CONNECT request (authenticated once for the whole tunnel).
	tunnelAuth, authErr := extractProxyAuth(r.Header.Get("Proxy-Authorization"))
	if authErr != nil {
		slog.Warn("CONNECT unsupported auth scheme, returning 407", "request_id", requestID)
		w.Header().Set("Proxy-Authenticate", `Basic realm="CrabTrap"`)
		http.Error(w, "Unsupported proxy authentication scheme. Only Basic authentication is supported. Set Proxy-Authorization: Basic base64(gat_xxx:) or HTTP_PROXY=http://gat_xxx:@host:port", http.StatusProxyAuthRequired)
		return
	}

	// --- Early authentication gate for CONNECT requests ---
	// Validate credentials BEFORE certificate generation or connection hijacking
	// to prevent unauthenticated clients from triggering expensive crypto operations.
	if h.userResolver != nil {
		if tunnelAuth.gatewayToken == "" {
			slog.Warn("CONNECT gateway auth missing, returning 407", "request_id", requestID)
			w.Header().Set("Proxy-Authenticate", `Basic realm="CrabTrap"`)
			http.Error(w, "Proxy authentication required. Set Proxy-Authorization: Basic base64(gat_xxx:) or HTTP_PROXY=http://gat_xxx:@host:port", http.StatusProxyAuthRequired)
			return
		}
		if _, ok := h.userResolver.GetUserByGatewayAuthToken(tunnelAuth.gatewayToken); !ok {
			slog.Warn("CONNECT gateway auth token invalid, returning 407", "request_id", requestID)
			w.Header().Set("Proxy-Authenticate", `Basic realm="CrabTrap"`)
			http.Error(w, "Proxy authentication required. Set Proxy-Authorization: Basic base64(gat_xxx:) or HTTP_PROXY=http://gat_xxx:@host:port", http.StatusProxyAuthRequired)
			return
		}
	}

	// Extract host
	host := r.Host

	// Strip port from host for certificate generation
	// CONNECT requests include port (e.g., "httpbin.org:443")
	// but certificates should only have hostname (e.g., "httpbin.org")
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	// Get certificate for this host
	cert, err := h.tlsManager.GetCertificate(hostname)
	if err != nil {
		slog.Error("failed to get certificate", "request_id", requestID, "hostname", hostname, "error", err)
		http.Error(w, "Failed to get certificate", http.StatusInternalServerError)
		return
	}

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("ResponseWriter does not support hijacking", "request_id", requestID)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		slog.Error("failed to hijack connection", "request_id", requestID, "error", err)
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		slog.Error("failed to write connection established", "request_id", requestID, "error", err)
		return
	}

	// Create TLS connection
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		if err.Error() == "EOF" || err == io.EOF {
			slog.Warn("TLS handshake failed: client rejected certificate (not trusted)", "request_id", requestID, "ca_cert_path", h.tlsManager.CACertPath())
		} else {
			slog.Error("TLS handshake failed", "request_id", requestID, "error", err)
		}
		return
	}

	// Now read and process HTTPS requests (pass tunnel auth for the whole tunnel).
	// requestID is forwarded as the tunnelID so inner requests can be correlated
	// back to the CONNECT that established this tunnel.
	h.serveTLS(tlsConn, requestID, tunnelAuth, hostname)
}

// serveTLS serves HTTPS requests over the TLS connection.
// tunnelID is the requestID from the original CONNECT request that established
// this tunnel; it is logged alongside each inner request so forensic analysis
// can correlate individual requests back to the tunnel they arrived on.
// auth is the proxy auth extracted from the CONNECT request (may be zero value).
// connectHostname is the hostname from the original CONNECT target; inner
// requests whose Host header doesn't match are rejected to prevent SSRF via
// Host header manipulation inside CONNECT tunnels.
func (h *Handler) serveTLS(tlsConn *tls.Conn, tunnelID string, auth proxyAuth, connectHostname string) {
	// Build a cancellable base context so that when the TLS loop exits (client
	// disconnected, read error, etc.) all in-flight upstream requests and DNS
	// lookups derived from this context are promptly cancelled.
	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()

	// Carry the proxy auth so processRequest can find it without needing
	// another Proxy-Authorization header on each inner request.
	if auth.gatewayToken != "" {
		baseCtx = context.WithValue(baseCtx, contextKeyProxyAuth, auth)
	}

	// Read requests from the TLS connection
	reader := bufio.NewReader(tlsConn)

	// Extract client IP once for rate limiting inner requests within
	// this CONNECT tunnel (the initial CONNECT was already rate-limited
	// in ServeHTTP, but inner requests must also be checked).
	var tunnelClientIP string
	if h.rateLimiter != nil {
		if host, _, err := net.SplitHostPort(tlsConn.RemoteAddr().String()); err == nil {
			tunnelClientIP = host
		}
	}

	for {
		// Parse HTTP request (blocks until the client sends the next request
		// on the keep-alive connection).
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				slog.Error("failed to read request in tunnel", "tunnel_id", tunnelID, "error", err)
			}
			return
		}

		// Rate-limit inner requests within the CONNECT tunnel.
		if h.rateLimiter != nil && tunnelClientIP != "" && !h.rateLimiter.Allow(tunnelClientIP) {
			slog.Debug("rate-limited tunnel inner request", "tunnel_id", tunnelID, "ip", tunnelClientIP)
			resp := errorResponse(http.StatusTooManyRequests, "text/plain", "Too Many Requests")
			resp.Header.Set("Retry-After", "1")
			resp.Header.Set("Connection", "close")
			resp.Write(tlsConn)
			return
		}

		// Generate a fresh requestID and startTime AFTER ReadRequest returns
		// so that DurationMs in audit entries measures actual processing time,
		// not idle keep-alive wait.
		requestID := generateRequestID()
		startTime := time.Now()

		slog.Debug("processing request in tunnel", "request_id", requestID, "tunnel_id", tunnelID, "method", req.Method, "url", req.URL.String())

		// Fix request URL (ReadRequest doesn't set scheme/host)
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		req.RequestURI = ""

		// Validate that the inner request's Host matches the CONNECT target
		// to prevent SSRF via Host header manipulation inside tunnels.
		if connectHostname != "" {
			innerHost := req.Host
			if h, _, err := net.SplitHostPort(innerHost); err == nil {
				innerHost = h
			}
			if !strings.EqualFold(innerHost, connectHostname) {
				slog.Warn("SSRF blocked: inner Host does not match CONNECT target", "request_id", requestID, "inner_host", req.Host, "connect_target", connectHostname)
				resp := errorResponse(http.StatusForbidden, "text/plain",
					fmt.Sprintf("Forbidden: inner request Host %q does not match CONNECT tunnel target %q", innerHost, connectHostname))
				resp.Write(tlsConn)
				return
			}
		}

		// Validate auth scheme on inner requests when the tunnel does not
		// carry pre-authenticated credentials in baseCtx. Write the 407
		// directly so it is not stripped by stripHopByHopHeaders later.
		if _, ok := baseCtx.Value(contextKeyProxyAuth).(proxyAuth); !ok {
			if _, authErr := extractProxyAuth(req.Header.Get("Proxy-Authorization")); authErr != nil {
				slog.Warn("TLS inner request: unsupported auth scheme, returning 407", "request_id", requestID)
				resp := unsupportedAuthSchemeResponse()
				resp.Write(tlsConn)
				return
			}
		}

		// WebSocket upgrade: run approval then relay, consuming the connection.
		if isWebSocketUpgrade(req) {
			result := h.processUpgradeApproval(req, requestID, startTime, baseCtx)
			if !result.approved {
				result.denyResp.Write(tlsConn)
				result.denyResp.Body.Close()
				return
			}
			h.handleWebSocketUpgrade(tlsConn, reader, req, requestID, startTime, result.userID, result.decision, result.llmResponseID, baseCtx)
			return
		}

		// Process the request
		resp := h.processRequest(req, requestID, startTime, baseCtx)

		// Determine keep-alive BEFORE stripping hop-by-hop headers,
		// since Connection: close is a hop-by-hop header that influences
		// whether we should continue the loop.
		keepAlive := h.shouldKeepAlive(req, resp)

		// Strip hop-by-hop headers from the upstream response before forwarding to client.
		stripHopByHopHeaders(resp.Header, false)

		// Write response back to client
		if err := resp.Write(tlsConn); err != nil {
			slog.Error("failed to write response", "request_id", requestID, "error", err)
			resp.Body.Close()
			return
		}

		// Close the response body to return the upstream connection to the
		// transport pool. Without this, each response in a keep-alive tunnel
		// leaks a connection until GC.
		resp.Body.Close()

		// Close if not keep-alive
		if !keepAlive {
			return
		}
	}
}

// handleHTTP handles regular HTTP requests
func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request, requestID string, startTime time.Time) {
	// Validate auth scheme early, before the request enters processRequest /
	// processUpgradeApproval whose *http.Response would flow through
	// stripHopByHopHeaders and lose the Proxy-Authenticate header that
	// RFC 7235 requires on 407 responses.
	if _, authErr := extractProxyAuth(r.Header.Get("Proxy-Authorization")); authErr != nil {
		slog.Warn("unsupported auth scheme, returning 407", "request_id", requestID)
		w.Header().Set("Proxy-Authenticate", `Basic realm="CrabTrap"`)
		http.Error(w, "Unsupported proxy authentication scheme. Only Basic authentication is supported. Set Proxy-Authorization: Basic base64(gat_xxx:) or HTTP_PROXY=http://gat_xxx:@host:port", http.StatusProxyAuthRequired)
		return
	}

	if isWebSocketUpgrade(r) {
		h.handleHTTPWebSocket(w, r, requestID, startTime)
		return
	}

	// Process the request (no pre-authenticated tunnel context for plain HTTP).
	// Pass the client request's context so upstream calls are canceled when the
	// client disconnects or the server shuts down.
	resp := h.processRequest(r, requestID, startTime, r.Context())
	defer resp.Body.Close()

	// Strip hop-by-hop headers from the upstream response before forwarding to client.
	stripHopByHopHeaders(resp.Header, false)

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

// handleHTTPWebSocket handles a WebSocket upgrade over plain HTTP.
func (h *Handler) handleHTTPWebSocket(w http.ResponseWriter, r *http.Request, requestID string, startTime time.Time) {
	result := h.processUpgradeApproval(r, requestID, startTime, r.Context())
	if !result.approved {
		for key, values := range result.denyResp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(result.denyResp.StatusCode)
		io.Copy(w, result.denyResp.Body)
		result.denyResp.Body.Close()
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("ResponseWriter does not support hijacking for WebSocket", "request_id", requestID)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		slog.Error("failed to hijack for WebSocket", "request_id", requestID, "error", err)
		return
	}
	defer clientConn.Close()

	h.handleWebSocketUpgrade(clientConn, clientBuf, r, requestID, startTime, result.userID, result.decision, result.llmResponseID, r.Context())
}

// approvalResult holds the outcome of processUpgradeApproval.
type approvalResult struct {
	decision      types.ApprovalDecision
	userID        string
	llmResponseID string // persisted llm_responses row ID (if judge ran)
	approved      bool
	denyResp      *http.Response // non-nil when approved==false
}

// processUpgradeApproval runs authentication, user resolution, and the approval
// flow for the given request. It does NOT forward upstream — callers decide what
// to do with an approved request (normal HTTP forwarding vs WebSocket relay).
func (h *Handler) processUpgradeApproval(r *http.Request, requestID string, startTime time.Time, baseCtx context.Context) approvalResult {
	ctx := baseCtx

	// Resolve proxy auth: from tunnel context (HTTPS) or per-request Proxy-Authorization (HTTP).
	auth, hasContextAuth := ctx.Value(contextKeyProxyAuth).(proxyAuth)
	if !hasContextAuth {
		var authErr error
		auth, authErr = extractProxyAuth(r.Header.Get("Proxy-Authorization"))
		if authErr != nil {
			slog.Warn("unsupported auth scheme, returning 407", "request_id", requestID)
			return approvalResult{denyResp: unsupportedAuthSchemeResponse()}
		}
	}
	// Always strip Proxy-Authorization before forwarding upstream.
	r.Header.Del("Proxy-Authorization")

	// --- User identification via gateway auth token ---
	var gatewayUserID string
	if h.userResolver != nil && auth.gatewayToken != "" {
		if uid, ok := h.userResolver.GetUserByGatewayAuthToken(auth.gatewayToken); ok {
			gatewayUserID = uid
			ctx = context.WithValue(ctx, approval.ContextKeyUserID, uid)
			if policy := h.userResolver.GetLLMPolicyForUser(uid); policy != nil {
				ctx = context.WithValue(ctx, approval.ContextKeyLLMPolicy, policy)
			}
		}
	}

	// --- Gateway auth gate ---
	if h.userResolver != nil {
		if auth.gatewayToken == "" {
			slog.Warn("gateway auth missing, returning 407", "request_id", requestID)
			return approvalResult{denyResp: proxyAuthRequiredResponse()}
		}
		if gatewayUserID == "" {
			slog.Warn("gateway auth token invalid, returning 407", "request_id", requestID)
			return approvalResult{denyResp: proxyAuthRequiredResponse()}
		}
	}

	// Capture headers/body for audit logging, capped like processRequest.
	originalHeaders := r.Header.Clone()
	var requestBody []byte
	var requestBodyTruncated bool
	if r.Body != nil {
		lr := &io.LimitedReader{R: r.Body, N: maxBufferedBodySize + 1}
		var readErr error
		requestBody, readErr = io.ReadAll(lr)
		requestBodyTruncated = lr.N == 0
		if readErr != nil {
			slog.Error("failed to read request body", "request_id", requestID, "error", readErr)
		}
		if requestBodyTruncated {
			// Body exceeds cap: reconstruct full streaming body so upstream
			// still receives the complete payload if forwarded.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(requestBody), lr.R))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(requestBody))
		}
	}

	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug("request", "request_id", requestID, "method", r.Method, "url", r.URL.String())

		for key, values := range originalHeaders {
			if isSensitiveHeader(key) {
				slog.Debug("request header", "request_id", requestID, "key", key, "value", "[REDACTED]")
				continue
			}
			for _, value := range values {
				displayValue := value
				if len(value) > 80 {
					displayValue = value[:77] + "..."
				}
				slog.Debug("request header", "request_id", requestID, "key", key, "value", displayValue)
			}
		}

		if len(requestBody) > 0 {
			slog.Debug("request body", "request_id", requestID, "body", h.formatBody(requestBody, requestID))
		}
	}

	// Check approval.
	slog.Debug("checking approval requirements", "request_id", requestID)

	// Decompress request body for LLM eval (same logic as processRequest).
	wsEvalBody := requestBody
	wsEvalHeaders := originalHeaders
	if ce := strings.Join(originalHeaders.Values("Content-Encoding"), ", "); ce != "" && len(requestBody) > 0 {
		if decoded, ok := decompressRequestBody(requestBody, ce, requestID); ok {
			wsEvalBody = decoded
			wsEvalHeaders = originalHeaders.Clone()
			wsEvalHeaders.Del("Content-Encoding")
			wsEvalHeaders.Del("Content-Length")
		}
		// If decompression failed, keep original body + Content-Encoding header.
	}
	ctx = context.WithValue(ctx, approval.ContextKeyBufferedBody, requestBody)
	ctx = context.WithValue(ctx, approval.ContextKeyOriginalHeaders, wsEvalHeaders)
	ctx = context.WithValue(ctx, approval.ContextKeyOriginalBody, wsEvalBody)
	decision, _, approvalErr := h.approvalManager.CheckApproval(ctx, r, requestID, nil)
	if approvalErr != nil {
		slog.Error("approval error", "request_id", requestID, "error", approvalErr)
		e := newEntry(requestID, r, originalHeaders, startTime, gatewayUserID)
		e.Decision = "ERROR"
		e.ResponseStatus = 500
		e.Error = approvalErr.Error()
		h.logEntry(e)
		return approvalResult{denyResp: errorResponse(http.StatusInternalServerError, "text/plain", "Approval check failed")}
	}

	llmResponseID := h.persistLLMResponse(requestID, decision.LLMResponse)

	switch decision.Decision {
	case types.DecisionAllow:
		if decision.ApprovedBy == "cache" {
			slog.Debug("request approved", "request_id", requestID, "approved_by", "cache")
		} else if decision.ApprovedBy != "" {
			slog.Debug("request approved", "request_id", requestID, "approved_by", decision.ApprovedBy)
		} else {
			slog.Debug("request approved", "request_id", requestID)
		}
		return approvalResult{decision: decision, userID: gatewayUserID, llmResponseID: llmResponseID, approved: true}

	case types.DecisionDeny:
		slog.Debug("request denied", "request_id", requestID, "reason", decision.Reason)
		headers := make(http.Header)
		headers.Set("Connection", "close")
		e := newEntry(requestID, r, originalHeaders, startTime, gatewayUserID)
		e.Decision = "denied"
		e.ResponseStatus = 403
		e.RequestBody = truncateBodyForAudit(requestBody)
		e.ResponseHeaders = headers
		applyDecision(&e, decision, llmResponseID, decision.Reason)
		h.logEntry(e)
		slog.Debug("returning 403 response to client", "request_id", requestID)
		return approvalResult{
			decision: decision,
			userID:   gatewayUserID,
			denyResp: &http.Response{
				Status:     "403 Forbidden",
				StatusCode: http.StatusForbidden,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Body:       io.NopCloser(bytes.NewReader([]byte{})),
				Header:     headers,
			},
		}

	case types.DecisionTimeout:
		slog.Warn("approval request timed out", "request_id", requestID)
		headers := make(http.Header)
		headers.Set("Connection", "close")
		e := newEntry(requestID, r, originalHeaders, startTime, gatewayUserID)
		e.Decision = "timeout"
		e.ResponseStatus = 408
		e.RequestBody = truncateBodyForAudit(requestBody)
		e.ResponseHeaders = headers
		h.logEntry(e)
		return approvalResult{
			decision: decision,
			userID:   gatewayUserID,
			denyResp: &http.Response{
				Status:     "408 Request Timeout",
				StatusCode: http.StatusRequestTimeout,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Body:       io.NopCloser(bytes.NewReader([]byte{})),
				Header:     headers,
			},
		}

	default:
		slog.Error("unknown approval decision", "request_id", requestID, "decision", decision.Decision)
		return approvalResult{
			decision: decision,
			userID:   gatewayUserID,
			denyResp: errorResponse(http.StatusInternalServerError, "text/plain", "Unknown approval decision"),
		}
	}
}

// wsIdleTimeout is the duration of inactivity after which a WebSocket
// connection is closed. Each successful data transfer resets the timer
// on both sides of the relay.
//
// These are vars (not consts) so that tests can temporarily shorten them
// without waiting for the full production durations.
var wsIdleTimeout = 30 * time.Minute

// wsWriteTimeout is the maximum time a single write may block before the
// destination is considered a slow client and the connection is torn down.
// This prevents a slow reader on one side from blocking the relay loop,
// which would stop read-deadline resets and eventually kill the other side.
var wsWriteTimeout = 30 * time.Second

// wsDrainTimeout bounds how long the surviving relay direction may continue
// draining data after the first direction has terminated. Without this cap,
// the surviving side could hang for up to wsIdleTimeout (30 minutes) on a
// half-closed TLS connection where the peer never sends data.
var wsDrainTimeout = 5 * time.Second

// wsRelayWriter wraps a destination writer and manages deadlines so that:
//  1. A per-write deadline (wsWriteTimeout) is set before each Write, ensuring
//     slow/stalled writers are detected quickly without waiting for the full
//     idle timeout.
//  2. After a successful write, the read deadline on all tracked connections
//     is refreshed to the idle timeout, keeping active sessions alive.
//
// Only SetReadDeadline is used for idle detection (not SetDeadline) so that
// the write deadline and idle deadline do not interfere with each other.
type wsRelayWriter struct {
	dst      net.Conn   // destination connection (supports SetWriteDeadline)
	readFrom []net.Conn // connections whose read deadlines are refreshed on activity
	idle     time.Duration
	write    time.Duration
}

func (w *wsRelayWriter) Write(b []byte) (int, error) {
	// Set a per-write deadline so that writing to a slow/stalled client
	// fails fast rather than blocking until the idle timeout fires.
	w.dst.SetWriteDeadline(time.Now().Add(w.write))
	n, err := w.dst.Write(b)
	if n > 0 {
		// Data was delivered — reset the idle read deadline on both sides
		// so that active sessions are not torn down.
		deadline := time.Now().Add(w.idle)
		for _, c := range w.readFrom {
			c.SetReadDeadline(deadline)
		}
	}
	return n, err
}

// halfCloser is implemented by connections that support closing only the write
// half (e.g. *net.TCPConn, *tls.Conn). Closing the write half sends a FIN to
// the peer, signalling end-of-stream while still allowing reads.
type halfCloser interface {
	CloseWrite() error
}

// closeWrite performs a half-close (write-side only) on the connection if
// supported (e.g. *net.TCPConn, *tls.Conn), allowing the other direction
// of the relay to drain remaining data. If the connection does not support
// half-close, falls back to a full Close which terminates both directions
// immediately.
func closeWrite(c net.Conn) {
	if hc, ok := c.(halfCloser); ok {
		hc.CloseWrite()
	} else {
		c.Close()
	}
}

// handleWebSocketUpgrade handles an approved WebSocket upgrade by dialing
// upstream, forwarding the upgrade handshake, and relaying bytes bidirectionally.
func (h *Handler) handleWebSocketUpgrade(clientConn net.Conn, clientBuf io.Reader, r *http.Request, requestID string, startTime time.Time, userID string, decision types.ApprovalDecision, llmResponseID string, ctx context.Context) {
	slog.Debug("WebSocket upgrade", "request_id", requestID, "url", r.URL.String())

	// Dial upstream.
	var upstreamConn net.Conn
	var err error
	targetHost := r.URL.Host
	if targetHost == "" {
		targetHost = r.Host
	}

	if r.URL.Scheme == "https" || r.URL.Scheme == "wss" {
		host, port, splitErr := net.SplitHostPort(targetHost)
		if splitErr != nil {
			host = targetHost
			port = "443"
			targetHost = targetHost + ":443"
		}
		// Resolve and check IPs, then dial the validated IP directly (SSRF + TOCTOU protection).
		validatedIP, checkErr := safeResolveAndCheckHost(ctx, host, h.allowedPrivateCIDRs)
		if checkErr != nil {
			slog.Warn("WebSocket TLS SSRF blocked", "request_id", requestID, "error", checkErr)
			resp := errorResponse(http.StatusForbidden, "text/plain", "Forbidden: destination resolves to blocked address")
			resp.Write(clientConn)
			h.logWebSocketEntry(requestID, r, r.Header.Clone(), startTime, userID, decision, llmResponseID, 403)
			return
		}
		dialAddr := net.JoinHostPort(validatedIP.String(), port)
		upstreamConn, err = (&tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 30 * time.Second},
			Config: &tls.Config{
				InsecureSkipVerify: h.shouldSkipTLSVerify(host, port),
				ServerName:         host,
			},
		}).DialContext(ctx, "tcp", dialAddr)
	} else {
		if _, _, splitErr := net.SplitHostPort(targetHost); splitErr != nil {
			targetHost = targetHost + ":80"
		}
		// Resolve and check IPs, then dial the validated IP directly (SSRF + TOCTOU protection).
		plainHost, port, splitErr := net.SplitHostPort(targetHost)
		if splitErr != nil {
			plainHost = targetHost
			port = "80"
		}
		validatedIP, checkErr := safeResolveAndCheckHost(ctx, plainHost, h.allowedPrivateCIDRs)
		if checkErr != nil {
			slog.Warn("WebSocket SSRF blocked", "request_id", requestID, "error", checkErr)
			resp := errorResponse(http.StatusForbidden, "text/plain", "Forbidden: destination resolves to blocked address")
			resp.Write(clientConn)
			h.logWebSocketEntry(requestID, r, r.Header.Clone(), startTime, userID, decision, llmResponseID, 403)
			return
		}
		dialAddr := net.JoinHostPort(validatedIP.String(), port)
		upstreamConn, err = (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", dialAddr)
	}
	if err != nil {
		slog.Error("WebSocket failed to dial upstream", "request_id", requestID, "target", targetHost, "error", err)
		resp := errorResponse(http.StatusBadGateway, "text/plain", "Failed to connect to upstream")
		resp.Write(clientConn)
		h.logWebSocketEntry(requestID, r, r.Header.Clone(), startTime, userID, decision, llmResponseID, 502)
		return
	}
	defer upstreamConn.Close()

	// Capture original headers for audit logging before stripping hop-by-hop
	// headers. The audit log should record the original client headers
	// (including potentially malicious Connection-designated headers) for
	// forensic analysis.
	originalHeaders := r.Header.Clone()

	// Strip hop-by-hop headers from the upgrade request, preserving
	// Connection: Upgrade and Upgrade: websocket which are required for the
	// WebSocket handshake.
	stripHopByHopHeaders(r.Header, true)

	// Write the upgrade request to upstream.
	if err := r.Write(upstreamConn); err != nil {
		slog.Error("WebSocket failed to write upgrade request", "request_id", requestID, "error", err)
		resp := errorResponse(http.StatusBadGateway, "text/plain", "Failed to send upgrade request")
		resp.Write(clientConn)
		h.logWebSocketEntry(requestID, r, originalHeaders, startTime, userID, decision, llmResponseID, 502)
		return
	}

	// Read upstream's response.
	upstreamBuf := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamBuf, r)
	if err != nil {
		slog.Error("WebSocket failed to read upstream response", "request_id", requestID, "error", err)
		errResp := errorResponse(http.StatusBadGateway, "text/plain", "Failed to read upstream response")
		errResp.Write(clientConn)
		h.logWebSocketEntry(requestID, r, originalHeaders, startTime, userID, decision, llmResponseID, 502)
		return
	}

	// If upstream didn't respond with 101, relay the error response.
	if resp.StatusCode != http.StatusSwitchingProtocols {
		slog.Warn("WebSocket upstream returned non-101 status", "request_id", requestID, "status", resp.StatusCode)
		resp.Write(clientConn)
		resp.Body.Close()
		h.logWebSocketEntry(requestID, r, originalHeaders, startTime, userID, decision, llmResponseID, resp.StatusCode)
		return
	}

	// Strip hop-by-hop headers from the upstream 101 response, preserving
	// Connection: Upgrade and Upgrade: websocket needed for the handshake.
	stripHopByHopHeaders(resp.Header, true)

	// Relay the 101 response to the client.
	if err := resp.Write(clientConn); err != nil {
		slog.Error("WebSocket failed to relay 101 to client", "request_id", requestID, "error", err)
		resp.Body.Close()
		h.logWebSocketEntry(requestID, r, originalHeaders, startTime, userID, decision, llmResponseID, 101)
		return
	}
	resp.Body.Close()

	slog.Debug("WebSocket upgrade successful, relaying", "request_id", requestID)

	// Set initial idle deadline using SetReadDeadline only. Write deadlines
	// are managed per-write by wsRelayWriter to detect slow clients quickly
	// without interfering with the idle timeout.
	conns := []net.Conn{clientConn, upstreamConn}
	deadline := time.Now().Add(wsIdleTimeout)
	clientConn.SetReadDeadline(deadline)
	upstreamConn.SetReadDeadline(deadline)

	// Bidirectional relay. Each wsRelayWriter:
	//   - Sets a per-write deadline (wsWriteTimeout) before writing so slow
	//     clients are detected quickly.
	//   - Refreshes the read deadline on BOTH connections after every
	//     successful write, keeping active sessions alive.
	// When one direction fails (slow writer timeout, read EOF, idle timeout),
	// only the affected write-side connection is closed. The other direction
	// may continue draining until it also finishes or times out.
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(&wsRelayWriter{dst: upstreamConn, readFrom: conns, idle: wsIdleTimeout, write: wsWriteTimeout}, clientBuf)
		// Client->upstream failed: close upstream's write side to signal
		// the upstream that no more data is coming. Use CloseWrite if
		// available to allow the upstream->client direction to drain.
		closeWrite(upstreamConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(&wsRelayWriter{dst: clientConn, readFrom: conns, idle: wsIdleTimeout, write: wsWriteTimeout}, upstreamBuf)
		// Upstream->client failed: close client's write side.
		closeWrite(clientConn)
		errc <- err
	}()

	// Wait for the first direction to finish, then tighten the read
	// deadline on both connections so the surviving direction drains
	// promptly instead of hanging for the full idle timeout.
	<-errc
	drainDeadline := time.Now().Add(wsDrainTimeout)
	clientConn.SetReadDeadline(drainDeadline)
	upstreamConn.SetReadDeadline(drainDeadline)
	<-errc

	slog.Debug("WebSocket connection closed", "request_id", requestID, "duration", time.Since(startTime))
	h.logWebSocketEntry(requestID, r, originalHeaders, startTime, userID, decision, llmResponseID, 101)
}

// logWebSocketEntry creates and logs an audit entry for a WebSocket connection.
// originalHeaders should be the headers captured before hop-by-hop stripping.
func (h *Handler) logWebSocketEntry(requestID string, r *http.Request, originalHeaders http.Header, startTime time.Time, userID string, decision types.ApprovalDecision, llmResponseID string, statusCode int) {
	e := newEntry(requestID, r, originalHeaders, startTime, userID)
	e.Operation = "WEBSOCKET"
	e.Decision = "approved"
	e.ResponseStatus = statusCode
	applyDecision(&e, decision, llmResponseID, decision.Reason)
	h.logEntry(e)
}

// processRequest processes a request through the approval flow.
// baseCtx carries any values set by the outer CONNECT handler (e.g. gateway auth).
func (h *Handler) processRequest(r *http.Request, requestID string, startTime time.Time, baseCtx context.Context) *http.Response {
	ctx := baseCtx

	// Read body first so we can log it.
	// Bodies larger than maxBufferedBodySize are still forwarded; only the
	// buffered prefix is logged (see requestBodyTruncated handling below).
	var requestBody []byte
	var err error
	var requestBodyTruncated bool
	if r.Body != nil {
		lr := &io.LimitedReader{R: r.Body, N: maxBufferedBodySize + 1}
		requestBody, err = io.ReadAll(lr)
		requestBodyTruncated = lr.N == 0
		if err != nil {
			slog.Error("failed to read request body", "request_id", requestID, "error", err)
		}
		if requestBodyTruncated {
			// Reconstruct full streaming body: buffered prefix + remaining tail
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(requestBody), lr.R))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(requestBody))
		}
	}

	// Resolve proxy auth: from tunnel context (HTTPS) or per-request Proxy-Authorization (HTTP).
	auth, hasContextAuth := ctx.Value(contextKeyProxyAuth).(proxyAuth)
	if !hasContextAuth {
		var authErr error
		auth, authErr = extractProxyAuth(r.Header.Get("Proxy-Authorization"))
		if authErr != nil {
			slog.Warn("unsupported auth scheme, returning 407", "request_id", requestID)
			return unsupportedAuthSchemeResponse()
		}
	}
	// Always strip Proxy-Authorization before forwarding upstream.
	r.Header.Del("Proxy-Authorization")

	// --- User identification via gateway auth token ---
	var gatewayUserID string
	if h.userResolver != nil && auth.gatewayToken != "" {
		if uid, ok := h.userResolver.GetUserByGatewayAuthToken(auth.gatewayToken); ok {
			gatewayUserID = uid
			ctx = context.WithValue(ctx, approval.ContextKeyUserID, uid)
			if policy := h.userResolver.GetLLMPolicyForUser(uid); policy != nil {
				ctx = context.WithValue(ctx, approval.ContextKeyLLMPolicy, policy)
			}
		}
	}

	// --- Gateway auth gate ---
	if h.userResolver != nil {
		if auth.gatewayToken == "" {
			slog.Warn("gateway auth missing, returning 407", "request_id", requestID)
			return proxyAuthRequiredResponse()
		}
		if gatewayUserID == "" {
			slog.Warn("gateway auth token invalid, returning 407", "request_id", requestID)
			return proxyAuthRequiredResponse()
		}
	}

	// Capture headers/body for audit logging.
	originalHeaders := r.Header.Clone()
	originalRequestBody := requestBody

	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug("request", "request_id", requestID, "method", r.Method, "url", r.URL.String())

		for key, values := range originalHeaders {
			if isSensitiveHeader(key) {
				slog.Debug("request header", "request_id", requestID, "key", key, "value", "[REDACTED]")
				continue
			}
			for _, value := range values {
				displayValue := value
				if len(value) > 80 {
					displayValue = value[:77] + "..."
				}
				slog.Debug("request header", "request_id", requestID, "key", key, "value", displayValue)
			}
		}

		if len(originalRequestBody) > 0 {
			slog.Debug("request body", "request_id", requestID, "body", h.formatBody(originalRequestBody, requestID))
		}
	}

	requestUserID := gatewayUserID

	// Check approval.
	slog.Debug("checking approval requirements", "request_id", requestID)

	var decision types.ApprovalDecision
	var body []byte
	var approvalErr error
	// Decompress request body for the LLM eval path so the judge sees
	// plaintext, not compressed binary. The raw (compressed) body is still
	// forwarded to the upstream unchanged.
	evalBody := originalRequestBody
	evalHeaders := originalHeaders
	if ce := strings.Join(originalHeaders.Values("Content-Encoding"), ", "); ce != "" && len(originalRequestBody) > 0 {
		if decoded, ok := decompressRequestBody(originalRequestBody, ce, requestID); ok {
			evalBody = decoded
			// Strip Content-Encoding and Content-Length from the eval headers
			// so the judge does not see a mismatched header alongside a
			// decompressed body (Content-Length reflects compressed size).
			evalHeaders = originalHeaders.Clone()
			evalHeaders.Del("Content-Encoding")
			evalHeaders.Del("Content-Length")
		}
		// If decompression failed (unsupported encoding, corrupt stream, etc.)
		// keep the original body AND the Content-Encoding header so the LLM
		// knows it is looking at encoded content it could not decode.
	}
	ctx = context.WithValue(ctx, approval.ContextKeyBufferedBody, originalRequestBody)
	ctx = context.WithValue(ctx, approval.ContextKeyOriginalHeaders, evalHeaders)
	ctx = context.WithValue(ctx, approval.ContextKeyOriginalBody, evalBody)
	decision, body, approvalErr = h.approvalManager.CheckApproval(ctx, r, requestID, nil)
	if approvalErr != nil {
		slog.Error("approval error", "request_id", requestID, "error", approvalErr)
		e := newEntry(requestID, r, originalHeaders, startTime, requestUserID)
		e.Decision = "ERROR"
		e.ResponseStatus = 500
		e.Error = approvalErr.Error()
		h.logEntry(e)
		return errorResponse(http.StatusInternalServerError, "text/plain", "Approval check failed")
	}

	// Log approval decision (final outcome)
	// Persist llm_responses row if the judge ran.
	llmResponseID := h.persistLLMResponse(requestID, decision.LLMResponse)

	switch decision.Decision {
	case types.DecisionAllow:
		if decision.ApprovedBy == "cache" {
			slog.Debug("request approved", "request_id", requestID, "approved_by", "cache")
		} else if decision.ApprovedBy != "" {
			slog.Debug("request approved", "request_id", requestID, "approved_by", decision.ApprovedBy)
		} else {
			slog.Debug("request approved", "request_id", requestID)
		}
	case types.DecisionDeny:
		slog.Debug("request denied", "request_id", requestID, "reason", decision.Reason)
		headers := make(http.Header)
		headers.Set("Connection", "close") // Close connection after denied request
		e := newEntry(requestID, r, originalHeaders, startTime, requestUserID)
		e.Decision = "denied"
		e.ResponseStatus = 403
		e.RequestBody = truncateBodyForAudit(originalRequestBody)
		e.ResponseHeaders = headers

		applyDecision(&e, decision, llmResponseID, decision.Reason)
		h.logEntry(e)
		resp := &http.Response{
			Status:     "403 Forbidden",
			StatusCode: http.StatusForbidden,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
			Header:     headers,
		}
		slog.Debug("returning 403 response to client", "request_id", requestID)
		return resp
	case types.DecisionTimeout:
		slog.Warn("approval request timed out", "request_id", requestID)
		headers := make(http.Header)
		headers.Set("Connection", "close") // Close connection after timeout
		e := newEntry(requestID, r, originalHeaders, startTime, requestUserID)
		e.Decision = "timeout"
		e.ResponseStatus = 408
		e.RequestBody = truncateBodyForAudit(originalRequestBody)
		e.ResponseHeaders = headers

		h.logEntry(e)
		return &http.Response{
			Status:     "408 Request Timeout",
			StatusCode: http.StatusRequestTimeout,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
			Header:     headers,
		}
	default:
		slog.Error("unknown approval decision", "request_id", requestID, "decision", decision.Decision)
		return errorResponse(http.StatusInternalServerError, "text/plain", "Unknown approval decision")
	}

	// Restore body if it was read by approval manager
	if body != nil {
		requestBody = body
	}
	if !requestBodyTruncated && len(requestBody) > 0 {
		r.Body = io.NopCloser(bytes.NewReader(requestBody))
	}

	// Create new request (to avoid modifying original).
	// For large (truncated) uploads, use the streaming MultiReader so the full body reaches upstream.
	var proxyBody io.Reader
	if requestBodyTruncated {
		proxyBody = r.Body // streaming MultiReader: buffered prefix + remaining tail
	} else {
		proxyBody = bytes.NewReader(requestBody)
	}
	proxyReq, err := http.NewRequestWithContext(ctx, r.Method, r.URL.String(), proxyBody)
	if err != nil {
		slog.Error("failed to create proxy request", "request_id", requestID, "error", err)
		e := newEntry(requestID, r, originalHeaders, startTime, requestUserID)
		e.Decision = "ERROR"
		e.ResponseStatus = 500
		e.Error = err.Error()
		e.RequestBody = truncateBodyForAudit(originalRequestBody)

		applyDecision(&e, decision, llmResponseID, decision.Reason)
		h.logEntry(e)
		return errorResponse(http.StatusInternalServerError, "text/plain", "Failed to create proxy request")
	}
	// For truncated uploads, preserve the original Content-Length so upstream gets the correct value.
	// If absent (chunked upload), log so it's visible if an upstream rejects the request.
	if requestBodyTruncated {
		if cl, parseErr := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64); parseErr == nil {
			proxyReq.ContentLength = cl
		} else {
			slog.Debug("large upload has no Content-Length, forwarding with chunked transfer encoding", "request_id", requestID)
		}
	}

	// Copy headers and strip hop-by-hop headers before forwarding upstream.
	proxyReq.Header = r.Header.Clone()
	stripHopByHopHeaders(proxyReq.Header, false)

	// Forward request
	resp, err := h.client.Do(proxyReq)
	if err != nil {
		slog.Error("failed to forward request", "request_id", requestID, "error", err)
		e := newEntry(requestID, r, originalHeaders, startTime, requestUserID)
		e.Decision = "approved"
		e.CacheHit = decision.ApprovedBy == "cache"
		e.ResponseStatus = 502
		e.Error = err.Error()
		e.RequestBody = truncateBodyForAudit(originalRequestBody)

		applyDecision(&e, decision, llmResponseID, decision.Reason)
		h.logEntry(e)
		return errorResponse(http.StatusBadGateway, "text/plain", "Failed to forward request")
	}

	// Read and log response body (capped to avoid OOM on large downloads).
	respLR := &io.LimitedReader{R: resp.Body, N: maxBufferedBodySize + 1}
	responseBody, err := io.ReadAll(respLR)
	if err != nil {
		resp.Body.Close()
		slog.Error("failed to read response body", "request_id", requestID, "error", err)
		e := newEntry(requestID, r, originalHeaders, startTime, requestUserID)
		e.Decision = "approved"
		e.CacheHit = decision.ApprovedBy == "cache"
		e.ResponseStatus = 502
		e.Error = err.Error()
		e.RequestBody = truncateBodyForAudit(originalRequestBody)
		e.ResponseHeaders = resp.Header.Clone()

		applyDecision(&e, decision, llmResponseID, decision.Reason)
		h.logEntry(e)
		return errorResponse(http.StatusBadGateway, "text/plain", "Failed to read response")
	}
	if respLR.N == 0 {
		// Body exceeds cap — reconstruct full stream for the client and log with truncation note.
		// Use multiReadCloser so Close() still reaches the original body and returns the
		// underlying TCP connection to the pool even if the caller doesn't drain fully.
		resp.Body = &multiReadCloser{
			Reader: io.MultiReader(bytes.NewReader(responseBody), respLR.R),
			closer: resp.Body,
		}
		suffix := []byte("\n[response body truncated for logging]")
		truncatedBody := make([]byte, len(responseBody), len(responseBody)+len(suffix))
		copy(truncatedBody, responseBody)
		truncatedBody = append(truncatedBody, suffix...)
		slog.Debug("response body exceeds buffer size, streaming without full buffering", "request_id", requestID, "max_bytes", maxBufferedBodySize)
		e := newEntry(requestID, r, originalHeaders, startTime, requestUserID)
		e.Decision = "approved"
		e.CacheHit = decision.ApprovedBy == "cache"
		e.ResponseStatus = resp.StatusCode
		e.RequestBody = truncateBodyForAudit(originalRequestBody)
		e.ResponseHeaders = resp.Header.Clone()
		e.ResponseBody = string(truncatedBody)

		applyDecision(&e, decision, llmResponseID, decision.Reason)
		h.logEntry(e)
		return resp
	}
	resp.Body.Close()

	// Decompress response body if needed for logging
	loggableBody := responseBody
	contentEncoding := resp.Header.Get("Content-Encoding")
	if strings.Contains(strings.ToLower(contentEncoding), "gzip") {
		gzipReader, err := gzip.NewReader(bytes.NewReader(responseBody))
		if err != nil {
			slog.Error("failed to create gzip reader", "request_id", requestID, "error", err)
		} else {
			// Read up to maxBufferedBodySize+1 to detect whether the
			// decompressed output exceeds the cap.
			decompressed, err := io.ReadAll(io.LimitReader(gzipReader, maxBufferedBodySize+1))
			gzipReader.Close()
			if err != nil {
				slog.Error("failed to decompress gzip body", "request_id", requestID, "error", err)
			} else if int64(len(decompressed)) > maxBufferedBodySize {
				loggableBody = append(decompressed[:maxBufferedBodySize], []byte("\n[decompressed response body truncated for logging]")...)
			} else {
				loggableBody = decompressed
			}
		}
	}

	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug("response", "request_id", requestID, "status", resp.StatusCode)

		importantHeaders := []string{"Content-Type", "Content-Length", "Content-Encoding", "Cache-Control"}
		for _, key := range importantHeaders {
			if value := resp.Header.Get(key); value != "" {
				slog.Debug("response header", "request_id", requestID, "key", key, "value", value)
			}
		}

		if len(loggableBody) > 0 {
			slog.Debug("response body", "request_id", requestID, "body", h.formatBody(loggableBody, requestID))
		}
	}

	// Restore response body so it can be used by caller
	resp.Body = io.NopCloser(bytes.NewReader(responseBody))

	// Log audit
	e := newEntry(requestID, r, originalHeaders, startTime, requestUserID)
	e.Decision = "approved"
	e.CacheHit = decision.ApprovedBy == "cache"
	e.ResponseStatus = resp.StatusCode
	e.RequestBody = truncateBodyForAudit(originalRequestBody)
	e.ResponseHeaders = resp.Header.Clone()
	e.ResponseBody = string(loggableBody)
	applyDecision(&e, decision, llmResponseID, decision.Reason)
	h.logEntry(e)

	return resp
}

// persistLLMResponse creates an llm_responses row if the judge ran and a writer
// is configured. Returns the row ID, or "" if nothing was persisted.
func (h *Handler) persistLLMResponse(requestID string, lr *types.LLMResponse) string {
	if lr == nil || h.llmResponseWriter == nil {
		return ""
	}
	id, err := h.llmResponseWriter.CreateLLMResponse(*lr)
	if err != nil {
		slog.Error("failed to persist llm_response", "request_id", requestID, "error", err)
		return ""
	}
	return id
}

// newEntry builds a base AuditEntry from the request context.
// Call sites set the remaining fields (Decision, ResponseStatus, etc.) directly.
func newEntry(requestID string, r *http.Request, requestHeaders http.Header, startTime time.Time, userID string) types.AuditEntry {
	operation := "READ"
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
		operation = "WRITE"
	}
	return types.AuditEntry{
		Timestamp:      time.Now(),
		UserID:         userID,
		RequestID:      requestID,
		Method:         r.Method,
		URL:            r.URL.String(),
		Operation:      operation,
		DurationMs:     time.Since(startTime).Milliseconds(),
		RequestHeaders: requestHeaders,
	}
}

// applyDecision copies the approval decision fields onto an entry.
// Used on paths where the LLM judge ran.
func applyDecision(e *types.AuditEntry, d types.ApprovalDecision, llmResponseID, llmReason string) {
	e.ApprovedBy = d.ApprovedBy
	e.Channel = d.Channel
	e.LLMPolicyID = d.LLMPolicyID
	e.LLMResponseID = llmResponseID
	e.LLMReason = llmReason // for SSE broadcast; not stored in DB column
}

// logEntry dispatches a fully-built audit entry to the DB reader, SSE, and audit file.
func (h *Handler) logEntry(entry types.AuditEntry) {
	if h.auditReader != nil {
		h.auditReader.Add(entry)
	}
	h.auditLogger.LogRequest(entry)
}

// stripHopByHopHeaders removes hop-by-hop headers from the given header map
// as required by RFC 7230 Section 6.1. Any header names listed in the
// Connection header value are also removed. Transfer-Encoding is only removed
// if explicitly listed in the Connection header (it is needed for chunked
// bodies). The Upgrade header is preserved when isWebSocket is true.
func stripHopByHopHeaders(header http.Header, isWebSocket bool) {
	// First, read the Connection header and remove any headers it designates.
	connectionValues := header.Values("Connection")
	for _, v := range connectionValues {
		for _, name := range strings.Split(v, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			// Do not strip Upgrade for WebSocket connections.
			if isWebSocket && strings.EqualFold(name, "Upgrade") {
				continue
			}
			header.Del(name)
		}
	}

	// Standard hop-by-hop headers per RFC 7230 Section 6.1.
	if !isWebSocket {
		header.Del("Connection")
	} else {
		// For WebSocket, replace any Connection value with just "Upgrade".
		header.Set("Connection", "Upgrade")
	}
	header.Del("Keep-Alive")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("TE")
	header.Del("Trailer")
	// Transfer-Encoding is NOT deleted unconditionally — only if it appeared
	// in the Connection header (handled above).
	if !isWebSocket {
		header.Del("Upgrade")
	}
	header.Del("Proxy-Connection")
}

// isWebSocketUpgrade returns true if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	connHeader := r.Header.Get("Connection")
	hasUpgrade := false
	for _, v := range strings.Split(connHeader, ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			hasUpgrade = true
			break
		}
	}
	if !hasUpgrade {
		return false
	}
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// connectionHasClose returns true if any Connection header value contains the
// "close" token. Per RFC 7230 §6.1, the header is a comma-separated list of
// tokens, and multiple Connection headers may be present.
func connectionHasClose(h http.Header) bool {
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "close") {
				return true
			}
		}
	}
	return false
}

// shouldKeepAlive checks if the connection should be kept alive
func (h *Handler) shouldKeepAlive(req *http.Request, resp *http.Response) bool {
	if connectionHasClose(req.Header) {
		return false
	}
	if connectionHasClose(resp.Header) {
		return false
	}

	// Default to keep-alive for HTTP/1.1
	return req.ProtoMajor == 1 && req.ProtoMinor >= 1
}

// decompressSingleLayer applies a single Content-Encoding layer to body.
// Returns (decompressed, true) on success, or (body, false) on failure or
// unsupported encoding. Output is capped at maxBufferedBodySize+1 via
// LimitReader; truncation is applied by the caller (decompressRequestBody)
// only on the final output so intermediate layers remain valid compressed data.
//
// When the compressed stream is truncated (e.g. body was capped at the buffer
// limit), decompression will hit an unexpected EOF. If any plaintext was
// produced before the error, that partial output is returned as success so
// the judge can still inspect early content.
func decompressSingleLayer(body []byte, encoding string, requestID string) ([]byte, bool) {
	enc := strings.TrimSpace(strings.ToLower(encoding))
	switch enc {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			slog.Error("failed to create gzip reader for request body", "request_id", requestID, "error", err)
			return body, false
		}
		decompressed, err := io.ReadAll(io.LimitReader(gr, maxBufferedBodySize+1))
		gr.Close()
		if err != nil {
			if len(decompressed) > 0 {
				return decompressed, true
			}
			slog.Error("failed to decompress gzip request body", "request_id", requestID, "error", err)
			return body, false
		}
		return decompressed, true

	case "deflate":
		// HTTP "deflate" is officially zlib (RFC 1950), but some clients
		// send raw DEFLATE (RFC 1951). Try zlib first, fall back to raw.
		if zr, zErr := zlib.NewReader(bytes.NewReader(body)); zErr == nil {
			decompressed, err := io.ReadAll(io.LimitReader(zr, maxBufferedBodySize+1))
			zr.Close()
			if err == nil {
				return decompressed, true
			}
			if len(decompressed) > 0 {
				return decompressed, true
			}
		}
		fr := flate.NewReader(bytes.NewReader(body))
		decompressed, err := io.ReadAll(io.LimitReader(fr, maxBufferedBodySize+1))
		fr.Close()
		if err != nil {
			if len(decompressed) > 0 {
				return decompressed, true
			}
			slog.Error("failed to decompress deflate request body", "request_id", requestID, "error", err)
			return body, false
		}
		return decompressed, true

	case "br":
		br := brotli.NewReader(bytes.NewReader(body))
		decompressed, err := io.ReadAll(io.LimitReader(br, maxBufferedBodySize+1))
		if err != nil {
			if len(decompressed) > 0 {
				return decompressed, true
			}
			slog.Error("failed to decompress brotli request body", "request_id", requestID, "error", err)
			return body, false
		}
		return decompressed, true

	default:
		slog.Warn("unsupported Content-Encoding, keeping original body and header", "request_id", requestID, "encoding", encoding)
		return body, false
	}
}

// decompressRequestBody decompresses a request body based on the Content-Encoding
// header. It supports gzip and deflate, including stacked encodings
// (e.g. "gzip, deflate") which are applied in reverse order per HTTP spec.
// Returns (decompressed body, true) when ALL layers were successfully decoded,
// or (original body, false) when any layer fails or uses an unsupported encoding.
// On failure the original body is returned so proxying is not broken (fail-open),
// but the caller must preserve the Content-Encoding header so the LLM sees
// that the body is still encoded.
func decompressRequestBody(body []byte, encoding string, requestID string) ([]byte, bool) {
	// Split on comma to handle stacked encodings like "gzip, deflate".
	parts := strings.Split(encoding, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	// Remove empty parts (e.g. trailing comma).
	var layers []string
	for _, p := range parts {
		if p != "" {
			layers = append(layers, p)
		}
	}
	if len(layers) == 0 {
		return body, false
	}

	// Apply in reverse order: rightmost encoding was applied last, so it
	// must be removed first.
	current := body
	for i := len(layers) - 1; i >= 0; i-- {
		decoded, ok := decompressSingleLayer(current, layers[i], requestID)
		if !ok {
			// Any layer failure → return original body, signal failure.
			return body, false
		}
		current = decoded
	}
	if int64(len(current)) > maxBufferedBodySize {
		return append(current[:maxBufferedBodySize], []byte("\n[decompressed request body truncated]")...), true
	}
	return current, true
}

// generateRequestID generates a unique request ID.
// It combines a nanosecond timestamp with 8 bytes of cryptographic randomness
// to guarantee uniqueness even when concurrent requests arrive within the
// same nanosecond.
func generateRequestID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:]) // crypto/rand.Read never returns an error on supported platforms
	return fmt.Sprintf("req_%d-%s", time.Now().UnixNano(), hex.EncodeToString(buf[:]))
}

// truncateBodyForAudit converts a request body to a string suitable for audit
// log entries. If the body exceeds maxAuditBodySize it is truncated and a
// marker is appended so reviewers know the log entry is incomplete. The
// truncation point is adjusted backwards to avoid splitting a multi-byte
// UTF-8 character.
func truncateBodyForAudit(body []byte) string {
	if len(body) <= maxAuditBodySize {
		return string(body)
	}
	// Find a clean UTF-8 boundary at or before maxAuditBodySize.
	truncLen := maxAuditBodySize
	for truncLen > 0 && !utf8.RuneStart(body[truncLen]) {
		truncLen--
	}
	return string(body[:truncLen]) + fmt.Sprintf("\n[truncated: %d bytes total, showing first %d]", len(body), truncLen)
}

// sensitiveHeaders is the set of header names whose values must be redacted
// in debug log output to avoid leaking secrets (tokens, cookies, etc.).
var sensitiveHeaders = map[string]bool{
	"Authorization":       true,
	"Cookie":              true,
	"Set-Cookie":          true,
	"Proxy-Authorization": true,
	"X-Api-Key":           true,
	"X-Auth-Token":        true,
}

// isSensitiveHeader reports whether the given header key should be redacted in logs.
func isSensitiveHeader(key string) bool {
	return sensitiveHeaders[http.CanonicalHeaderKey(key)]
}

// formatBody formats a body for logging (pretty-prints JSON if possible)
func (h *Handler) formatBody(body []byte, requestID string) string {
	// Try to parse as JSON
	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err == nil {
		// It's valid JSON, pretty print it
		prettyJSON, err := json.MarshalIndent(jsonData, "["+requestID+"] ", "  ")
		if err == nil {
			return "\n[" + requestID + "] " + string(prettyJSON)
		}
	}

	// Not JSON or failed to pretty-print, return as-is
	// Truncate if too long
	bodyStr := string(body)
	if len(bodyStr) > 1000 {
		return bodyStr[:1000] + "... (truncated)"
	}
	return bodyStr
}
