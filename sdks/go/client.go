// Package wslvault provides a Go client for the WSLVault secrets platform.
//
// # Quick start
//
//	import "github.com/bwalia/wslvault/sdks/go"
//
//	ctx := context.Background()
//
//	// Option A: start with a JWT token
//	client, err := wslvault.NewClient(wslvault.Config{
//	    Endpoint: "https://vault.example.com",
//	    Token:    "s.my-jwt-token",
//	    TenantID: "my-tenant-uuid",
//	})
//
//	// Option B: exchange a raw API key for a JWT (updates the client in-place)
//	client, err := wslvault.NewClient(wslvault.Config{Endpoint: "https://vault.example.com"})
//	if err != nil { ... }
//	if _, err := client.LoginWithAPIKey(ctx, "wslv_..."); err != nil { ... }
//
//	// Read a secret
//	secret, err := client.Secrets.Get(ctx, "prod/database/password")
//
//	// Encrypt with transit
//	enc, err := client.Transit.Encrypt(ctx, "my-key", "dGVzdA==")
//
// # Retry behaviour
//
// Every request is automatically retried up to Config.MaxRetries times on
// transient HTTP errors (408, 429, 500, 502, 503, 504) and network-level
// failures. Retries use exponential backoff starting at 100 ms, doubling each
// attempt, and capped at 10 s.
package wslvault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Retryable status codes
// ---------------------------------------------------------------------------

// retryableStatuses lists the HTTP status codes that represent transient
// server-side conditions which may resolve on retry.
var retryableStatuses = map[int]bool{
	http.StatusRequestTimeout:      true, // 408
	http.StatusTooManyRequests:      true, // 429
	http.StatusInternalServerError:  true, // 500
	http.StatusBadGateway:           true, // 502
	http.StatusServiceUnavailable:   true, // 503
	http.StatusGatewayTimeout:       true, // 504
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// Config holds the configuration options for a [Client].
type Config struct {
	// Endpoint is the base URL of the WSLVault gateway, e.g.
	// "https://vault.example.com". Required; must not be empty.
	Endpoint string

	// Token is the bearer JWT used for authentication. May be empty when the
	// client will authenticate via [Client.LoginWithAPIKey] before making other
	// requests.
	Token string

	// TenantID is the tenant UUID sent as the X-Tenant-Id header on every
	// request. Optional when operating at the platform level.
	TenantID string

	// Timeout is the per-request timeout. Defaults to 30 s when zero.
	Timeout time.Duration

	// MaxRetries is the maximum number of retry attempts for transient errors.
	// Defaults to 3 when zero.
	MaxRetries int

	// HTTPClient is the underlying [http.Client] used to execute requests.
	// When nil a default client with a 30-second timeout is used.
	HTTPClient *http.Client

	// Logger receives structured debug messages. When nil log output is
	// suppressed.
	Logger *slog.Logger
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client is the WSLVault API client.
//
// Namespaced sub-clients are exposed as fields; all methods accept a
// [context.Context] as their first argument.
//
//	client.Secrets.Get(ctx, "path/to/secret")
//	client.Transit.Encrypt(ctx, "my-key", base64Plaintext)
//	client.Tenants.Create(ctx, req)
type Client struct {
	endpoint   string
	token      string
	tenantID   string
	timeout    time.Duration
	maxRetries int
	http       *http.Client
	log        *slog.Logger

	// Secrets is the namespaced sub-client for the KV secrets engine.
	Secrets *SecretsClient
	// Transit is the namespaced sub-client for the transit encryption engine.
	Transit *TransitClient
	// Tenants is the namespaced sub-client for tenant management.
	Tenants *TenantsClient
	// APIKeys is the namespaced sub-client for API key lifecycle management.
	APIKeys *APIKeysClient
	// Policies is the namespaced sub-client for policy management.
	Policies *PoliciesClient
	// Audit is the namespaced sub-client for querying audit events.
	Audit *AuditClient
	// Leases is the namespaced sub-client for lease lifecycle management.
	Leases *LeasesClient
}

// NewClient constructs a new [Client] from the provided [Config].
//
// Returns an error when cfg.Endpoint is empty.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("wslvault: endpoint must not be empty")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}

	log := cfg.Logger
	if log == nil {
		// Discard all log output when no logger is provided.
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	c := &Client{
		endpoint:   strings.TrimRight(cfg.Endpoint, "/"),
		token:      cfg.Token,
		tenantID:   cfg.TenantID,
		timeout:    timeout,
		maxRetries: maxRetries,
		http:       httpClient,
		log:        log,
	}

	// Wire up namespaced sub-clients.
	c.Secrets = &SecretsClient{c: c}
	c.Transit = &TransitClient{c: c}
	c.Tenants = &TenantsClient{c: c}
	c.APIKeys = &APIKeysClient{c: c}
	c.Policies = &PoliciesClient{c: c}
	c.Audit = &AuditClient{c: c}
	c.Leases = &LeasesClient{c: c}

	return c, nil
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

// SetToken replaces the bearer token used for subsequent requests. This is
// useful after [LoginWithAPIKey] returns a fresh JWT.
func (c *Client) SetToken(token string) {
	c.token = token
}

// LoginWithAPIKey exchanges a raw API key (wslv_...) for a short-lived JWT
// and installs it on the client automatically so subsequent calls are
// authenticated.
func (c *Client) LoginWithAPIKey(ctx context.Context, apiKey string) (*ApiKeyAuthResponse, error) {
	resp, err := c.APIKeys.Authenticate(ctx, apiKey)
	if err != nil {
		return nil, err
	}
	c.SetToken(resp.Token)
	return resp, nil
}

// ---------------------------------------------------------------------------
// Internal HTTP transport
// ---------------------------------------------------------------------------

// requestOptions holds optional parameters for an outbound request.
type requestOptions struct {
	// params is the query-string key-value map.
	params map[string]string
	// body is the value to JSON-encode as the request body. Nil means no body.
	body interface{}
	// expectBody controls whether the response body is decoded. When false
	// the body is discarded and do returns nil.
	expectBody bool
}

// do executes an HTTP request with automatic exponential-backoff retry.
//
// On success the response body is JSON-decoded into out (when opts.expectBody
// is true and out is non-nil). On failure one of the typed errors from
// errors.go is returned.
func (c *Client) do(ctx context.Context, method, path string, opts requestOptions, out interface{}) error {
	rawURL := c.endpoint + path
	if len(opts.params) > 0 {
		q := url.Values{}
		for k, v := range opts.params {
			q.Set(k, v)
		}
		rawURL = rawURL + "?" + q.Encode()
	}

	var bodyBytes []byte
	if opts.body != nil {
		var err error
		bodyBytes, err = json.Marshal(opts.body)
		if err != nil {
			return fmt.Errorf("wslvault: failed to marshal request body: %w", err)
		}
	}

	const (
		initialBackoff = 100 * time.Millisecond
		maxBackoff     = 10 * time.Second
	)

	backoff := initialBackoff
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Respect context cancellation during the backoff sleep.
			select {
			case <-ctx.Done():
				return &VaultConnectionError{
					Message: "context cancelled during retry backoff",
					Cause:   ctx.Err(),
				}
			case <-time.After(backoff):
			}

			c.log.DebugContext(ctx, "retrying request",
				slog.String("method", method),
				slog.String("path", path),
				slog.Int("attempt", attempt+1),
				slog.Int("max_retries", c.maxRetries),
			)

			// Double the backoff, capped at maxBackoff.
			backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
		}

		// Build a fresh request each attempt so the body reader is not
		// consumed a second time.
		var bodyReader io.Reader
		if len(bodyBytes) > 0 {
			bodyReader = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
		if err != nil {
			return fmt.Errorf("wslvault: failed to build request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		if c.tenantID != "" {
			req.Header.Set("X-Tenant-Id", c.tenantID)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			// Network-level failure — always retryable.
			lastErr = &VaultConnectionError{
				Message: "HTTP request failed",
				Cause:   err,
			}
			continue
		}

		// Ensure the body is always drained and closed to allow connection
		// reuse in the underlying transport.
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = &VaultConnectionError{
				Message: "failed to read response body",
				Cause:   readErr,
			}
			continue
		}

		// --- Success path ---
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if !opts.expectBody || resp.StatusCode == http.StatusNoContent {
				return nil
			}
			if out != nil {
				if jsonErr := json.Unmarshal(respBody, out); jsonErr != nil {
					return &VaultApiError{
						StatusCode: resp.StatusCode,
						Message:    fmt.Sprintf("failed to decode JSON response: %v", jsonErr),
					}
				}
			}
			return nil
		}

		// --- Error path ---
		bodyText := strings.TrimSpace(string(respBody))
		var apiErr error
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			apiErr = &VaultAuthError{Message: bodyText}
		case http.StatusForbidden:
			apiErr = &VaultPermissionError{Message: bodyText}
		case http.StatusNotFound:
			apiErr = &VaultNotFoundError{Message: bodyText}
		case http.StatusConflict:
			apiErr = &VaultConflictError{Message: bodyText}
		default:
			apiErr = &VaultApiError{StatusCode: resp.StatusCode, Message: bodyText}
		}

		if retryableStatuses[resp.StatusCode] && attempt < c.maxRetries {
			lastErr = apiErr
			continue
		}

		return apiErr
	}

	// All retries exhausted — return the most recent error.
	if lastErr != nil {
		return lastErr
	}
	return &VaultConnectionError{Message: "request failed after all retry attempts"}
}
