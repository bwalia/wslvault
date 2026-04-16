package wslvault_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wslvault "github.com/bwalia/wslvault/sdks/go"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestServer spins up an httptest.Server that replies with the provided
// status code and JSON body. It returns the server and a client pre-configured
// to talk to it.
func newTestServer(t *testing.T, status int, body interface{}) (*httptest.Server, *wslvault.Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			json.NewEncoder(w).Encode(body) //nolint:errcheck
		}
	}))
	t.Cleanup(srv.Close)

	client, err := wslvault.NewClient(wslvault.Config{
		Endpoint:   srv.URL,
		Token:      "test-token",
		TenantID:   "tenant-001",
		MaxRetries: 0, // disable retries for deterministic unit tests
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return srv, client
}

// newHandlerServer creates an httptest.Server driven by a custom handler,
// allowing tests to inspect the incoming request.
func newHandlerServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *wslvault.Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client, err := wslvault.NewClient(wslvault.Config{
		Endpoint:   srv.URL,
		Token:      "test-token",
		TenantID:   "tenant-abc",
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return srv, client
}

// ---------------------------------------------------------------------------
// NewClient
// ---------------------------------------------------------------------------

func TestNewClient_RequiresEndpoint(t *testing.T) {
	_, err := wslvault.NewClient(wslvault.Config{})
	if err == nil {
		t.Fatal("expected error for empty endpoint, got nil")
	}
}

func TestNewClient_Success(t *testing.T) {
	client, err := wslvault.NewClient(wslvault.Config{Endpoint: "https://vault.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewClient_SubClientsNotNil(t *testing.T) {
	client, _ := wslvault.NewClient(wslvault.Config{Endpoint: "https://vault.example.com"})
	if client.Secrets == nil {
		t.Error("Secrets sub-client is nil")
	}
	if client.Transit == nil {
		t.Error("Transit sub-client is nil")
	}
	if client.Tenants == nil {
		t.Error("Tenants sub-client is nil")
	}
	if client.APIKeys == nil {
		t.Error("APIKeys sub-client is nil")
	}
	if client.Policies == nil {
		t.Error("Policies sub-client is nil")
	}
	if client.Audit == nil {
		t.Error("Audit sub-client is nil")
	}
	if client.Leases == nil {
		t.Error("Leases sub-client is nil")
	}
}

// ---------------------------------------------------------------------------
// Request construction — headers
// ---------------------------------------------------------------------------

func TestClient_SetsAuthorizationHeader(t *testing.T) {
	var capturedAuth string
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})

	// Trigger any request; use Tenants.Delete because it expects no body.
	_ = client.Tenants.Delete(context.Background(), "some-id")

	if capturedAuth != "Bearer test-token" {
		t.Errorf("Authorization header = %q, want %q", capturedAuth, "Bearer test-token")
	}
}

func TestClient_SetsTenantIDHeader(t *testing.T) {
	var capturedTenant string
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = r.Header.Get("X-Tenant-Id")
		w.WriteHeader(http.StatusNoContent)
	})

	_ = client.Tenants.Delete(context.Background(), "some-id")

	if capturedTenant != "tenant-abc" {
		t.Errorf("X-Tenant-Id header = %q, want %q", capturedTenant, "tenant-abc")
	}
}

func TestClient_NoAuthHeaderWhenTokenEmpty(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	client, _ := wslvault.NewClient(wslvault.Config{
		Endpoint:   srv.URL,
		MaxRetries: 0,
	})

	_ = client.Tenants.Delete(context.Background(), "x")

	if capturedAuth != "" {
		t.Errorf("expected no Authorization header, got %q", capturedAuth)
	}
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

func TestClient_Maps401ToVaultAuthError(t *testing.T) {
	_, client := newTestServer(t, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	_, err := client.Secrets.Get(context.Background(), "any/path")

	var authErr *wslvault.VaultAuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *VaultAuthError, got %T: %v", err, err)
	}
}

func TestClient_Maps403ToVaultPermissionError(t *testing.T) {
	_, client := newTestServer(t, http.StatusForbidden, nil)
	_, err := client.Secrets.Get(context.Background(), "any/path")

	var permErr *wslvault.VaultPermissionError
	if !errors.As(err, &permErr) {
		t.Fatalf("expected *VaultPermissionError, got %T: %v", err, err)
	}
}

func TestClient_Maps404ToVaultNotFoundError(t *testing.T) {
	_, client := newTestServer(t, http.StatusNotFound, nil)
	_, err := client.Secrets.Get(context.Background(), "missing/path")

	var nfErr *wslvault.VaultNotFoundError
	if !errors.As(err, &nfErr) {
		t.Fatalf("expected *VaultNotFoundError, got %T: %v", err, err)
	}
}

func TestClient_Maps409ToVaultConflictError(t *testing.T) {
	_, client := newTestServer(t, http.StatusConflict, nil)
	err := client.Tenants.Delete(context.Background(), "x")

	var conflictErr *wslvault.VaultConflictError
	if !errors.As(err, &conflictErr) {
		t.Fatalf("expected *VaultConflictError, got %T: %v", err, err)
	}
}

func TestClient_Maps500ToVaultApiError(t *testing.T) {
	_, client := newTestServer(t, http.StatusInternalServerError, nil)
	_, err := client.Secrets.Get(context.Background(), "any/path")

	var apiErr *wslvault.VaultApiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *VaultApiError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", apiErr.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Retry logic
// ---------------------------------------------------------------------------

func TestClient_RetriesOn503(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// Third attempt succeeds.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":    map[string]interface{}{"key": "value"},
			"version": 1,
		}) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	client, err := wslvault.NewClient(wslvault.Config{
		Endpoint:   srv.URL,
		MaxRetries: 3,
		// Use a minimal HTTP client timeout; backoff delays are short in tests.
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	secret, err := client.Secrets.Get(context.Background(), "prod/db")
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}
	if secret == nil {
		t.Fatal("expected non-nil SecretData")
	}
	if callCount != 3 {
		t.Errorf("expected 3 HTTP calls, got %d", callCount)
	}
}

func TestClient_DoesNotRetryOn404(t *testing.T) {
	callCount := 0
	_, _ = newHandlerServer(t, func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusNotFound)
	})
	// Override with a client that would retry if not for the 404.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	clientWithRetries, _ := wslvault.NewClient(wslvault.Config{
		Endpoint:   srv.URL,
		MaxRetries: 3,
	})

	_, err := clientWithRetries.Secrets.Get(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if callCount != 1 {
		t.Errorf("expected exactly 1 HTTP call for 404, got %d", callCount)
	}
}

func TestClient_RetriesExhaustedReturnsLastError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	client, _ := wslvault.NewClient(wslvault.Config{
		Endpoint:   srv.URL,
		MaxRetries: 2,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	})

	_, err := client.Secrets.Get(context.Background(), "path")
	var apiErr *wslvault.VaultApiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *VaultApiError after exhausted retries, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

func TestClient_RespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow server to ensure the context fires.
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	client, _ := wslvault.NewClient(wslvault.Config{
		Endpoint:   srv.URL,
		MaxRetries: 0,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.Secrets.Get(ctx, "any/path")
	if err == nil {
		t.Fatal("expected error due to context cancellation, got nil")
	}
}

// ---------------------------------------------------------------------------
// Secrets sub-client
// ---------------------------------------------------------------------------

func TestSecretsGet_ParsesResponse(t *testing.T) {
	payload := map[string]interface{}{
		"data":       map[string]interface{}{"password": "s3cr3t", "user": "admin"},
		"version":    3,
		"created_at": "2024-01-01T00:00:00Z",
	}
	_, client := newTestServer(t, http.StatusOK, payload)

	secret, err := client.Secrets.Get(context.Background(), "prod/db/creds")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if secret.Version != 3 {
		t.Errorf("Version = %d, want 3", secret.Version)
	}
	if secret.Data["password"] != "s3cr3t" {
		t.Errorf("Data[password] = %v, want s3cr3t", secret.Data["password"])
	}
}

func TestSecretsGet_SendsCorrectPath(t *testing.T) {
	var capturedPath string
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}, "version": 1}) //nolint:errcheck
	})

	client.Secrets.Get(context.Background(), "prod/database/password") //nolint:errcheck

	if capturedPath != "/v1/secret/data/prod/database/password" {
		t.Errorf("path = %q, want /v1/secret/data/prod/database/password", capturedPath)
	}
}

func TestSecretsPut_SendsCorrectBodyAndPath(t *testing.T) {
	var capturedPath string
	var capturedBody map[string]interface{}

	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&capturedBody) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"secret_id": "abc-123", "version": 1}) //nolint:errcheck
	})

	data := map[string]interface{}{"api_key": "super-secret"}
	resp, err := client.Secrets.Put(context.Background(), "service/config", data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if resp.SecretID != "abc-123" {
		t.Errorf("SecretID = %q, want abc-123", resp.SecretID)
	}
	if capturedPath != "/v1/secret/data/service/config" {
		t.Errorf("path = %q, want /v1/secret/data/service/config", capturedPath)
	}
	// The body must wrap data under a "data" key.
	innerData, ok := capturedBody["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected body.data to be an object, got %T", capturedBody["data"])
	}
	if innerData["api_key"] != "super-secret" {
		t.Errorf("body.data.api_key = %v, want super-secret", innerData["api_key"])
	}
}

func TestSecretsDelete_SendsVersions(t *testing.T) {
	var capturedBody map[string]interface{}
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody) //nolint:errcheck
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.Secrets.Delete(context.Background(), "prod/db", []int{1, 2, 3})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	versions, ok := capturedBody["versions"].([]interface{})
	if !ok {
		t.Fatalf("expected body.versions to be an array")
	}
	if len(versions) != 3 {
		t.Errorf("len(versions) = %d, want 3", len(versions))
	}
}

func TestSecretsList_SendsPrefixParam(t *testing.T) {
	var capturedQuery string
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"paths": []string{"a", "b"}}) //nolint:errcheck
	})

	resp, err := client.Secrets.List(context.Background(), "prod/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Paths) != 2 {
		t.Errorf("len(Paths) = %d, want 2", len(resp.Paths))
	}
	if !strings.Contains(capturedQuery, "prefix=prod") {
		t.Errorf("query string %q does not contain prefix param", capturedQuery)
	}
}

// ---------------------------------------------------------------------------
// Transit sub-client
// ---------------------------------------------------------------------------

func TestTransitEncrypt_SendsKeyNameAndPlaintext(t *testing.T) {
	var capturedPath string
	var capturedBody map[string]string

	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&capturedBody) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"ciphertext": "vault:v1:abc123"}) //nolint:errcheck
	})

	resp, err := client.Transit.Encrypt(context.Background(), "my-key", "dGVzdA==")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if capturedPath != "/v1/transit/encrypt/my-key" {
		t.Errorf("path = %q, want /v1/transit/encrypt/my-key", capturedPath)
	}
	if capturedBody["plaintext"] != "dGVzdA==" {
		t.Errorf("body.plaintext = %q, want dGVzdA==", capturedBody["plaintext"])
	}
	if resp.Ciphertext != "vault:v1:abc123" {
		t.Errorf("Ciphertext = %q, want vault:v1:abc123", resp.Ciphertext)
	}
}

func TestTransitDecrypt_ParsesPlaintext(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, map[string]string{"plaintext": "dGVzdA=="})

	resp, err := client.Transit.Decrypt(context.Background(), "my-key", "vault:v1:abc123")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if resp.Plaintext != "dGVzdA==" {
		t.Errorf("Plaintext = %q, want dGVzdA==", resp.Plaintext)
	}
}

func TestTransitVerify_ParsesValidField(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, map[string]bool{"valid": true})

	resp, err := client.Transit.Verify(context.Background(), "my-key", "dGVzdA==", "sig")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !resp.Valid {
		t.Error("expected Valid = true")
	}
}

// ---------------------------------------------------------------------------
// Tenants sub-client
// ---------------------------------------------------------------------------

func TestTenantsCreate_SendsRequestBody(t *testing.T) {
	var capturedBody map[string]interface{}
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"id":           "tenant-uuid-1",
			"slug":         "acme",
			"display_name": "Acme Corp",
			"tier":         "shared",
			"root_key_id":  "kek-001",
			"created_at":   "2024-01-01T00:00:00Z",
			"updated_at":   "2024-01-01T00:00:00Z",
		})
	})

	resp, err := client.Tenants.Create(context.Background(), wslvault.TenantCreateRequest{
		Slug:        "acme",
		DisplayName: "Acme Corp",
		RootKeyID:   "kek-001",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if resp.ID != "tenant-uuid-1" {
		t.Errorf("ID = %q, want tenant-uuid-1", resp.ID)
	}
	if capturedBody["slug"] != "acme" {
		t.Errorf("body.slug = %v, want acme", capturedBody["slug"])
	}
}

func TestTenantsGet_ParsesResponse(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, map[string]interface{}{
		"id":           "tid-1",
		"slug":         "beta",
		"display_name": "Beta Corp",
		"tier":         "dedicated",
		"root_key_id":  "kek-002",
		"created_at":   "2024-01-02T00:00:00Z",
		"updated_at":   "2024-01-02T00:00:00Z",
	})

	resp, err := client.Tenants.Get(context.Background(), "tid-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.Tier != "dedicated" {
		t.Errorf("Tier = %q, want dedicated", resp.Tier)
	}
}

func TestTenantsList_ReturnsSlice(t *testing.T) {
	payload := []map[string]interface{}{
		{"id": "t1", "slug": "a", "display_name": "A", "tier": "shared", "root_key_id": "k1", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
		{"id": "t2", "slug": "b", "display_name": "B", "tier": "shared", "root_key_id": "k2", "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
	}
	_, client := newTestServer(t, http.StatusOK, payload)

	tenants, err := client.Tenants.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(tenants) != 2 {
		t.Errorf("len(tenants) = %d, want 2", len(tenants))
	}
}

func TestTenantsDelete_SendsDeleteMethod(t *testing.T) {
	var capturedMethod string
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.Tenants.Delete(context.Background(), "tid-1")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if capturedMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", capturedMethod)
	}
}

// ---------------------------------------------------------------------------
// APIKeys sub-client
// ---------------------------------------------------------------------------

func TestAPIKeysCreate_ReturnsRawKey(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, map[string]interface{}{
		"id":            "key-uuid-1",
		"key":           "wslv_abc123secret",
		"key_prefix":    "wslv_abc",
		"name":          "ci-pipeline",
		"tenant_id":     "tenant-001",
		"policies":      []string{"read-only"},
		"path_prefixes": []string{"prod/"},
		"created_at":    "2024-01-01T00:00:00Z",
	})

	resp, err := client.APIKeys.Create(context.Background(), wslvault.ApiKeyCreateRequest{
		Name:     "ci-pipeline",
		TenantID: "tenant-001",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if resp.Key != "wslv_abc123secret" {
		t.Errorf("Key = %q, want wslv_abc123secret", resp.Key)
	}
}

func TestAPIKeysAuthenticate_SendsAPIKey(t *testing.T) {
	var capturedBody map[string]string
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"token":     "jwt.signed.token",
			"expires_at": "2024-12-31T23:59:59Z",
			"tenant_id": "tenant-001",
			"policies":  []string{"admin"},
		})
	})

	resp, err := client.APIKeys.Authenticate(context.Background(), "wslv_rawkey123")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if capturedBody["api_key"] != "wslv_rawkey123" {
		t.Errorf("body.api_key = %q, want wslv_rawkey123", capturedBody["api_key"])
	}
	if resp.Token != "jwt.signed.token" {
		t.Errorf("Token = %q, want jwt.signed.token", resp.Token)
	}
}

func TestLoginWithAPIKey_UpdatesClientToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/api-key" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"token":     "new-jwt-token",
				"expires_at": "2024-12-31T23:59:59Z",
				"tenant_id": "t1",
				"policies":  []string{},
			})
			return
		}
		// Capture the auth header from a subsequent request.
		w.Header().Set("X-Captured-Auth", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}, "version": 1}) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	client, _ := wslvault.NewClient(wslvault.Config{
		Endpoint:   srv.URL,
		MaxRetries: 0,
	})

	if _, err := client.LoginWithAPIKey(context.Background(), "wslv_raw"); err != nil {
		t.Fatalf("LoginWithAPIKey: %v", err)
	}

	// A subsequent Secrets.Get should succeed with the updated token installed
	// by LoginWithAPIKey; the test server returns a valid SecretData for any path.
	_, err := client.Secrets.Get(context.Background(), "test")
	if err != nil {
		t.Fatalf("post-login Secrets.Get: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Policies sub-client
// ---------------------------------------------------------------------------

func TestPoliciesCreate_SendsRulesBody(t *testing.T) {
	var capturedBody map[string]interface{}
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"name":  "read-only",
			"rules": []interface{}{},
		})
	})

	_, err := client.Policies.Create(context.Background(), wslvault.PolicyCreateRequest{
		Name: "read-only",
		Rules: []wslvault.PolicyRule{
			{Paths: []string{"secret/*"}, Capabilities: []string{"read", "list"}},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if capturedBody["name"] != "read-only" {
		t.Errorf("body.name = %v, want read-only", capturedBody["name"])
	}
}

func TestPoliciesList_ReturnsAllPolicies(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, map[string]interface{}{
		"policies": []map[string]interface{}{
			{"name": "admin", "rules": []interface{}{}},
			{"name": "read-only", "rules": []interface{}{}},
		},
	})

	resp, err := client.Policies.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Policies) != 2 {
		t.Errorf("len(Policies) = %d, want 2", len(resp.Policies))
	}
}

// ---------------------------------------------------------------------------
// Audit sub-client
// ---------------------------------------------------------------------------

func TestAuditList_SendsFilterParams(t *testing.T) {
	var capturedQuery string
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"events": []interface{}{}, "total": 0}) //nolint:errcheck
	})

	_, err := client.Audit.List(context.Background(), &wslvault.AuditQueryFilters{
		ActionFilter: "secret.read",
		Limit:        50,
		Offset:       10,
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !strings.Contains(capturedQuery, "action=secret.read") {
		t.Errorf("query %q missing action param", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "limit=50") {
		t.Errorf("query %q missing limit param", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "offset=10") {
		t.Errorf("query %q missing offset param", capturedQuery)
	}
}

func TestAuditList_NilFiltersOmitsParams(t *testing.T) {
	var capturedQuery string
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"events": []interface{}{}, "total": 0}) //nolint:errcheck
	})

	client.Audit.List(context.Background(), nil) //nolint:errcheck

	if capturedQuery != "" {
		t.Errorf("expected empty query string for nil filters, got %q", capturedQuery)
	}
}

func TestAuditGet_ParsesEvent(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, map[string]interface{}{
		"id":           "evt-001",
		"tenant_id":    "t1",
		"principal_id": "user-1",
		"action":       "secret.read",
		"resource":     "prod/db",
		"outcome":      "success",
		"timestamp":    "2024-06-01T12:00:00Z",
	})

	evt, err := client.Audit.Get(context.Background(), "evt-001")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if evt.Action != "secret.read" {
		t.Errorf("Action = %q, want secret.read", evt.Action)
	}
}

// ---------------------------------------------------------------------------
// Leases sub-client
// ---------------------------------------------------------------------------

func TestLeasesGet_ParsesRecord(t *testing.T) {
	_, client := newTestServer(t, http.StatusOK, map[string]interface{}{
		"id":              "lease-001",
		"tenant_id":       "t1",
		"target_type":     "secret",
		"state":           "active",
		"ttl_seconds":     3600,
		"max_ttl_seconds": 86400,
		"renewable":       true,
		"issued_at":       "2024-01-01T00:00:00Z",
		"expires_at":      "2024-01-01T01:00:00Z",
	})

	lease, err := client.Leases.Get(context.Background(), "lease-001")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if lease.State != "active" {
		t.Errorf("State = %q, want active", lease.State)
	}
	if !lease.Renewable {
		t.Error("expected Renewable = true")
	}
}

func TestLeasesRenew_SendsIncrementSeconds(t *testing.T) {
	var capturedBody map[string]interface{}
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"id":          "lease-001",
			"expires_at":  "2024-01-01T02:00:00Z",
			"ttl_seconds": 3600,
		})
	})

	resp, err := client.Leases.Renew(context.Background(), "lease-001", 3600)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if resp.TTLSeconds != 3600 {
		t.Errorf("TTLSeconds = %d, want 3600", resp.TTLSeconds)
	}
	// increment_seconds is stored as float64 when decoded into map[string]interface{}.
	if capturedBody["increment_seconds"].(float64) != 3600 {
		t.Errorf("body.increment_seconds = %v, want 3600", capturedBody["increment_seconds"])
	}
}

func TestLeasesRevoke_SendsPostRequest(t *testing.T) {
	var capturedMethod string
	var capturedPath string
	_, client := newHandlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.Leases.Revoke(context.Background(), "lease-abc")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if capturedMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", capturedMethod)
	}
	if capturedPath != "/v1/leases/lease-abc/revoke" {
		t.Errorf("path = %q, want /v1/leases/lease-abc/revoke", capturedPath)
	}
}

// ---------------------------------------------------------------------------
// VaultConnectionError — unreachable server
// ---------------------------------------------------------------------------

func TestClient_ConnectionError_ReturnsVaultConnectionError(t *testing.T) {
	// Point client at a port that is not listening.
	client, _ := wslvault.NewClient(wslvault.Config{
		Endpoint:   "http://127.0.0.1:19999",
		MaxRetries: 0,
		HTTPClient: &http.Client{Timeout: 500 * time.Millisecond},
	})

	_, err := client.Secrets.Get(context.Background(), "any")
	var connErr *wslvault.VaultConnectionError
	if !errors.As(err, &connErr) {
		t.Fatalf("expected *VaultConnectionError, got %T: %v", err, err)
	}
}
