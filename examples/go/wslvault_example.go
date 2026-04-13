// WSLVault Secret Lifecycle Example — Go
//
// Shows the full flow:
//   1. Write a secret (base64-encoded payload)
//   2. Read the secret back and decode it
//   3. List secrets
//   4. Read a specific version
//   5. Soft-delete a version
//   6. (Optional) Exchange an API key for a JWT via /v1/auth/api-key
//
// Usage:
//   VAULT_ADDR=http://localhost:8081 \
//   VAULT_TENANT_ID=019d813d-74bc-7660-89a7-f02fd9f2736d \
//   go run wslvault_example.go
//
// No external dependencies — uses only the standard library.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const secretPath = "demo/go/service-token"

type writeRequest struct {
	Data string `json:"data"`
}

type writeResponse struct {
	SecretID string `json:"secret_id"`
	Version  int    `json:"version"`
}

type readResponse struct {
	Data      string `json:"data"`
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
}

type deleteRequest struct {
	Versions []int `json:"versions"`
}

// vaultClient holds the configuration for making requests to WSLVault.
type vaultClient struct {
	vaultAddr   string
	tenantID    string
	principalID string
	policies    string
	http        *http.Client
}

func newVaultClient(vaultAddr, tenantID, principalID, policies string) *vaultClient {
	return &vaultClient{
		vaultAddr:   vaultAddr,
		tenantID:    tenantID,
		principalID: principalID,
		policies:    policies,
		http:        &http.Client{},
	}
}

// do sends an authenticated HTTP request and decodes the JSON response into dest.
// Pass dest=nil when you don't need the response body (e.g. delete operations).
func (c *vaultClient) do(method, url string, body any, dest any) error {
	var reqBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	// In production the gateway injects X-Principal-Id / X-Policies from the JWT.
	// When calling the secret-engine directly (dev / service mesh), pass them manually.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-Id", c.tenantID)
	req.Header.Set("X-Principal-Id", c.principalID)
	req.Header.Set("X-Policies", c.policies)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("http %s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %s %s: status %d — %s", method, url, resp.StatusCode, respBytes)
	}

	if dest != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, dest); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Optional: exchange an API key for a JWT.
//
//	func exchangeAPIKey(identityAddr, apiKey, tenantID string) (string, error) {
//	    body := fmt.Sprintf(`{"api_key":"%s","tenant_id":"%s"}`, apiKey, tenantID)
//	    req, _ := http.NewRequest("POST", identityAddr+"/v1/auth/api-key",
//	        strings.NewReader(body))
//	    req.Header.Set("Content-Type", "application/json")
//	    resp, err := http.DefaultClient.Do(req)
//	    // ... parse resp.body["token"]
//	}

func main() {
	vaultAddr := envOrDefault("VAULT_ADDR", "http://localhost:8081")
	tenantID := envOrDefault("VAULT_TENANT_ID", "019d813d-74bc-7660-89a7-f02fd9f2736d")
	principalID := envOrDefault("VAULT_PRINCIPAL_ID", "go-example")
	policies := envOrDefault("VAULT_POLICIES", "admin")

	client := newVaultClient(vaultAddr, tenantID, principalID, policies)

	// ── 1. Write a secret ──────────────────────────────────────────────────────
	fmt.Printf("==> 1. Writing secret to '%s'...\n", secretPath)
	payload := map[string]string{
		"service_token": "svc-token-abc123",
		"environment":   "production",
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		fatalf("marshal payload: %v", err)
	}
	data := base64.StdEncoding.EncodeToString(payloadJSON)

	var writeResp writeResponse
	if err := client.do("POST", vaultAddr+"/v1/secret/data/"+secretPath,
		writeRequest{Data: data}, &writeResp); err != nil {
		fatalf("write secret: %v", err)
	}
	fmt.Printf("    secret_id=%s  version=%d\n", writeResp.SecretID, writeResp.Version)

	// ── 2. Read the secret back ────────────────────────────────────────────────
	fmt.Printf("\n==> 2. Reading secret from '%s'...\n", secretPath)
	var readResp readResponse
	if err := client.do("GET", vaultAddr+"/v1/secret/data/"+secretPath, nil, &readResp); err != nil {
		fatalf("read secret: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(readResp.Data)
	if err != nil {
		fatalf("decode data: %v", err)
	}
	fmt.Printf("    Decoded: %s\n", decoded)

	// ── 3. List secrets ────────────────────────────────────────────────────────
	fmt.Println("\n==> 3. Listing secrets...")
	var listResp any
	if err := client.do("GET", vaultAddr+"/v1/secret/list", nil, &listResp); err != nil {
		fatalf("list secrets: %v", err)
	}
	listJSON, _ := json.MarshalIndent(listResp, "    ", "  ")
	fmt.Printf("    %s\n", listJSON)

	// ── 4. Read a specific version ─────────────────────────────────────────────
	fmt.Printf("\n==> 4. Reading version %d explicitly...\n", writeResp.Version)
	var verResp readResponse
	url := fmt.Sprintf("%s/v1/secret/data/%s?version=%d", vaultAddr, secretPath, writeResp.Version)
	if err := client.do("GET", url, nil, &verResp); err != nil {
		fatalf("read version: %v", err)
	}
	fmt.Printf("    version=%d  created_at=%s\n", verResp.Version, verResp.CreatedAt)

	// ── 5. Soft-delete the version ─────────────────────────────────────────────
	fmt.Printf("\n==> 5. Soft-deleting version %d...\n", writeResp.Version)
	if err := client.do("POST", vaultAddr+"/v1/secret/delete/"+secretPath,
		deleteRequest{Versions: []int{writeResp.Version}}, nil); err != nil {
		fatalf("delete secret: %v", err)
	}
	fmt.Println("    Deleted (soft — data retained for undelete).")

	fmt.Println("\nDone! All WSLVault operations completed successfully.")
}

func envOrDefault(key, defaultVal string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return defaultVal
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
