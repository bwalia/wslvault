package wslvault

import (
	"context"
	"fmt"
)

// APIKeysClient provides methods for API key lifecycle management.
//
// Access via [Client.APIKeys].
type APIKeysClient struct {
	c *Client
}

// Create creates a new API key. The [ApiKeyCreateResponse.Key] field contains
// the raw API key and is returned only once — store it securely immediately.
func (a *APIKeysClient) Create(ctx context.Context, req ApiKeyCreateRequest) (*ApiKeyCreateResponse, error) {
	var out ApiKeyCreateResponse
	if err := a.c.do(ctx, "POST", "/v1/api-keys", requestOptions{body: req, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns the metadata for all active API keys belonging to the
// configured tenant. The raw key value is never included in list responses.
func (a *APIKeysClient) List(ctx context.Context) ([]ApiKeyMetadata, error) {
	var out []ApiKeyMetadata
	if err := a.c.do(ctx, "GET", "/v1/api-keys", requestOptions{expectBody: true}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke immediately revokes an API key by its UUID. Revoked keys cannot be
// used for authentication.
func (a *APIKeysClient) Revoke(ctx context.Context, keyID string) error {
	return a.c.do(ctx, "DELETE", fmt.Sprintf("/v1/api-keys/%s", keyID), requestOptions{expectBody: false}, nil)
}

// Rotate revokes the existing API key identified by keyID and returns a new
// replacement key with the same configuration. Store the new key immediately.
func (a *APIKeysClient) Rotate(ctx context.Context, keyID string) (*ApiKeyCreateResponse, error) {
	var out ApiKeyCreateResponse
	if err := a.c.do(ctx, "POST", fmt.Sprintf("/v1/api-keys/%s/rotate", keyID), requestOptions{body: map[string]interface{}{}, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Authenticate exchanges a raw API key (wslv_...) for a short-lived JWT. The
// returned token can be passed to [Client.SetToken] or used with
// [Client.LoginWithAPIKey] to authenticate subsequent requests.
func (a *APIKeysClient) Authenticate(ctx context.Context, apiKey string) (*ApiKeyAuthResponse, error) {
	body := map[string]string{"api_key": apiKey}
	var out ApiKeyAuthResponse
	if err := a.c.do(ctx, "POST", "/v1/auth/api-key", requestOptions{body: body, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
