package wslvault

import (
	"context"
	"fmt"
)

// TenantsClient provides methods for tenant management.
//
// Access via [Client.Tenants].
type TenantsClient struct {
	c *Client
}

// Create creates a new tenant and returns the full tenant record.
func (t *TenantsClient) Create(ctx context.Context, req TenantCreateRequest) (*TenantResponse, error) {
	var out TenantResponse
	if err := t.c.do(ctx, "POST", "/v1/tenants", requestOptions{body: req, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Get retrieves a single tenant by its UUID.
func (t *TenantsClient) Get(ctx context.Context, tenantID string) (*TenantResponse, error) {
	var out TenantResponse
	if err := t.c.do(ctx, "GET", fmt.Sprintf("/v1/tenants/%s", tenantID), requestOptions{expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns all active (non-deleted) tenants visible to the caller.
func (t *TenantsClient) List(ctx context.Context) ([]TenantResponse, error) {
	var out []TenantResponse
	if err := t.c.do(ctx, "GET", "/v1/tenants", requestOptions{expectBody: true}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Delete soft-deletes a tenant by its UUID. The tenant's data is retained
// until a hard-purge is performed by a platform administrator.
func (t *TenantsClient) Delete(ctx context.Context, tenantID string) error {
	return t.c.do(ctx, "DELETE", fmt.Sprintf("/v1/tenants/%s", tenantID), requestOptions{expectBody: false}, nil)
}
