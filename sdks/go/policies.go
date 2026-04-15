package wslvault

import (
	"context"
	"fmt"
)

// PoliciesClient provides methods for policy management.
//
// Access via [Client.Policies].
type PoliciesClient struct {
	c *Client
}

// Create creates a new policy or replaces an existing policy with the same
// name.
func (p *PoliciesClient) Create(ctx context.Context, req PolicyCreateRequest) (*PolicyResponse, error) {
	var out PolicyResponse
	if err := p.c.do(ctx, "POST", "/v1/policies", requestOptions{body: req, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Get retrieves a policy by name.
func (p *PoliciesClient) Get(ctx context.Context, name string) (*PolicyResponse, error) {
	var out PolicyResponse
	if err := p.c.do(ctx, "GET", fmt.Sprintf("/v1/policies/%s", name), requestOptions{expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns all policies for the configured tenant.
func (p *PoliciesClient) List(ctx context.Context) (*PolicyListResponse, error) {
	var out PolicyListResponse
	if err := p.c.do(ctx, "GET", "/v1/policies", requestOptions{expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete permanently removes a policy by name. Any API keys or roles bound to
// this policy will lose the permissions it granted.
func (p *PoliciesClient) Delete(ctx context.Context, name string) error {
	return p.c.do(ctx, "DELETE", fmt.Sprintf("/v1/policies/%s", name), requestOptions{expectBody: false}, nil)
}
