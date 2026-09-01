package wslvault

import (
	"context"
	"fmt"
)

// LeasesClient provides methods for lease lifecycle management.
//
// Access via [Client.Leases].
type LeasesClient struct {
	c *Client
}

// List returns all leases for the configured tenant.
func (l *LeasesClient) List(ctx context.Context) ([]LeaseRecord, error) {
	var envelope LeaseListResponse
	if err := l.c.do(ctx, "GET", "/v1/leases", requestOptions{expectBody: true}, &envelope); err != nil {
		return nil, err
	}
	if envelope.Leases == nil {
		return []LeaseRecord{}, nil
	}
	return envelope.Leases, nil
}

// Get retrieves a single lease by its UUID.
func (l *LeasesClient) Get(ctx context.Context, leaseID string) (*LeaseRecord, error) {
	var out LeaseRecord
	if err := l.c.do(ctx, "GET", fmt.Sprintf("/v1/leases/%s", leaseID), requestOptions{expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Renew extends a lease's TTL by incrementSeconds. The lease must be
// renewable and must not have already expired.
func (l *LeasesClient) Renew(ctx context.Context, leaseID string, incrementSeconds int) (*LeaseRenewResponse, error) {
	body := map[string]int{"increment_seconds": incrementSeconds}
	var out LeaseRenewResponse
	if err := l.c.do(ctx, "POST", fmt.Sprintf("/v1/leases/%s/renew", leaseID), requestOptions{body: body, expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Revoke immediately terminates a lease. Any dynamic credentials associated
// with the lease are invalidated on the backing service.
func (l *LeasesClient) Revoke(ctx context.Context, leaseID string) error {
	return l.c.do(ctx, "POST", fmt.Sprintf("/v1/leases/%s/revoke", leaseID), requestOptions{body: map[string]interface{}{}, expectBody: false}, nil)
}
