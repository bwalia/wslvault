package wslvault

import (
	"context"
	"fmt"
)

// AuditClient provides methods for querying the immutable audit event log.
//
// Access via [Client.Audit].
type AuditClient struct {
	c *Client
}

// List queries audit events with optional filters. Pass a zero-value
// [AuditQueryFilters] (or nil) to retrieve all events for the tenant.
//
// Results are returned in reverse-chronological order and honour the Limit
// and Offset fields for pagination.
func (a *AuditClient) List(ctx context.Context, filters *AuditQueryFilters) (*AuditQueryResponse, error) {
	params := map[string]string{}
	if filters != nil {
		if filters.StartTime != "" {
			params["start_time"] = filters.StartTime
		}
		if filters.EndTime != "" {
			params["end_time"] = filters.EndTime
		}
		if filters.ActionFilter != "" {
			params["action"] = filters.ActionFilter
		}
		if filters.PrincipalFilter != "" {
			params["principal"] = filters.PrincipalFilter
		}
		if filters.Limit > 0 {
			params["limit"] = fmt.Sprintf("%d", filters.Limit)
		}
		if filters.Offset > 0 {
			params["offset"] = fmt.Sprintf("%d", filters.Offset)
		}
	}

	opts := requestOptions{expectBody: true}
	if len(params) > 0 {
		opts.params = params
	}

	var out AuditQueryResponse
	if err := a.c.do(ctx, "GET", "/v1/audit/events", opts, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Get retrieves a single audit event by its UUID.
func (a *AuditClient) Get(ctx context.Context, eventID string) (*AuditEvent, error) {
	var out AuditEvent
	if err := a.c.do(ctx, "GET", fmt.Sprintf("/v1/audit/events/%s", eventID), requestOptions{expectBody: true}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
