// Package wslvault provides a Go client for the WSLVault secrets platform.
//
// All errors returned by client methods are either a [VaultError] or one of its
// concrete subtypes so callers can use errors.As / errors.Is for fine-grained
// handling:
//
//	var notFound *VaultNotFoundError
//	if errors.As(err, &notFound) {
//	    // handle missing resource
//	}
package wslvault

import "fmt"

// VaultError is the base interface implemented by every error type in this
// package. Callers that do not need to distinguish failure modes can use
// errors.As(err, new(*VaultError)) as a broad catch.
type VaultError interface {
	error
	isVaultError()
}

// ---------------------------------------------------------------------------
// VaultApiError
// ---------------------------------------------------------------------------

// VaultApiError is returned when the server responds with a non-2xx status
// that does not map to a more specific error type.
type VaultApiError struct {
	// StatusCode is the HTTP status code returned by the server.
	StatusCode int
	// Message is the response body text.
	Message string
}

func (e *VaultApiError) Error() string {
	return fmt.Sprintf("vault API error %d: %s", e.StatusCode, e.Message)
}

func (e *VaultApiError) isVaultError() {}

// ---------------------------------------------------------------------------
// VaultAuthError
// ---------------------------------------------------------------------------

// VaultAuthError is returned when the server responds with HTTP 401,
// indicating that no valid credentials were provided.
type VaultAuthError struct {
	Message string
}

func (e *VaultAuthError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("vault authentication required: %s", e.Message)
	}
	return "vault authentication required"
}

func (e *VaultAuthError) isVaultError() {}

// ---------------------------------------------------------------------------
// VaultPermissionError
// ---------------------------------------------------------------------------

// VaultPermissionError is returned when the server responds with HTTP 403,
// indicating that the authenticated principal lacks permission for the
// requested operation.
type VaultPermissionError struct {
	Message string
}

func (e *VaultPermissionError) Error() string {
	return fmt.Sprintf("vault permission denied: %s", e.Message)
}

func (e *VaultPermissionError) isVaultError() {}

// ---------------------------------------------------------------------------
// VaultNotFoundError
// ---------------------------------------------------------------------------

// VaultNotFoundError is returned when the server responds with HTTP 404,
// indicating that the requested resource does not exist.
type VaultNotFoundError struct {
	Message string
}

func (e *VaultNotFoundError) Error() string {
	return fmt.Sprintf("vault resource not found: %s", e.Message)
}

func (e *VaultNotFoundError) isVaultError() {}

// ---------------------------------------------------------------------------
// VaultConnectionError
// ---------------------------------------------------------------------------

// VaultConnectionError is returned when a network-level error occurs while
// communicating with the vault endpoint (e.g. DNS failure, connection refused,
// timeout). The underlying cause is wrapped and accessible via errors.Unwrap.
type VaultConnectionError struct {
	Message string
	// Cause holds the underlying network error, if any.
	Cause error
}

func (e *VaultConnectionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vault connection error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("vault connection error: %s", e.Message)
}

// Unwrap returns the underlying network error so that errors.Is / errors.As
// can traverse the chain.
func (e *VaultConnectionError) Unwrap() error { return e.Cause }

func (e *VaultConnectionError) isVaultError() {}

// ---------------------------------------------------------------------------
// VaultConflictError
// ---------------------------------------------------------------------------

// VaultConflictError is returned when the server responds with HTTP 409,
// indicating that the operation conflicts with existing server state (e.g.
// duplicate resource name).
type VaultConflictError struct {
	Message string
}

func (e *VaultConflictError) Error() string {
	return fmt.Sprintf("vault conflict: %s", e.Message)
}

func (e *VaultConflictError) isVaultError() {}
