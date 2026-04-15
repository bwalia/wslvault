package wslvault

// ---------------------------------------------------------------------------
// Secret types
// ---------------------------------------------------------------------------

// SecretData is the response from reading a KV secret.
type SecretData struct {
	// Data contains the key-value pairs stored in the secret.
	Data map[string]interface{} `json:"data"`
	// Version is the current version number of the secret.
	Version int `json:"version"`
	// CreatedAt is the RFC-3339 timestamp when this version was created.
	CreatedAt string `json:"created_at,omitempty"`
	// Metadata contains optional user-supplied key-value metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// WriteResponse is the response from a secret write (PUT) operation.
type WriteResponse struct {
	SecretID string `json:"secret_id"`
	Version  int    `json:"version"`
}

// ListResponse is the response from listing secret paths under a prefix.
type ListResponse struct {
	Paths []string `json:"paths"`
}

// SecretDeleteRequest is the request body for a soft-delete operation.
// When Versions is empty the server deletes the latest version.
type SecretDeleteRequest struct {
	Versions []int `json:"versions"`
}

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

// PolicyRule is a single rule within a policy document.
type PolicyRule struct {
	// Paths is a list of glob-style path patterns the rule applies to.
	Paths []string `json:"paths"`
	// Capabilities is the list of operations permitted, e.g. "read", "write".
	Capabilities []string `json:"capabilities"`
}

// PolicyCreateRequest is the request body for creating or replacing a policy.
type PolicyCreateRequest struct {
	Name  string       `json:"name"`
	Rules []PolicyRule `json:"rules"`
}

// PolicyResponse is the server response for a single policy.
type PolicyResponse struct {
	Name      string       `json:"name"`
	Rules     []PolicyRule `json:"rules"`
	CreatedAt string       `json:"created_at,omitempty"`
	UpdatedAt string       `json:"updated_at,omitempty"`
}

// PolicyListResponse is the server response when listing all policies.
type PolicyListResponse struct {
	Policies []PolicyResponse `json:"policies"`
}

// ---------------------------------------------------------------------------
// Audit types
// ---------------------------------------------------------------------------

// AuditQueryFilters contains optional query parameters for listing audit events.
// Zero-value fields are omitted from the request.
type AuditQueryFilters struct {
	// StartTime is an RFC-3339 timestamp; only events at or after this time are returned.
	StartTime string
	// EndTime is an RFC-3339 timestamp; only events before or at this time are returned.
	EndTime string
	// ActionFilter restricts results to events with this action type.
	ActionFilter string
	// PrincipalFilter restricts results to events performed by this principal.
	PrincipalFilter string
	// Limit sets the maximum number of events to return.
	Limit int
	// Offset is the number of events to skip (for pagination).
	Offset int
}

// AuditEvent is a single immutable audit log record.
type AuditEvent struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	PrincipalID   string `json:"principal_id"`
	Action        string `json:"action"`
	Resource      string `json:"resource"`
	Outcome       string `json:"outcome"`
	OutcomeDetail string `json:"outcome_detail,omitempty"`
	ClientIP      string `json:"client_ip,omitempty"`
	Timestamp     string `json:"timestamp"`
}

// AuditQueryResponse is the paginated response from an audit event query.
type AuditQueryResponse struct {
	Events []AuditEvent `json:"events"`
	Total  int          `json:"total"`
}

// ---------------------------------------------------------------------------
// Lease types
// ---------------------------------------------------------------------------

// LeaseRecord is a full lease record returned by the service.
type LeaseRecord struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	TargetType    string `json:"target_type"`
	State         string `json:"state"`
	TTLSeconds    int    `json:"ttl_seconds"`
	MaxTTLSeconds int    `json:"max_ttl_seconds"`
	Renewable     bool   `json:"renewable"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	RevokedAt     string `json:"revoked_at,omitempty"`
}

// LeaseRenewResponse is the response from a lease renewal operation.
type LeaseRenewResponse struct {
	ID         string `json:"id"`
	ExpiresAt  string `json:"expires_at"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// ---------------------------------------------------------------------------
// Transit types
// ---------------------------------------------------------------------------

// TransitEncryptResponse is the response from a transit encrypt call.
type TransitEncryptResponse struct {
	// Ciphertext is the versioned ciphertext produced by the transit engine.
	Ciphertext string `json:"ciphertext"`
}

// TransitDecryptResponse is the response from a transit decrypt call.
type TransitDecryptResponse struct {
	// Plaintext is the base64-encoded decrypted value.
	Plaintext string `json:"plaintext"`
}

// TransitSignResponse is the response from a transit sign call.
type TransitSignResponse struct {
	Signature string `json:"signature"`
}

// TransitVerifyResponse is the response from a transit verify call.
type TransitVerifyResponse struct {
	Valid bool `json:"valid"`
}

// TransitHashResponse is the response from a transit hash call.
type TransitHashResponse struct {
	Hash string `json:"hash"`
}

// TransitHmacResponse is the response from a transit HMAC call.
type TransitHmacResponse struct {
	HMAC string `json:"hmac"`
}

// TransitKeyResponse is the response from creating a new transit key.
type TransitKeyResponse struct {
	KeyName   string `json:"key_name"`
	Algorithm string `json:"algorithm"`
}

// TransitKeyRotateResponse is the response from rotating a transit key.
type TransitKeyRotateResponse struct {
	KeyName    string `json:"key_name"`
	NewVersion int    `json:"new_version"`
}

// ---------------------------------------------------------------------------
// Tenant types
// ---------------------------------------------------------------------------

// TenantCreateRequest is the request body for creating a new tenant.
type TenantCreateRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	// Tier may be "shared", "dedicated", or "sovereign". Omit to use the
	// server default.
	Tier      string `json:"tier,omitempty"`
	RootKeyID string `json:"root_key_id"`
}

// TenantResponse is the server response for a single tenant.
type TenantResponse struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Tier        string `json:"tier"`
	RootKeyID   string `json:"root_key_id"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	DeletedAt   string `json:"deleted_at,omitempty"`
}

// ---------------------------------------------------------------------------
// API key types
// ---------------------------------------------------------------------------

// ApiKeyCreateRequest is the request body for creating a new API key.
type ApiKeyCreateRequest struct {
	Name     string `json:"name"`
	TenantID string `json:"tenant_id"`
	// Policies lists the policy names attached to the key.
	Policies []string `json:"policies,omitempty"`
	// PathPrefixes restricts the key to secret paths under these prefixes.
	PathPrefixes []string `json:"path_prefixes,omitempty"`
	// ExpiresInSeconds specifies the key TTL; zero means the key never expires.
	ExpiresInSeconds int `json:"expires_in_seconds,omitempty"`
	// RateLimitPerMinute sets the maximum requests per minute. Zero means unlimited.
	RateLimitPerMinute int `json:"rate_limit_per_minute,omitempty"`
}

// ApiKeyCreateResponse is the response from creating an API key.
//
// The Key field contains the raw API key and is returned only once. Store it
// securely immediately — it cannot be retrieved later.
type ApiKeyCreateResponse struct {
	ID           string   `json:"id"`
	Key          string   `json:"key"`
	KeyPrefix    string   `json:"key_prefix"`
	Name         string   `json:"name"`
	TenantID     string   `json:"tenant_id"`
	Policies     []string `json:"policies"`
	PathPrefixes []string `json:"path_prefixes"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	CreatedAt    string   `json:"created_at"`
}

// ApiKeyMetadata is the API key summary returned by list and rotate operations.
// The raw key is never included.
type ApiKeyMetadata struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	TenantID           string   `json:"tenant_id"`
	KeyPrefix          string   `json:"key_prefix"`
	Policies           []string `json:"policies"`
	PathPrefixes       []string `json:"path_prefixes"`
	CreatedBy          string   `json:"created_by"`
	CreatedAt          string   `json:"created_at"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
	LastUsedAt         string   `json:"last_used_at,omitempty"`
	RateLimitPerMinute int      `json:"rate_limit_per_minute"`
}

// ApiKeyAuthResponse is the response from exchanging a raw API key for a
// short-lived JWT.
type ApiKeyAuthResponse struct {
	Token     string   `json:"token"`
	ExpiresAt string   `json:"expires_at"`
	TenantID  string   `json:"tenant_id"`
	Policies  []string `json:"policies"`
}
