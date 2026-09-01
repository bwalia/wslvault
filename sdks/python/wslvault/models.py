"""Pydantic models for WSLVault API request and response types.

All models use ``model_config = ConfigDict(extra="allow")`` so that new fields
added server-side do not cause validation failures in older SDK versions.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# Shared base
# ---------------------------------------------------------------------------

class _Base(BaseModel):
    model_config = ConfigDict(extra="allow")


# ---------------------------------------------------------------------------
# Secret models
# ---------------------------------------------------------------------------

class SecretData(_Base):
    """Response from a secret read operation."""

    data: dict[str, Any]
    version: int
    created_at: Optional[str] = None
    metadata: Optional[dict[str, str]] = None


class WriteResponse(_Base):
    """Response from a secret write operation."""

    secret_id: str
    version: int


class ListResponse(_Base):
    """Response from a secret list operation."""

    paths: list[str]


# ---------------------------------------------------------------------------
# Policy models
# ---------------------------------------------------------------------------

class PolicyRule(_Base):
    """A single rule within a policy document."""

    paths: list[str]
    capabilities: list[str]


class PolicyCreateRequest(_Base):
    """Request body for creating or replacing a policy."""

    name: str
    rules: list[PolicyRule]


class PolicyResponse(_Base):
    """Response body for a single policy."""

    name: str
    rules: list[PolicyRule]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class PolicyListResponse(_Base):
    """Response body for listing all policies."""

    policies: list[PolicyResponse]


# ---------------------------------------------------------------------------
# Audit models
# ---------------------------------------------------------------------------

class AuditQueryFilters(_Base):
    """Optional filters for an audit event query."""

    start_time: Optional[str] = None
    end_time: Optional[str] = None
    action_filter: Optional[str] = None
    principal_filter: Optional[str] = None
    limit: Optional[int] = None
    offset: Optional[int] = None


class AuditEvent(_Base):
    """A single immutable audit event record."""

    id: str
    tenant_id: str
    principal_id: str
    action: str
    resource: str
    outcome: str
    outcome_detail: Optional[str] = None
    client_ip: Optional[str] = None
    timestamp: str


class AuditQueryResponse(_Base):
    """Paginated response from an audit event query."""

    events: list[AuditEvent]
    total: int


# ---------------------------------------------------------------------------
# Lease models
# ---------------------------------------------------------------------------

class LeaseRecord(_Base):
    """A full lease record returned by the service."""

    id: str
    tenant_id: str
    target_type: str
    target_label: Optional[str] = None
    state: str
    ttl_seconds: int
    max_ttl_seconds: int
    renewable: bool
    issued_at: str
    expires_at: str
    revoked_at: Optional[str] = None
    remaining_seconds: Optional[int] = None


class LeaseListResponse(_Base):
    """Envelope returned by GET /v1/leases."""

    leases: list[LeaseRecord]


class LeaseRenewResponse(_Base):
    """Response from a lease renewal operation."""

    id: str
    expires_at: str
    ttl_seconds: int


# ---------------------------------------------------------------------------
# Transit models
# ---------------------------------------------------------------------------

class TransitEncryptResponse(_Base):
    ciphertext: str


class TransitDecryptResponse(_Base):
    # Plaintext is returned as a base64-encoded string.
    plaintext: str


class TransitSignResponse(_Base):
    signature: str


class TransitVerifyResponse(_Base):
    valid: bool


class TransitHashResponse(_Base):
    hash: str


class TransitHmacResponse(_Base):
    hmac: str


class TransitKeyResponse(_Base):
    key_name: str
    algorithm: str


class TransitKeyRotateResponse(_Base):
    key_name: str
    new_version: int


# ---------------------------------------------------------------------------
# Tenant models
# ---------------------------------------------------------------------------

class TenantCreateRequest(_Base):
    """Request body for creating a new tenant."""

    slug: str
    display_name: str
    tier: Optional[str] = None
    root_key_id: str


class TenantResponse(_Base):
    """Response body for a single tenant."""

    id: str
    slug: str
    display_name: str
    tier: str
    root_key_id: str
    created_at: str
    updated_at: str
    deleted_at: Optional[str] = None


# ---------------------------------------------------------------------------
# API key models
# ---------------------------------------------------------------------------

class ApiKeyCreateRequest(_Base):
    """Request body for creating a new API key."""

    name: str
    tenant_id: str
    policies: Optional[list[str]] = None
    path_prefixes: Optional[list[str]] = None
    # Seconds until the key expires; None means the key never expires.
    expires_in_seconds: Optional[int] = None
    rate_limit_per_minute: Optional[int] = None


class ApiKeyCreateResponse(_Base):
    """Response from creating an API key.

    The ``key`` field contains the raw API key and is only returned once.
    Store it securely immediately; it cannot be retrieved later.
    """

    id: str
    # Raw API key string — shown only at creation.
    key: str
    key_prefix: str
    name: str
    tenant_id: str
    policies: list[str]
    path_prefixes: list[str]
    expires_at: Optional[str] = None
    created_at: str


class ApiKeyMetadata(_Base):
    """API key metadata returned by list and rotate operations (no raw key)."""

    id: str
    name: str
    tenant_id: str
    key_prefix: str
    policies: list[str]
    path_prefixes: list[str]
    created_by: str
    created_at: str
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    rate_limit_per_minute: int


class ApiKeyAuthResponse(_Base):
    """Response from exchanging a raw API key for a short-lived JWT."""

    token: str
    expires_at: str
    tenant_id: str
    policies: list[str]
