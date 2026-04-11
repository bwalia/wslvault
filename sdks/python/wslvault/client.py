"""WSLVault async HTTP client.

Usage::

    import asyncio
    from wslvault import WslVaultClient
    from wslvault.models import ApiKeyCreateRequest, TenantCreateRequest

    async def main() -> None:
        async with WslVaultClient(
            endpoint="https://vault.example.com",
            token="s.my-jwt-token",
            tenant_id="my-tenant-uuid",
        ) as client:
            secret = await client.secrets.get("prod/database/password")
            print(secret.data["password"])

            enc = await client.transit.encrypt("my-key", "dGVzdA==")
            print(enc.ciphertext)

    asyncio.run(main())

The client can also be used without an async context manager by calling
:meth:`WslVaultClient.aclose` manually.

Retry behaviour
---------------
Every request is retried up to ``max_retries`` times on transient HTTP errors
(408, 429, 500, 502, 503, 504) using exponential backoff starting at 100 ms,
doubling each attempt and capped at 10 s.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional, Type, TypeVar

import httpx

from .exceptions import (
    VaultApiError,
    VaultAuthError,
    VaultConnectionError,
    VaultNotFoundError,
    VaultPermissionError,
)
from .models import (
    ApiKeyAuthResponse,
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyMetadata,
    AuditEvent,
    AuditQueryFilters,
    AuditQueryResponse,
    LeaseRecord,
    LeaseRenewResponse,
    ListResponse,
    PolicyCreateRequest,
    PolicyListResponse,
    PolicyResponse,
    SecretData,
    TenantCreateRequest,
    TenantResponse,
    TransitDecryptResponse,
    TransitEncryptResponse,
    TransitHashResponse,
    TransitHmacResponse,
    TransitKeyResponse,
    TransitKeyRotateResponse,
    TransitSignResponse,
    TransitVerifyResponse,
    WriteResponse,
)

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

# HTTP status codes that indicate a transient server-side condition that may
# resolve on retry.
_RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})


def _is_retryable(exc: Exception) -> bool:
    """Return True when *exc* represents an error worth retrying."""
    if isinstance(exc, VaultApiError):
        return exc.status_code in _RETRYABLE_STATUSES
    if isinstance(exc, (httpx.ConnectError, httpx.TimeoutException)):
        return True
    return False


class _BaseSection:
    """Shared HTTP helpers used by every service section."""

    def __init__(self, client: "WslVaultClient") -> None:
        self._client = client

    async def _get(self, path: str, params: Optional[dict[str, str]] = None) -> Any:
        return await self._client._request("GET", path, params=params)

    async def _post(self, path: str, json: Any = None) -> Any:
        return await self._client._request("POST", path, json=json)

    async def _delete(self, path: str) -> None:
        await self._client._request("DELETE", path, expect_body=False)


# ---------------------------------------------------------------------------
# Service sections
# ---------------------------------------------------------------------------

class _SecretsSection(_BaseSection):
    """Methods for the KV secrets engine."""

    async def get(self, path: str) -> SecretData:
        """Read a secret at *path*."""
        data = await self._get(f"/v1/secret/data/{path}")
        return SecretData.model_validate(data)

    async def put(self, path: str, data: dict[str, Any]) -> WriteResponse:
        """Write *data* to a secret at *path*."""
        resp = await self._post(f"/v1/secret/data/{path}", json={"data": data})
        return WriteResponse.model_validate(resp)

    async def delete(self, path: str, versions: Optional[list[int]] = None) -> None:
        """Soft-delete specific *versions* of a secret (or all if omitted)."""
        await self._client._request(
            "POST",
            f"/v1/secret/delete/{path}",
            json={"versions": versions or []},
            expect_body=False,
        )

    async def list(self, prefix: str) -> ListResponse:
        """List secret paths under *prefix*."""
        data = await self._get("/v1/secret/list", params={"prefix": prefix})
        return ListResponse.model_validate(data)


class _TransitSection(_BaseSection):
    """Methods for the transit encryption engine."""

    async def encrypt(self, key_name: str, plaintext: str) -> TransitEncryptResponse:
        """Encrypt base64-encoded *plaintext* using the named transit key."""
        data = await self._post(
            f"/v1/transit/encrypt/{key_name}", json={"plaintext": plaintext}
        )
        return TransitEncryptResponse.model_validate(data)

    async def decrypt(self, key_name: str, ciphertext: str) -> TransitDecryptResponse:
        """Decrypt a versioned ciphertext using the named transit key."""
        data = await self._post(
            f"/v1/transit/decrypt/{key_name}", json={"ciphertext": ciphertext}
        )
        return TransitDecryptResponse.model_validate(data)

    async def sign(self, key_name: str, data: str) -> TransitSignResponse:
        """Sign base64-encoded *data* with the named transit key."""
        resp = await self._post(f"/v1/transit/sign/{key_name}", json={"data": data})
        return TransitSignResponse.model_validate(resp)

    async def verify(
        self, key_name: str, data: str, signature: str
    ) -> TransitVerifyResponse:
        """Verify a signature over base64-encoded *data* using the named transit key."""
        resp = await self._post(
            f"/v1/transit/verify/{key_name}",
            json={"data": data, "signature": signature},
        )
        return TransitVerifyResponse.model_validate(resp)

    async def hash(self, key_name: str, input_data: str) -> TransitHashResponse:
        """Compute a SHA-256 hash of *input_data* using the named key context."""
        resp = await self._post(
            f"/v1/transit/hash/{key_name}", json={"input": input_data}
        )
        return TransitHashResponse.model_validate(resp)

    async def hmac(self, key_name: str, input_data: str) -> TransitHmacResponse:
        """Compute an HMAC over *input_data* using the named transit key."""
        resp = await self._post(
            f"/v1/transit/hmac/{key_name}", json={"input": input_data}
        )
        return TransitHmacResponse.model_validate(resp)

    async def create_key(self, key_name: str) -> TransitKeyResponse:
        """Create a new named transit key."""
        resp = await self._post(f"/v1/transit/keys/{key_name}", json={})
        return TransitKeyResponse.model_validate(resp)

    async def rotate_key(self, key_name: str) -> TransitKeyRotateResponse:
        """Rotate the named transit key, adding a new key version."""
        resp = await self._post(f"/v1/transit/keys/{key_name}/rotate", json={})
        return TransitKeyRotateResponse.model_validate(resp)


class _TenantsSection(_BaseSection):
    """Methods for tenant management."""

    async def create(self, req: TenantCreateRequest) -> TenantResponse:
        """Create a new tenant."""
        data = await self._post("/v1/tenants", json=req.model_dump(exclude_none=True))
        return TenantResponse.model_validate(data)

    async def get(self, tenant_id: str) -> TenantResponse:
        """Get a single tenant by its UUID."""
        data = await self._get(f"/v1/tenants/{tenant_id}")
        return TenantResponse.model_validate(data)

    async def list(self) -> list[TenantResponse]:
        """List all active tenants."""
        data = await self._get("/v1/tenants")
        return [TenantResponse.model_validate(t) for t in data]

    async def delete(self, tenant_id: str) -> None:
        """Soft-delete a tenant by its UUID."""
        await self._delete(f"/v1/tenants/{tenant_id}")


class _ApiKeysSection(_BaseSection):
    """Methods for API key lifecycle management."""

    async def create(self, req: ApiKeyCreateRequest) -> ApiKeyCreateResponse:
        """Create a new API key.

        The returned :attr:`~ApiKeyCreateResponse.key` is shown only once.
        Store it securely immediately.
        """
        data = await self._post("/v1/api-keys", json=req.model_dump(exclude_none=True))
        return ApiKeyCreateResponse.model_validate(data)

    async def list(self) -> list[ApiKeyMetadata]:
        """List active API keys for the configured tenant."""
        data = await self._get("/v1/api-keys")
        return [ApiKeyMetadata.model_validate(k) for k in data]

    async def revoke(self, key_id: str) -> None:
        """Revoke an API key by its UUID."""
        await self._delete(f"/v1/api-keys/{key_id}")

    async def rotate(self, key_id: str) -> ApiKeyCreateResponse:
        """Rotate an API key: revoke the existing key and return a replacement."""
        data = await self._post(f"/v1/api-keys/{key_id}/rotate", json={})
        return ApiKeyCreateResponse.model_validate(data)

    async def authenticate(self, api_key: str) -> ApiKeyAuthResponse:
        """Exchange a raw API key (``wslv_...``) for a short-lived JWT.

        The returned token can be passed to :class:`WslVaultClient` as the
        ``token`` parameter on subsequent calls.
        """
        data = await self._post("/v1/auth/api-key", json={"api_key": api_key})
        return ApiKeyAuthResponse.model_validate(data)


class _PoliciesSection(_BaseSection):
    """Methods for policy management."""

    async def create(self, req: PolicyCreateRequest) -> PolicyResponse:
        """Create or replace a policy."""
        data = await self._post("/v1/policies", json=req.model_dump())
        return PolicyResponse.model_validate(data)

    async def get(self, name: str) -> PolicyResponse:
        """Get a policy by name."""
        data = await self._get(f"/v1/policies/{name}")
        return PolicyResponse.model_validate(data)

    async def delete(self, name: str) -> None:
        """Delete a policy by name."""
        await self._delete(f"/v1/policies/{name}")

    async def list(self) -> PolicyListResponse:
        """List all policies for the configured tenant."""
        data = await self._get("/v1/policies")
        return PolicyListResponse.model_validate(data)


class _AuditSection(_BaseSection):
    """Methods for querying audit events."""

    async def query(self, filters: Optional[AuditQueryFilters] = None) -> AuditQueryResponse:
        """Query audit events with optional *filters*."""
        params: dict[str, str] = {}
        if filters:
            if filters.start_time:
                params["start_time"] = filters.start_time
            if filters.end_time:
                params["end_time"] = filters.end_time
            if filters.action_filter:
                params["action"] = filters.action_filter
            if filters.principal_filter:
                params["principal"] = filters.principal_filter
            if filters.limit is not None:
                params["limit"] = str(filters.limit)
            if filters.offset is not None:
                params["offset"] = str(filters.offset)

        data = await self._get("/v1/audit/events", params=params or None)
        return AuditQueryResponse.model_validate(data)


class _LeasesSection(_BaseSection):
    """Methods for lease lifecycle management."""

    async def get(self, lease_id: str) -> LeaseRecord:
        """Retrieve a lease by its UUID."""
        data = await self._get(f"/v1/leases/{lease_id}")
        return LeaseRecord.model_validate(data)

    async def revoke(self, lease_id: str) -> None:
        """Revoke a lease immediately."""
        await self._client._request(
            "POST", f"/v1/leases/{lease_id}/revoke", json={}, expect_body=False
        )

    async def renew(self, lease_id: str, increment_seconds: int) -> LeaseRenewResponse:
        """Renew a lease by extending its TTL by *increment_seconds*."""
        data = await self._post(
            f"/v1/leases/{lease_id}/renew",
            json={"increment_seconds": increment_seconds},
        )
        return LeaseRenewResponse.model_validate(data)


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------

class WslVaultClient:
    """Async HTTP client for the WSLVault secrets platform.

    Args:
        endpoint: Base URL of the WSLVault gateway, e.g. ``"https://vault.example.com"``.
        token: Bearer token (JWT or exchanged API key JWT) used for authentication.
            When using raw API keys call :meth:`api_keys.authenticate` first to
            exchange the raw key for a short-lived JWT.
        tenant_id: Tenant UUID sent as ``X-Tenant-Id`` on every request.
        timeout: Per-request timeout in seconds (default 30).
        max_retries: Maximum number of retry attempts for transient errors (default 3).
    """

    def __init__(
        self,
        endpoint: str,
        token: Optional[str] = None,
        tenant_id: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        if not endpoint:
            raise ValueError("endpoint must not be empty")

        self._endpoint = endpoint.rstrip("/")
        self._token = token
        self._tenant_id = tenant_id
        self._max_retries = max_retries

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if tenant_id:
            headers["X-Tenant-Id"] = tenant_id

        self._http = httpx.AsyncClient(
            base_url=self._endpoint,
            headers=headers,
            timeout=timeout,
        )

        # Service sections — access methods as namespaced attributes.
        self.secrets = _SecretsSection(self)
        self.transit = _TransitSection(self)
        self.tenants = _TenantsSection(self)
        self.api_keys = _ApiKeysSection(self)
        self.policies = _PoliciesSection(self)
        self.audit = _AuditSection(self)
        self.leases = _LeasesSection(self)

    # -----------------------------------------------------------------------
    # Convenience auth helpers
    # -----------------------------------------------------------------------

    async def login_with_token(self, token: str) -> None:
        """Update the client's bearer token in-place.

        Useful after an initial :meth:`login_with_api_key` call to install the
        returned JWT without recreating the client.
        """
        self._token = token
        self._http.headers["Authorization"] = f"Bearer {token}"

    async def login_with_api_key(self, api_key: str) -> ApiKeyAuthResponse:
        """Exchange a raw API key for a JWT and install it as the bearer token.

        The returned :class:`ApiKeyAuthResponse` contains the token and its
        expiry; the token is also set on the client automatically so subsequent
        calls are authenticated.
        """
        resp = await self.api_keys.authenticate(api_key)
        await self.login_with_token(resp.token)
        return resp

    # -----------------------------------------------------------------------
    # Internal HTTP helper
    # -----------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[dict[str, str]] = None,
        expect_body: bool = True,
    ) -> Any:
        """Execute an HTTP request with exponential backoff retry.

        Retries on :data:`_RETRYABLE_STATUSES` and network-level errors.
        """
        delay_ms = 0.1  # seconds; doubles each retry, capped at 10 s
        last_exc: Optional[Exception] = None

        for attempt in range(1 + self._max_retries):
            if attempt > 0:
                await asyncio.sleep(delay_ms)
                delay_ms = min(delay_ms * 2, 10.0)
                logger.warning(
                    "retrying request %s %s (attempt %d/%d)",
                    method,
                    path,
                    attempt + 1,
                    1 + self._max_retries,
                )

            try:
                response = await self._http.request(
                    method,
                    path,
                    json=json,
                    params=params,
                )
            except httpx.ConnectError as exc:
                last_exc = VaultConnectionError(str(exc))
                continue
            except httpx.TimeoutException as exc:
                last_exc = VaultApiError(408, str(exc))
                continue

            if response.is_success:
                if not expect_body:
                    return None
                try:
                    return response.json()
                except Exception as exc:  # noqa: BLE001
                    raise VaultApiError(
                        response.status_code,
                        f"failed to decode JSON response: {exc}",
                    ) from exc

            # Map HTTP error codes to typed exceptions.
            text = response.text
            status = response.status_code
            exc_obj: Exception
            if status == 401:
                exc_obj = VaultAuthError("authentication required")
            elif status == 403:
                exc_obj = VaultPermissionError(text)
            elif status == 404:
                exc_obj = VaultNotFoundError(text)
            else:
                exc_obj = VaultApiError(status, text)

            if _is_retryable(exc_obj) and attempt < self._max_retries:
                last_exc = exc_obj
                continue

            raise exc_obj

        # All retries exhausted.
        if last_exc is not None:
            raise last_exc
        raise VaultConnectionError("request failed after all retry attempts")

    # -----------------------------------------------------------------------
    # Async context manager support
    # -----------------------------------------------------------------------

    async def aclose(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._http.aclose()

    async def __aenter__(self) -> "WslVaultClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()
