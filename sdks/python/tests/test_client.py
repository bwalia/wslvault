"""Tests for WslVaultClient core behaviour: auth, retries, error mapping."""

from __future__ import annotations

import httpx
import pytest
import respx

from wslvault.client import WslVaultClient
from wslvault.exceptions import (
    VaultApiError,
    VaultAuthError,
    VaultNotFoundError,
    VaultPermissionError,
)


async def test_constructor_requires_endpoint() -> None:
    with pytest.raises(ValueError, match="endpoint"):
        WslVaultClient(endpoint="")


async def test_auth_header_set(mock_api: respx.MockRouter) -> None:
    """Verify the Authorization header is sent when a token is configured."""
    route = mock_api.get("/v1/tenants").respond(200, json=[])

    async with WslVaultClient(
        endpoint="https://vault.test",
        token="my-token",
        max_retries=0,
    ) as client:
        await client.tenants.list()

    req = route.calls[0].request
    assert req.headers["authorization"] == "Bearer my-token"


async def test_tenant_header_set(mock_api: respx.MockRouter) -> None:
    """Verify the X-Tenant-Id header is sent."""
    route = mock_api.get("/v1/tenants").respond(200, json=[])

    async with WslVaultClient(
        endpoint="https://vault.test",
        token="tok",
        tenant_id="tid-123",
        max_retries=0,
    ) as client:
        await client.tenants.list()

    req = route.calls[0].request
    assert req.headers["x-tenant-id"] == "tid-123"


async def test_login_with_token(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    """login_with_token should update the auth header for subsequent requests."""
    route = mock_api.get("/v1/tenants").respond(200, json=[])

    await client.login_with_token("new-token")
    await client.tenants.list()

    req = route.calls[0].request
    assert req.headers["authorization"] == "Bearer new-token"


async def test_login_with_api_key(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/v1/auth/api-key").respond(
        200,
        json={
            "token": "jwt-from-api-key",
            "expires_at": "2026-01-01T00:00:00Z",
            "tenant_id": "tid-123",
            "policies": ["default"],
        },
    )

    resp = await client.login_with_api_key("wslv_test_key")
    assert resp.token == "jwt-from-api-key"


async def test_401_raises_auth_error(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.get("/v1/tenants").respond(401, text="unauthorized")

    with pytest.raises(VaultAuthError):
        await client.tenants.list()


async def test_403_raises_permission_error(
    client: WslVaultClient, mock_api: respx.MockRouter
) -> None:
    mock_api.get("/v1/tenants").respond(403, text="forbidden")

    with pytest.raises(VaultPermissionError):
        await client.tenants.list()


async def test_404_raises_not_found_error(
    client: WslVaultClient, mock_api: respx.MockRouter
) -> None:
    mock_api.get("/v1/tenants/missing").respond(404, text="not found")

    with pytest.raises(VaultNotFoundError):
        await client.tenants.get("missing")


async def test_500_raises_api_error(
    client: WslVaultClient, mock_api: respx.MockRouter
) -> None:
    mock_api.get("/v1/tenants").respond(500, text="internal error")

    with pytest.raises(VaultApiError) as exc_info:
        await client.tenants.list()
    assert exc_info.value.status_code == 500


async def test_retry_on_502(mock_api: respx.MockRouter) -> None:
    """Client should retry on 502 and succeed on the second attempt."""
    route = mock_api.get("/v1/tenants").mock(
        side_effect=[
            httpx.Response(502, text="bad gateway"),
            httpx.Response(200, json=[]),
        ]
    )

    async with WslVaultClient(
        endpoint="https://vault.test",
        token="tok",
        max_retries=1,
    ) as client:
        result = await client.tenants.list()

    assert result == []
    assert route.call_count == 2


async def test_context_manager() -> None:
    """Test that the async context manager protocol works."""
    async with WslVaultClient(endpoint="https://vault.test") as client:
        assert client is not None
