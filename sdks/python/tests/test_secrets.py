"""Tests for the secrets section of the WSLVault Python SDK."""

from __future__ import annotations

import httpx
import pytest
import respx

from wslvault.client import WslVaultClient
from wslvault.exceptions import VaultNotFoundError


async def test_get_secret(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.get("/v1/secret/data/prod/db/password").respond(
        200,
        json={
            "data": {"password": "s3cret"},
            "version": 1,
            "created_at": "2025-01-01T00:00:00Z",
        },
    )

    secret = await client.secrets.get("prod/db/password")
    assert secret.data["password"] == "s3cret"
    assert secret.version == 1


async def test_put_secret(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/v1/secret/data/prod/db/password").respond(
        200,
        json={"version": 2, "secret_id": "abc-123"},
    )

    resp = await client.secrets.put("prod/db/password", {"password": "new-pass"})
    assert resp.version == 2


async def test_delete_secret(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    route = mock_api.post("/v1/secret/delete/prod/db/password").respond(204)

    await client.secrets.delete("prod/db/password", versions=[1, 2])
    assert route.called


async def test_list_secrets(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.get("/v1/secret/list").respond(
        200,
        json={"paths": ["prod/db/password", "prod/db/username"]},
    )

    resp = await client.secrets.list("prod/db/")
    assert len(resp.paths) == 2
    assert "prod/db/password" in resp.paths


async def test_get_secret_not_found(
    client: WslVaultClient, mock_api: respx.MockRouter
) -> None:
    mock_api.get("/v1/secret/data/missing").respond(404, text="not found")

    with pytest.raises(VaultNotFoundError):
        await client.secrets.get("missing")
