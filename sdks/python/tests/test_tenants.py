"""Tests for the tenants section of the WSLVault Python SDK."""

from __future__ import annotations

import respx

from wslvault.client import WslVaultClient
from wslvault.models import TenantCreateRequest


async def test_create_tenant(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/v1/tenants").respond(
        201,
        json={
            "id": "00000000-0000-0000-0000-000000000002",
            "slug": "acme",
            "display_name": "Acme Corp",
            "tier": "shared",
            "root_key_id": "kek-001",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        },
    )

    req = TenantCreateRequest(
        slug="acme",
        display_name="Acme Corp",
        root_key_id="kek-001",
    )
    resp = await client.tenants.create(req)
    assert resp.slug == "acme"
    assert resp.tier == "shared"


async def test_get_tenant(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    tid = "00000000-0000-0000-0000-000000000002"
    mock_api.get(f"/v1/tenants/{tid}").respond(
        200,
        json={
            "id": tid,
            "slug": "acme",
            "display_name": "Acme Corp",
            "tier": "shared",
            "root_key_id": "kek-001",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
        },
    )

    resp = await client.tenants.get(tid)
    assert resp.id == tid


async def test_list_tenants(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.get("/v1/tenants").respond(
        200,
        json=[
            {
                "id": "00000000-0000-0000-0000-000000000002",
                "slug": "acme",
                "display_name": "Acme Corp",
                "tier": "shared",
                "root_key_id": "kek-001",
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-01-01T00:00:00Z",
            },
        ],
    )

    tenants = await client.tenants.list()
    assert len(tenants) == 1
    assert tenants[0].slug == "acme"


async def test_delete_tenant(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    tid = "00000000-0000-0000-0000-000000000002"
    route = mock_api.delete(f"/v1/tenants/{tid}").respond(204)

    await client.tenants.delete(tid)
    assert route.called
