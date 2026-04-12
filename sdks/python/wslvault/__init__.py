"""WSLVault Python SDK.

Provides an async HTTP client for the WSLVault secrets platform with
namespaced service sections for secrets, transit encryption, policies,
audit event queries, leases, tenant management, and API key management.

Quick start::

    import asyncio
    from wslvault import WslVaultClient
    from wslvault.models import TenantCreateRequest, ApiKeyCreateRequest

    async def main() -> None:
        async with WslVaultClient(
            endpoint="https://vault.example.com",
            token="s.my-jwt-token",
            tenant_id="my-tenant-uuid",
        ) as client:
            # Read a secret
            secret = await client.secrets.get("prod/db/password")
            print(secret.data["password"])

            # Transit encrypt
            enc = await client.transit.encrypt("my-key", "dGVzdA==")
            print(enc.ciphertext)

            # Create a tenant
            tenant = await client.tenants.create(TenantCreateRequest(
                slug="acme",
                display_name="Acme Corp",
                root_key_id="kek-001",
            ))
            print(tenant.id)

    asyncio.run(main())
"""

from .client import WslVaultClient
from .exceptions import (
    VaultApiError,
    VaultAuthError,
    VaultConnectionError,
    VaultError,
    VaultNotFoundError,
    VaultPermissionError,
)

__all__ = [
    "WslVaultClient",
    # Exceptions
    "VaultError",
    "VaultAuthError",
    "VaultPermissionError",
    "VaultNotFoundError",
    "VaultApiError",
    "VaultConnectionError",
]

__version__ = "0.1.0"
