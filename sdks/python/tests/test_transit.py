"""Tests for the transit section of the WSLVault Python SDK."""

from __future__ import annotations

import respx

from wslvault.client import WslVaultClient


async def test_encrypt(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/v1/transit/encrypt/my-key").respond(
        200,
        json={"ciphertext": "vault:v1:base64ciphertext=="},
    )

    resp = await client.transit.encrypt("my-key", "dGVzdA==")
    assert resp.ciphertext == "vault:v1:base64ciphertext=="


async def test_decrypt(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/v1/transit/decrypt/my-key").respond(
        200,
        json={"plaintext": "dGVzdA=="},
    )

    resp = await client.transit.decrypt("my-key", "vault:v1:base64ciphertext==")
    assert resp.plaintext == "dGVzdA=="


async def test_sign(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/v1/transit/sign/my-key").respond(
        200,
        json={"signature": "vault:v1:sig-data"},
    )

    resp = await client.transit.sign("my-key", "dGVzdA==")
    assert resp.signature == "vault:v1:sig-data"


async def test_verify(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/v1/transit/verify/my-key").respond(
        200,
        json={"valid": True},
    )

    resp = await client.transit.verify("my-key", "dGVzdA==", "vault:v1:sig-data")
    assert resp.valid is True


async def test_create_key(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/v1/transit/keys/new-key").respond(
        200,
        json={"key_name": "new-key", "algorithm": "aes256-gcm96"},
    )

    resp = await client.transit.create_key("new-key")
    assert resp.key_name == "new-key"
    assert resp.algorithm == "aes256-gcm96"


async def test_rotate_key(client: WslVaultClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/v1/transit/keys/my-key/rotate").respond(
        200,
        json={"key_name": "my-key", "new_version": 2},
    )

    resp = await client.transit.rotate_key("my-key")
    assert resp.new_version == 2
