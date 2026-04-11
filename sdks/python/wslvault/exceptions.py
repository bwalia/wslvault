"""Custom exception hierarchy for the WSLVault Python SDK.

All exceptions raised by the client are subclasses of :class:`VaultError` so
callers can catch the broad base class when they do not need to distinguish
between specific failure modes.
"""

from __future__ import annotations


class VaultError(Exception):
    """Base class for all WSLVault SDK errors."""


class VaultAuthError(VaultError):
    """The request was rejected because no valid credentials were provided (HTTP 401)."""


class VaultPermissionError(VaultError):
    """The authenticated principal lacks permission for the requested operation (HTTP 403)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class VaultNotFoundError(VaultError):
    """The requested resource does not exist (HTTP 404)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class VaultConflictError(VaultError):
    """The operation conflicts with the current server state (HTTP 409), e.g. duplicate name."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class VaultApiError(VaultError):
    """A non-2xx response was returned and does not map to a more specific exception.

    Attributes:
        status_code: The HTTP status code returned by the server.
        message: The response body text.
    """

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"API error {status_code}: {message}")
        self.status_code = status_code
        self.message = message


class VaultConnectionError(VaultError):
    """A network-level error occurred while communicating with the vault endpoint."""
