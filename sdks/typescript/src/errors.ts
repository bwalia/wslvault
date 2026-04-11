/**
 * Custom error classes for the WSLVault TypeScript SDK.
 *
 * All errors thrown by the client extend {@link VaultError} so callers can
 * catch the base class when they do not need to distinguish specific failure modes.
 */

/** Base class for all WSLVault SDK errors. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    // Maintains proper stack trace in V8 (Node.js / Chrome).
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * The request was rejected because no valid credentials were provided (HTTP 401).
 */
export class VaultAuthError extends VaultError {
  constructor() {
    super("authentication required");
  }
}

/**
 * The authenticated principal lacks permission for the requested operation (HTTP 403).
 */
export class VaultPermissionError extends VaultError {
  constructor(public readonly detail: string) {
    super(`permission denied: ${detail}`);
  }
}

/**
 * The requested resource does not exist (HTTP 404).
 */
export class VaultNotFoundError extends VaultError {
  constructor(public readonly detail: string) {
    super(`not found: ${detail}`);
  }
}

/**
 * The operation conflicts with the current server state (HTTP 409),
 * e.g. a duplicate API key name.
 */
export class VaultConflictError extends VaultError {
  constructor(public readonly detail: string) {
    super(`conflict: ${detail}`);
  }
}

/**
 * A non-2xx HTTP response was received that does not map to a more specific error.
 */
export class VaultApiError extends VaultError {
  constructor(
    public readonly statusCode: number,
    public readonly body: string,
  ) {
    super(`API error ${statusCode}: ${body}`);
  }
}

/**
 * A network-level error occurred (connection refused, timeout, DNS failure, etc.).
 */
export class VaultConnectionError extends VaultError {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
  }
}
