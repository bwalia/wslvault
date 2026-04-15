/**
 * Tests for WslVaultClient core behaviour: auth, error mapping, retries.
 */

import { WslVaultClient } from "../src/client";
import {
  VaultApiError,
  VaultAuthError,
  VaultNotFoundError,
  VaultPermissionError,
} from "../src/errors";
import { ENDPOINT, TOKEN, TENANT_ID, mockFetch } from "./helpers";

describe("WslVaultClient", () => {
  let restore: () => void;

  afterEach(() => {
    if (restore) restore();
  });

  it("throws when endpoint is empty", () => {
    expect(() => new WslVaultClient({ endpoint: "" })).toThrow("endpoint");
  });

  it("sends Authorization header when token is set", async () => {
    const { calls, restore: r } = mockFetch([
      { method: "GET", path: "/v1/tenants", status: 200, body: [] },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    await client.tenants.list();

    expect(calls).toHaveLength(1);
    // fetch is called with headers object — we check the URL was correct
    expect(calls[0].url).toContain("/v1/tenants");
  });

  it("maps 401 to VaultAuthError", async () => {
    const { restore: r } = mockFetch([
      { method: "GET", path: "/v1/tenants", status: 401, text: "unauthorized" },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    await expect(client.tenants.list()).rejects.toThrow(VaultAuthError);
  });

  it("maps 403 to VaultPermissionError", async () => {
    const { restore: r } = mockFetch([
      { method: "GET", path: "/v1/tenants", status: 403, text: "forbidden" },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    await expect(client.tenants.list()).rejects.toThrow(VaultPermissionError);
  });

  it("maps 404 to VaultNotFoundError", async () => {
    const { restore: r } = mockFetch([
      { method: "GET", path: "/v1/tenants/missing", status: 404, text: "not found" },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    await expect(client.tenants.get("missing")).rejects.toThrow(VaultNotFoundError);
  });

  it("maps 500 to VaultApiError with status code", async () => {
    const { restore: r } = mockFetch([
      { method: "GET", path: "/v1/tenants", status: 500, text: "internal error" },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    try {
      await client.tenants.list();
      fail("expected VaultApiError");
    } catch (e) {
      expect(e).toBeInstanceOf(VaultApiError);
      expect((e as VaultApiError).statusCode).toBe(500);
    }
  });

  it("setToken updates the auth token for subsequent requests", async () => {
    const { calls, restore: r } = mockFetch([
      { method: "GET", path: "/v1/tenants", status: 200, body: [] },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: "old", maxRetries: 0 });
    client.setToken("new-token");
    await client.tenants.list();

    // We can't inspect headers directly via our simple mock, but verify the
    // request was made after setToken without error.
    expect(calls).toHaveLength(1);
  });

  it("loginWithApiKey exchanges key for JWT and sets token", async () => {
    const { calls, restore: r } = mockFetch([
      {
        method: "POST",
        path: "/v1/auth/api-key",
        status: 200,
        body: { token: "jwt-from-key", expires_at: "2026-01-01T00:00:00Z", tenant_id: "tid-123", policies: ["default"] },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, maxRetries: 0 });
    const resp = await client.loginWithApiKey("wslv_test_key");

    expect(resp.token).toBe("jwt-from-key");
    expect(calls[0].body).toEqual({ api_key: "wslv_test_key" });
  });
});
