/**
 * Tests for the secrets section of the WSLVault TypeScript SDK.
 */

import { WslVaultClient } from "../src/client";
import { VaultNotFoundError } from "../src/errors";
import { ENDPOINT, TOKEN, mockFetch } from "./helpers";

describe("SecretsSection", () => {
  let restore: () => void;

  afterEach(() => {
    if (restore) restore();
  });

  it("gets a secret", async () => {
    const { restore: r } = mockFetch([
      {
        method: "GET",
        path: "/v1/secret/data/prod/db/password",
        status: 200,
        body: {
          data: { password: "s3cret" },
          version: 1,
          created_at: "2025-01-01T00:00:00Z",
        },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const secret = await client.secrets.get("prod/db/password");
    expect(secret.data.password).toBe("s3cret");
  });

  it("puts a secret", async () => {
    const { calls, restore: r } = mockFetch([
      {
        method: "POST",
        path: "/v1/secret/data/prod/db/password",
        status: 200,
        body: { version: 2, secret_id: "abc-123" },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.secrets.put("prod/db/password", { password: "new-pass" });

    expect(resp.version).toBe(2);
    expect(calls[0].body).toEqual({ data: { password: "new-pass" } });
  });

  it("deletes secret versions", async () => {
    const { calls, restore: r } = mockFetch([
      {
        method: "POST",
        path: "/v1/secret/delete/prod/db/password",
        status: 204,
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    await client.secrets.delete("prod/db/password", [1, 2]);

    expect(calls).toHaveLength(1);
    expect(calls[0].body).toEqual({ versions: [1, 2] });
  });

  it("lists secrets", async () => {
    const { restore: r } = mockFetch([
      {
        method: "GET",
        path: "/v1/secret/list",
        status: 200,
        body: { paths: ["prod/db/password", "prod/db/username"] },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.secrets.list("prod/db/");

    expect(resp.paths).toHaveLength(2);
    expect(resp.paths).toContain("prod/db/password");
  });

  it("throws VaultNotFoundError on 404", async () => {
    const { restore: r } = mockFetch([
      { method: "GET", path: "/v1/secret/data/missing", status: 404, text: "not found" },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    await expect(client.secrets.get("missing")).rejects.toThrow(VaultNotFoundError);
  });
});
