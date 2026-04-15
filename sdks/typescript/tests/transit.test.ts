/**
 * Tests for the transit section of the WSLVault TypeScript SDK.
 */

import { WslVaultClient } from "../src/client";
import { ENDPOINT, TOKEN, mockFetch } from "./helpers";

describe("TransitSection", () => {
  let restore: () => void;

  afterEach(() => {
    if (restore) restore();
  });

  it("encrypts plaintext", async () => {
    const { restore: r } = mockFetch([
      {
        method: "POST",
        path: "/v1/transit/encrypt/my-key",
        status: 200,
        body: { ciphertext: "vault:v1:base64ciphertext==" },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.transit.encrypt("my-key", "dGVzdA==");
    expect(resp.ciphertext).toBe("vault:v1:base64ciphertext==");
  });

  it("decrypts ciphertext", async () => {
    const { restore: r } = mockFetch([
      {
        method: "POST",
        path: "/v1/transit/decrypt/my-key",
        status: 200,
        body: { plaintext: "dGVzdA==" },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.transit.decrypt("my-key", "vault:v1:base64ciphertext==");
    expect(resp.plaintext).toBe("dGVzdA==");
  });

  it("signs data", async () => {
    const { restore: r } = mockFetch([
      {
        method: "POST",
        path: "/v1/transit/sign/my-key",
        status: 200,
        body: { signature: "vault:v1:sig-data" },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.transit.sign("my-key", "dGVzdA==");
    expect(resp.signature).toBe("vault:v1:sig-data");
  });

  it("verifies a signature", async () => {
    const { restore: r } = mockFetch([
      {
        method: "POST",
        path: "/v1/transit/verify/my-key",
        status: 200,
        body: { valid: true },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.transit.verify("my-key", "dGVzdA==", "vault:v1:sig-data");
    expect(resp.valid).toBe(true);
  });

  it("creates a transit key", async () => {
    const { restore: r } = mockFetch([
      {
        method: "POST",
        path: "/v1/transit/keys/new-key",
        status: 200,
        body: { key_name: "new-key", algorithm: "aes256-gcm96" },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.transit.createKey("new-key");
    expect(resp.key_name).toBe("new-key");
  });

  it("rotates a transit key", async () => {
    const { restore: r } = mockFetch([
      {
        method: "POST",
        path: "/v1/transit/keys/my-key/rotate",
        status: 200,
        body: { key_name: "my-key", new_version: 2 },
      },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.transit.rotateKey("my-key");
    expect(resp.new_version).toBe(2);
  });
});
