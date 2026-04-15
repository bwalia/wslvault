/**
 * Tests for the tenants section of the WSLVault TypeScript SDK.
 */

import { WslVaultClient } from "../src/client";
import { ENDPOINT, TOKEN, mockFetch } from "./helpers";

const SAMPLE_TENANT = {
  id: "00000000-0000-0000-0000-000000000002",
  slug: "acme",
  display_name: "Acme Corp",
  tier: "shared",
  root_key_id: "kek-001",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

describe("TenantsSection", () => {
  let restore: () => void;

  afterEach(() => {
    if (restore) restore();
  });

  it("creates a tenant", async () => {
    const { calls, restore: r } = mockFetch([
      { method: "POST", path: "/v1/tenants", status: 201, body: SAMPLE_TENANT },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.tenants.create({
      slug: "acme",
      display_name: "Acme Corp",
      root_key_id: "kek-001",
    });

    expect(resp.slug).toBe("acme");
    expect(resp.tier).toBe("shared");
    expect(calls[0].body).toMatchObject({ slug: "acme" });
  });

  it("gets a tenant by UUID", async () => {
    const tid = SAMPLE_TENANT.id;
    const { restore: r } = mockFetch([
      { method: "GET", path: `/v1/tenants/${tid}`, status: 200, body: SAMPLE_TENANT },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const resp = await client.tenants.get(tid);
    expect(resp.id).toBe(tid);
  });

  it("lists tenants", async () => {
    const { restore: r } = mockFetch([
      { method: "GET", path: "/v1/tenants", status: 200, body: [SAMPLE_TENANT] },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    const tenants = await client.tenants.list();
    expect(tenants).toHaveLength(1);
    expect(tenants[0].slug).toBe("acme");
  });

  it("deletes a tenant", async () => {
    const tid = SAMPLE_TENANT.id;
    const { calls, restore: r } = mockFetch([
      { method: "DELETE", path: `/v1/tenants/${tid}`, status: 204 },
    ]);
    restore = r;

    const client = new WslVaultClient({ endpoint: ENDPOINT, token: TOKEN, maxRetries: 0 });
    await client.tenants.delete(tid);
    expect(calls).toHaveLength(1);
  });
});
