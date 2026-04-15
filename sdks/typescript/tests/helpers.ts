/**
 * Shared test helpers for the WSLVault TypeScript SDK tests.
 *
 * Provides a `mockFetch` helper that replaces the global `fetch` with a
 * configurable mock for intercepting HTTP requests without external deps.
 */

const ENDPOINT = "https://vault.test";
const TOKEN = "s.test-jwt-token";
const TENANT_ID = "00000000-0000-0000-0000-000000000001";

export { ENDPOINT, TOKEN, TENANT_ID };

export interface MockRoute {
  method: string;
  path: string;
  status: number;
  body?: unknown;
  text?: string;
}

/**
 * Install a mock `fetch` that matches routes by method + URL path.
 *
 * Returns the list of captured `Request`-like objects for assertion.
 */
export function mockFetch(routes: MockRoute[]): {
  calls: Array<{ method: string; url: string; body: unknown }>;
  restore: () => void;
} {
  const calls: Array<{ method: string; url: string; body: unknown }> = [];
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const method = init?.method ?? "GET";
    let parsedBody: unknown = undefined;
    if (init?.body) {
      try {
        parsedBody = JSON.parse(init.body as string);
      } catch {
        parsedBody = init.body;
      }
    }
    calls.push({ method, url, body: parsedBody });

    const route = routes.find(
      (r) => r.method === method && url.includes(r.path),
    );

    if (!route) {
      return new Response(JSON.stringify({ error: "no route matched" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 204 No Content responses must have a null body per the spec.
    if (route.status === 204) {
      return new Response(null, {
        status: 204,
        headers: { "Content-Type": "application/json" },
      });
    }

    const responseBody =
      route.body !== undefined
        ? JSON.stringify(route.body)
        : route.text ?? "";

    return new Response(responseBody, {
      status: route.status,
      headers: { "Content-Type": "application/json" },
    });
  };

  return {
    calls,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}
