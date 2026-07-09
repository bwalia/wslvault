/**
 * WSLVault HTTP Load Test — k6 script
 *
 * Target: secret-engine read path  GET /v1/secret/data/:path
 *
 * Usage:
 *   # Default: 20 VUs, 30 s ramp, reports p50/p95/p99
 *   k6 run scripts/load-test.js
 *
 *   # Override via environment variables:
 *   VAULT_ADDR=http://localhost:8081 \
 *   VAULT_TOKEN=root-token \
 *   VAULT_TENANT_ID=acme \
 *   VAULT_SECRET_PATH=prod/database/password \
 *   VUS=50 DURATION=60s \
 *   k6 run scripts/load-test.js
 *
 * Prerequisites:
 *   - k6 installed: brew install k6  (macOS) or https://k6.io/docs/getting-started/installation/
 *   - WSLVault secret-engine running and reachable at VAULT_ADDR
 *   - A secret pre-written at VAULT_SECRET_PATH for the given VAULT_TENANT_ID
 *
 * Output metrics of interest:
 *   http_req_duration{percentile:50}  — median latency
 *   http_req_duration{percentile:95}  — p95 latency
 *   http_req_duration{percentile:99}  — p99 latency
 *   http_req_failed                   — error rate
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Trend, Rate } from "k6/metrics";

// ── Configuration ─────────────────────────────────────────────────────────────

const BASE_URL = __ENV.VAULT_ADDR || "http://localhost:8081";
const TOKEN = __ENV.VAULT_TOKEN || "dev-root-token";
const TENANT_ID = __ENV.VAULT_TENANT_ID || "test-tenant";
const SECRET_PATH = __ENV.VAULT_SECRET_PATH || "bench/test-secret";
const VUS = parseInt(__ENV.VUS || "20", 10);
const DURATION = __ENV.DURATION || "30s";

// ── k6 options ────────────────────────────────────────────────────────────────

export const options = {
  stages: [
    // Ramp up to VUs over 10 % of DURATION, then hold, then ramp down
    { duration: "10s", target: VUS },
    { duration: DURATION, target: VUS },
    { duration: "5s", target: 0 },
  ],
  thresholds: {
    // Fail the run if p99 exceeds 500 ms or error rate exceeds 1 %
    http_req_duration: ["p(99)<500", "p(95)<200", "p(50)<50"],
    http_req_failed: ["rate<0.01"],
  },
};

// ── Custom metrics ────────────────────────────────────────────────────────────

// Tracks only the latency of successful (2xx) responses.
const successDuration = new Trend("secret_read_ok_duration", true);
const errorRate = new Rate("secret_read_errors");

// ── Default function (one VU iteration) ───────────────────────────────────────

export default function () {
  const url = `${BASE_URL}/v1/secret/data/${SECRET_PATH}`;
  const params = {
    headers: {
      "X-Vault-Token": TOKEN,
      "X-Tenant-ID": TENANT_ID,
      Accept: "application/json",
    },
    tags: { name: "secret_read" },
  };

  const res = http.get(url, params);

  const ok = check(res, {
    "status is 200": (r) => r.status === 200,
    "response has data": (r) => {
      try {
        const body = JSON.parse(r.body);
        return body && body.data !== undefined;
      } catch (_) {
        return false;
      }
    },
  });

  if (ok) {
    successDuration.add(res.timings.duration);
    errorRate.add(0);
  } else {
    errorRate.add(1);
  }

  // Minimal think-time — remove or lower to maximise throughput.
  sleep(0.05);
}
