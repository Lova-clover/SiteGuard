import assert from "node:assert/strict";
import test from "node:test";

import { __metricsInternals } from "../src/metrics-store.js";

test("normalizeTopDomainsResponse handles flat zrange withscores payload", () => {
  const normalized = __metricsInternals.normalizeTopDomainsResponse([
    "siteguard-mauve.vercel.app",
    "2",
    "example.com",
    "1"
  ]);

  assert.deepEqual(normalized, [
    { hostname: "siteguard-mauve.vercel.app", count: 2 },
    { hostname: "example.com", count: 1 }
  ]);
});

test("normalizeTopDomainsResponse handles object score-member payload", () => {
  const normalized = __metricsInternals.normalizeTopDomainsResponse([
    { member: "siteguard-mauve.vercel.app", score: 2 },
    { member: "example.com", score: 1 }
  ]);

  assert.deepEqual(normalized, [
    { hostname: "siteguard-mauve.vercel.app", count: 2 },
    { hostname: "example.com", count: 1 }
  ]);
});
