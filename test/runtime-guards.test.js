import test from "node:test";
import assert from "node:assert/strict";

import {
  createConcurrencyGuard,
  createFixedWindowRateLimiter,
  createTtlCache,
  getClientIp,
  isSecureRequest
} from "../src/runtime-guards.js";

test("fixed window rate limiter enforces limit and resets", () => {
  const limiter = createFixedWindowRateLimiter({
    limit: 2,
    windowMs: 1000
  });

  const now = 1_000;
  assert.equal(limiter.check("ip-1", now).allowed, true);
  assert.equal(limiter.check("ip-1", now + 10).allowed, true);
  assert.equal(limiter.check("ip-1", now + 20).allowed, false);
  assert.equal(limiter.check("ip-1", now + 1_100).allowed, true);
});

test("ttl cache expires entries", () => {
  const cache = createTtlCache({
    ttlMs: 100,
    maxEntries: 2
  });

  cache.set("a", { ok: true }, 1000);
  assert.deepEqual(cache.get("a", 1050), { ok: true });
  assert.equal(cache.get("a", 1200), null);
});

test("concurrency guard tracks active scans", () => {
  const guard = createConcurrencyGuard({ limit: 1 });

  assert.equal(guard.enter(), true);
  assert.equal(guard.enter(), false);
  assert.equal(guard.size(), 1);
  guard.leave();
  assert.equal(guard.size(), 0);
});

test("client ip and secure request helpers respect forwarded headers", () => {
  const request = {
    headers: {
      "x-forwarded-for": "203.0.113.1, 10.0.0.1",
      "x-forwarded-proto": "https"
    },
    socket: {
      remoteAddress: "127.0.0.1",
      encrypted: false
    }
  };

  assert.equal(getClientIp(request), "203.0.113.1");
  assert.equal(isSecureRequest(request), true);
});
