import assert from "node:assert/strict";
import test from "node:test";

import { createPasswordHash } from "../src/admin-auth.js";
import { createMetricsStore } from "../src/metrics-store.js";
import { createAppServer } from "../server.js";

function createStubReport(url) {
  const parsed = new URL(url);

  return {
    ok: true,
    target: {
      scannedAt: "2026-03-20T00:00:00.000Z",
      input: url,
      normalized: url,
      hostname: parsed.hostname,
      primaryProtocol: parsed.protocol.replace(":", ""),
      finalUrl: url,
      publicScanMode: "passive"
    },
    summary: {
      score: 88,
      grade: "B",
      riskLevel: "Moderate",
      headline: "CSP should be tightened.",
      counts: {
        critical: 0,
        high: 1,
        medium: 0,
        total: 1,
        redirects: 1
      },
      passes: 10,
      warnings: 1,
      failures: 1
    },
    findings: [],
    checks: [],
    evidence: {
      redirectChain: [],
      finalHeaders: {},
      finalStatusCode: 200,
      finalContentType: "text/html",
      tls: null,
      cookies: [],
      probes: {
        http: { ok: true },
        https: { ok: true }
      }
    },
    limitations: [
      "Passive scan only."
    ]
  };
}

async function withServer(server) {
  await new Promise((resolve) => server.listen(0, resolve));
  const address = server.address();

  return {
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
    url: `http://127.0.0.1:${address.port}`
  };
}

async function withEnv(nextEnv, fn) {
  const previous = {};

  for (const [key, value] of Object.entries(nextEnv)) {
    previous[key] = process.env[key];

    if (value == null) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  try {
    return await fn();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value == null) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test("visit tracking stores unique visitors and page views", async (t) => {
  const metrics = createMetricsStore({ mode: "memory", timeZone: "Asia/Seoul" });
  const server = createAppServer({
    metrics,
    scan: async (url) => createStubReport(url)
  });
  const app = await withServer(server);
  t.after(async () => {
    await app.close();
  });

  const response = await fetch(`${app.url}/api/metrics/visit`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ path: "/" })
  });

  assert.equal(response.status, 200);
  assert.match(response.headers.get("set-cookie") || "", /siteguard_visitor=/);

  const snapshot = await metrics.getSnapshot();
  assert.equal(snapshot.visitors.pageViewsTotal, 1);
  assert.equal(snapshot.visitors.pageViewsToday, 1);
  assert.equal(snapshot.visitors.uniqueTotal, 1);
  assert.equal(snapshot.visitors.uniqueToday, 1);
});

test("admin login and metrics endpoint expose private usage stats", async (t) => {
  await withEnv({
    ADMIN_PASSWORD: undefined,
    ADMIN_PASSWORD_HASH: createPasswordHash("letmein"),
    ADMIN_SESSION_SECRET: "session-secret-for-tests",
    ADMIN_USERNAME: "owner"
  }, async () => {
    const metrics = createMetricsStore({ mode: "memory", timeZone: "Asia/Seoul" });
    const server = createAppServer({
      metrics,
      scan: async (url) => createStubReport(url)
    });
    const app = await withServer(server);
    t.after(async () => {
      await app.close();
    });

    const unauthenticated = await fetch(`${app.url}/api/admin/metrics`);
    assert.equal(unauthenticated.status, 401);

    const login = await fetch(`${app.url}/api/admin/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        username: "owner",
        password: "letmein"
      })
    });
    const loginPayload = await login.json();
    const adminCookie = login.headers.get("set-cookie") || "";

    assert.equal(login.status, 200);
    assert.equal(loginPayload.ok, true);
    assert.match(adminCookie, /siteguard_admin_session=/);

    const visit = await fetch(`${app.url}/api/metrics/visit`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ path: "/" })
    });
    const visitorCookie = visit.headers.get("set-cookie") || "";
    assert.match(visitorCookie, /siteguard_visitor=/);

    const scan = await fetch(`${app.url}/api/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: "https://siteguard.example" })
    });
    const scanPayload = await scan.json();

    assert.equal(scan.status, 200);
    assert.equal(scanPayload.ok, true);

    const metricsResponse = await fetch(`${app.url}/api/admin/metrics`, {
      headers: {
        Cookie: adminCookie
      }
    });
    const metricsPayload = await metricsResponse.json();

    assert.equal(metricsResponse.status, 200);
    assert.equal(metricsPayload.ok, true);
    assert.equal(metricsPayload.metrics.backend, "memory");
    assert.equal(metricsPayload.metrics.visitors.uniqueTotal, 1);
    assert.equal(metricsPayload.metrics.scans.totalRequests, 1);
    assert.equal(metricsPayload.metrics.scans.successfulTotal, 1);
    assert.equal(metricsPayload.metrics.scans.failedTotal, 0);
    assert.equal(metricsPayload.metrics.recentScans.length, 1);
    assert.equal(metricsPayload.metrics.topDomains[0].hostname, "siteguard.example");
  });
});
