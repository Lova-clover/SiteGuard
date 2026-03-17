import test from "node:test";
import assert from "node:assert/strict";

import { createAppServer } from "../server.js";

function createStubReport(url) {
  return {
    ok: true,
    target: {
      scannedAt: "2026-03-17T00:00:00.000Z",
      input: url,
      normalized: url,
      hostname: "example.com",
      primaryProtocol: "https",
      finalUrl: url,
      publicScanMode: "passive"
    },
    summary: {
      score: 90,
      grade: "A",
      riskLevel: "Low",
      headline: "공개 구성은 안정적으로 보입니다.",
      counts: {
        critical: 0,
        high: 0,
        medium: 0,
        total: 0,
        redirects: 1
      },
      passes: 5,
      warnings: 0,
      failures: 0
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

test("health endpoint returns operational metadata", async (t) => {
  const server = createAppServer({
    scan: async (url) => createStubReport(url)
  });

  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());

  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/health`);
  const payload = await response.json();

  assert.equal(response.status, 200);
  assert.equal(payload.ok, true);
  assert.equal(typeof payload.uptimeSec, "number");
});

test("scan endpoint returns cached metadata on repeat requests", async (t) => {
  let calls = 0;
  const server = createAppServer({
    scan: async (url) => {
      calls += 1;
      return createStubReport(url);
    }
  });

  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());

  const address = server.address();
  const endpoint = `http://127.0.0.1:${address.port}/api/scan`;
  const body = JSON.stringify({ url: "https://example.com" });

  const first = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body
  });
  const firstPayload = await first.json();

  const second = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body
  });
  const secondPayload = await second.json();

  assert.equal(first.status, 200);
  assert.equal(firstPayload.meta.cached, false);
  assert.equal(secondPayload.meta.cached, true);
  assert.equal(calls, 1);
});

test("static root returns html", async (t) => {
  const server = createAppServer({
    scan: async (url) => createStubReport(url)
  });

  await new Promise((resolve) => server.listen(0, resolve));
  t.after(() => server.close());

  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/`);
  const text = await response.text();

  assert.equal(response.status, 200);
  assert.match(text, /SiteGuard/);
});
