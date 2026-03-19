import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { ScanError, __internals } from "../src/scanner.js";

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

function lookupPinnedAddress(lookupFn, familyOrOptions) {
  return new Promise((resolve, reject) => {
    lookupFn("example.com", familyOrOptions, (error, addressOrAddresses, family) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(typeof family === "number"
        ? { address: addressOrAddresses, family }
        : addressOrAddresses);
    });
  });
}

test("analyzeSecurityTxt marks missing, complete, and expired states", () => {
  const missing = __internals.analyzeSecurityTxt({ available: false });
  assert.equal(missing.available, false);
  assert.equal(missing.hasContact, false);
  assert.equal(missing.hasExpires, false);

  const complete = __internals.analyzeSecurityTxt({
    available: true,
    contact: "mailto:security@example.com",
    expires: "2099-12-31T23:59:00Z"
  });
  assert.equal(complete.available, true);
  assert.equal(complete.hasContact, true);
  assert.equal(complete.hasExpires, true);
  assert.equal(complete.isExpired, false);

  const expired = __internals.analyzeSecurityTxt({
    available: true,
    contact: "mailto:security@example.com",
    expires: "2020-01-01T00:00:00Z"
  });
  assert.equal(expired.isExpired, true);
});

test("analyzeCors ignores wildcard CORS on public HTML documents", () => {
  const result = __internals.analyzeCors({
    "access-control-allow-origin": "*",
    "access-control-allow-credentials": ""
  }, "text/html; charset=utf-8");

  assert.equal(result.configured, true);
  assert.equal(result.publicDocumentWildcard, true);
  assert.equal(result.permissive, false);
  assert.equal(result.wildcardWithCredentials, false);
});

test("resolvePublicTarget rejects private DNS answers", async () => {
  const target = new URL("https://example.com");

  await assert.rejects(
    () => __internals.resolvePublicTarget(target, async () => [{ address: "10.0.0.5", family: 4 }]),
    (error) => {
      assert.equal(error instanceof ScanError, true);
      assert.equal(error.code, "PRIVATE_DNS_TARGET_BLOCKED");
      return true;
    }
  );
});

test("resolvePublicTarget deduplicates validated public DNS answers", async () => {
  const target = new URL("https://example.com");
  const resolved = await __internals.resolvePublicTarget(target, async () => [
    { address: "93.184.216.34", family: 4 },
    { address: "93.184.216.34", family: 4 },
    { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 }
  ]);

  assert.deepEqual(resolved, [
    { address: "93.184.216.34", family: 4 },
    { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 }
  ]);
});

test("createPinnedLookup honors requested address family and all-address lookups", async () => {
  const pinnedLookup = __internals.createPinnedLookup([
    { address: "93.184.216.34", family: 4 },
    { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 }
  ]);

  const ipv4 = await lookupPinnedAddress(pinnedLookup, { family: 4 });
  assert.deepEqual(ipv4, { address: "93.184.216.34", family: 4 });

  const ipv6 = await lookupPinnedAddress(pinnedLookup, { family: 6 });
  assert.deepEqual(ipv6, {
    address: "2606:2800:220:1:248:1893:25c8:1946",
    family: 6
  });

  const all = await lookupPinnedAddress(pinnedLookup, { all: true });
  assert.deepEqual(all, [
    { address: "93.184.216.34", family: 4 },
    { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 }
  ]);
});

test("assertResolvedSocketAddress accepts pinned addresses and rejects mismatches", () => {
  assert.equal(
    __internals.assertResolvedSocketAddress(
      { remoteAddress: "::ffff:93.184.216.34" },
      [{ address: "93.184.216.34", family: 4 }]
    ),
    "93.184.216.34"
  );

  assert.throws(
    () => __internals.assertResolvedSocketAddress(
      { remoteAddress: "93.184.216.99" },
      [{ address: "93.184.216.34", family: 4 }]
    ),
    (error) => {
      assert.equal(error instanceof ScanError, true);
      assert.equal(error.code, "SOCKET_ADDRESS_MISMATCH");
      return true;
    }
  );
});

test("inspectHtmlDocument parses metadata and ignores comment-based false positives", () => {
  const html = [
    "<!doctype html>",
    "<html lang=\"ko\">",
    "<head>",
    "<title>Safe &amp; Sound</title>",
    "<meta content=\"Security overview\" name=\"description\">",
    "</head>",
    "<body>",
    "<!-- <form method=\"get\"><input type=\"password\"></form> -->",
    "<form method=\"post\" action=\"/login\"><input type=\"password\"></form>",
    "<img src=\"http://cdn.example.com/logo.png\">",
    "<script>const fake = '<form method=\"get\"><input type=\"password\"></form>';</script>",
    "</body>",
    "</html>"
  ].join("");

  const result = __internals.inspectHtmlDocument(
    html,
    "https://example.com/account",
    "text/html; charset=utf-8"
  );

  assert.equal(result.isHtml, true);
  assert.equal(result.lang, "ko");
  assert.equal(result.title, "Safe & Sound");
  assert.equal(result.description, "Security overview");
  assert.equal(result.mixedContentCount, 1);
  assert.equal(result.insecureLoginFormCount, 0);
});

test("requestOnce truncates oversized text bodies and returns partial evidence safely", async () => {
  const server = http.createServer((request, response) => {
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    response.end("A".repeat(64));
  });

  const port = await listen(server);

  try {
    const result = await __internals.requestOnce(
      new URL(`http://127.0.0.1:${port}/`),
      [{ address: "127.0.0.1", family: 4 }],
      {
        maxBodyBytes: 10,
        requestTimeoutMs: 1_000,
        totalTimeoutMs: 1_000
      }
    );

    assert.equal(result.statusCode, 200);
    assert.equal(result.remoteAddress, "127.0.0.1");
    assert.equal(result.body.length, 10);
    assert.equal(result.body, "AAAAAAAAAA");
    assert.equal(result.bodyTruncated, true);
  } finally {
    await close(server);
  }
});

test("requestOnce enforces an absolute timeout for slow streaming responses", async () => {
  const server = http.createServer((request, response) => {
    response.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });

    const timer = setInterval(() => {
      response.write(".");
    }, 40);

    response.on("close", () => {
      clearInterval(timer);
    });
  });

  const port = await listen(server);

  try {
    await assert.rejects(
      () => __internals.requestOnce(
        new URL(`http://127.0.0.1:${port}/`),
        [{ address: "127.0.0.1", family: 4 }],
        {
          maxBodyBytes: 1_024,
          requestTimeoutMs: 1_000,
          totalTimeoutMs: 150
        }
      ),
      (error) => {
        assert.equal(error instanceof ScanError, true);
        assert.equal(error.code, "REQUEST_TOTAL_TIMEOUT");
        return true;
      }
    );
  } finally {
    await close(server);
  }
});
