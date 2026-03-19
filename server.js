import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  clearAdminSessionCookie,
  createAdminSessionCookie,
  ensureVisitorCookie,
  isAdminConfigured,
  readAdminSession,
  verifyAdminCredentials
} from "./src/admin-auth.js";
import { createMetricsStore } from "./src/metrics-store.js";
import { ScanError, scanTarget } from "./src/scanner.js";
import {
  createConcurrencyGuard,
  createFixedWindowRateLimiter,
  createTtlCache,
  getClientIp,
  isSecureRequest
} from "./src/runtime-guards.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "public");

const PORT = Number(process.env.PORT || 3000);
const CACHE_TTL_MS = Number(process.env.SCAN_CACHE_TTL_MS || 5 * 60 * 1000);
const MAX_CACHE_ENTRIES = Number(process.env.SCAN_CACHE_MAX_ENTRIES || 300);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60 * 1000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 10);
const MAX_CONCURRENT_SCANS = Number(process.env.MAX_CONCURRENT_SCANS || 4);

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".webp": "image/webp"
};

function getMimeType(filePath) {
  return MIME_TYPES[path.extname(filePath).toLowerCase()] || "application/octet-stream";
}

function normalizePublicPath(urlPathname) {
  const normalized = path.posix.normalize(urlPathname).replace(/^(\.\.\/)+/, "").replace(/^\/+/, "");
  const resolved = path.join(publicDir, normalized || "index.html");

  if (!resolved.startsWith(publicDir)) {
    throw new ScanError("Invalid path.", { code: "INVALID_PATH", statusCode: 400 });
  }

  return resolved;
}

function hasFileExtension(urlPathname) {
  return path.posix.basename(urlPathname).includes(".");
}

function applyBaseHeaders(response, request, requestId, { cacheControl = "no-store", contentType } = {}) {
  response.setHeader("Cache-Control", cacheControl);
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("X-DNS-Prefetch-Control", "off");
  response.setHeader("X-Request-Id", requestId);
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  );

  if (isSecureRequest(request)) {
    response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }

  if (contentType) {
    response.setHeader("Content-Type", contentType);
  }
}

function setExtraHeaders(response, extraHeaders = {}) {
  for (const [key, value] of Object.entries(extraHeaders)) {
    if (value == null) {
      continue;
    }

    response.setHeader(key, value);
  }
}

function sendJson(response, request, requestId, statusCode, payload, extraHeaders = {}) {
  applyBaseHeaders(response, request, requestId, {
    cacheControl: "no-store",
    contentType: "application/json; charset=utf-8"
  });
  setExtraHeaders(response, extraHeaders);
  response.writeHead(statusCode);
  response.end(JSON.stringify(payload, null, 2));
}

async function readJsonBody(request) {
  const contentType = String(request.headers["content-type"] || "");
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new ScanError("Content-Type must be application/json.", {
      code: "UNSUPPORTED_CONTENT_TYPE",
      statusCode: 415
    });
  }

  const chunks = [];
  let size = 0;

  for await (const chunk of request) {
    size += chunk.length;

    if (size > 32_768) {
      throw new ScanError("Request body is too large.", {
        code: "BODY_TOO_LARGE",
        statusCode: 413
      });
    }

    chunks.push(chunk);
  }

  if (!chunks.length) {
    return {};
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ScanError("Request body must be valid JSON.", {
      code: "INVALID_JSON",
      statusCode: 400
    });
  }
}

async function serveStatic(request, response, requestId, pathname) {
  const requestPath = pathname === "/"
    ? "/index.html"
    : (pathname === "/admin" || pathname === "/admin/" ? "/admin/index.html" : pathname);
  const filePath = normalizePublicPath(requestPath);

  try {
    const file = await readFile(filePath);
    applyBaseHeaders(response, request, requestId, {
      cacheControl: filePath.endsWith("index.html") ? "no-store" : "public, max-age=86400, immutable",
      contentType: getMimeType(filePath)
    });
    if (requestPath.startsWith("/admin")) {
      response.setHeader("X-Robots-Tag", "noindex, nofollow");
    }
    response.writeHead(200);
    response.end(request.method === "HEAD" ? undefined : file);
  } catch (error) {
    if (hasFileExtension(requestPath)) {
      throw new ScanError("Static asset not found.", {
        code: "STATIC_NOT_FOUND",
        statusCode: 404
      });
    }

    const fallbackPath = pathname.startsWith("/admin") ? "/admin/index.html" : "/index.html";
    const fallback = await readFile(path.join(publicDir, fallbackPath));
    applyBaseHeaders(response, request, requestId, {
      cacheControl: "no-store",
      contentType: "text/html; charset=utf-8"
    });
    if (pathname.startsWith("/admin")) {
      response.setHeader("X-Robots-Tag", "noindex, nofollow");
    }
    response.writeHead(200);
    response.end(request.method === "HEAD" ? undefined : fallback);
  }
}

function extractHostname(input) {
  if (typeof input !== "string" || !input.trim()) {
    return "";
  }

  try {
    return new URL(input).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function toScanMetric(result, fallbackHostname, requestId, durationMs, cached) {
  return {
    cached,
    durationMs,
    hostname: result?.target?.hostname || fallbackHostname,
    ok: true,
    requestId,
    score: result?.summary?.score ?? null
  };
}

function toScanFailureMetric(hostname, requestId, durationMs, errorCode) {
  return {
    cached: false,
    durationMs,
    errorCode,
    hostname,
    ok: false,
    requestId,
    score: null
  };
}

async function recordMetricSilently(metrics, action, payload) {
  try {
    await metrics[action](payload);
  } catch (error) {
    console.error(`Metrics ${action} failed:`, error);
  }
}

async function handleVisitRequest(request, response, requestId, metrics) {
  const visitor = ensureVisitorCookie(request);
  const body = await readJsonBody(request);
  const rawPath = typeof body.path === "string" ? body.path : "/";

  await metrics.recordVisit({
    path: rawPath,
    visitorId: visitor.visitorId
  });

  sendJson(response, request, requestId, 200, {
    ok: true,
    tracked: true
  }, visitor.setCookie ? { "Set-Cookie": visitor.setCookie } : {});
}

async function handleAdminLoginRequest(request, response, requestId) {
  if (!isAdminConfigured()) {
    sendJson(response, request, requestId, 503, {
      ok: false,
      error: {
        code: "ADMIN_NOT_CONFIGURED",
        message: "Admin access is not configured yet."
      }
    });
    return;
  }

  const body = await readJsonBody(request);
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const password = typeof body.password === "string" ? body.password : "";

  if (!verifyAdminCredentials(username, password)) {
    sendJson(response, request, requestId, 401, {
      ok: false,
      error: {
        code: "ADMIN_AUTH_FAILED",
        message: "Incorrect administrator credentials."
      }
    });
    return;
  }

  sendJson(response, request, requestId, 200, {
    ok: true,
    admin: {
      username
    }
  }, {
    "Set-Cookie": createAdminSessionCookie(request, username)
  });
}

function handleAdminLogoutRequest(request, response, requestId) {
  sendJson(response, request, requestId, 200, {
    ok: true
  }, {
    "Set-Cookie": clearAdminSessionCookie(request)
  });
}

function handleAdminSessionRequest(request, response, requestId) {
  const session = readAdminSession(request);

  sendJson(response, request, requestId, 200, {
    ok: true,
    admin: {
      authenticated: Boolean(session),
      configured: isAdminConfigured(),
      username: session?.username || null
    }
  });
}

async function handleAdminMetricsRequest(request, response, requestId, metrics) {
  if (!isAdminConfigured()) {
    sendJson(response, request, requestId, 503, {
      ok: false,
      error: {
        code: "ADMIN_NOT_CONFIGURED",
        message: "Admin access is not configured yet."
      }
    });
    return;
  }

  const session = readAdminSession(request);
  if (!session) {
    sendJson(response, request, requestId, 401, {
      ok: false,
      error: {
        code: "ADMIN_AUTH_REQUIRED",
        message: "Administrator login is required."
      }
    });
    return;
  }

  const snapshot = await metrics.getSnapshot();
  sendJson(response, request, requestId, 200, {
    ok: true,
    admin: {
      username: session.username
    },
    metrics: snapshot
  });
}

function createScanResponder({ scan, cache, concurrencyGuard, metrics, rateLimiter }) {
  return async function handleScan(request, response, requestId) {
    const clientIp = getClientIp(request);
    const rate = rateLimiter.check(clientIp);
    const rateHeaders = {
      "Retry-After": Math.max(Math.ceil((rate.resetAt - Date.now()) / 1000), 1).toString(),
      "X-RateLimit-Limit": String(rate.limit),
      "X-RateLimit-Remaining": String(rate.remaining),
      "X-RateLimit-Reset": new Date(rate.resetAt).toISOString()
    };

    if (!rate.allowed) {
      sendJson(response, request, requestId, 429, {
        ok: false,
        error: {
          code: "RATE_LIMITED",
          message: "Too many scans from this IP. Please wait and try again."
        }
      }, rateHeaders);
      return;
    }

    if (!concurrencyGuard.enter()) {
      sendJson(response, request, requestId, 503, {
        ok: false,
        error: {
          code: "SCAN_QUEUE_FULL",
          message: "The scanner is busy right now. Please retry in a moment."
        }
      }, rateHeaders);
      return;
    }

    const startedAt = Date.now();
    let hostnameHint = "";

    try {
      const body = await readJsonBody(request);
      const cacheKey = typeof body.url === "string" ? body.url.trim() : "";
      hostnameHint = extractHostname(cacheKey);
      const cachedPayload = cacheKey ? cache.get(cacheKey) : null;

      if (cachedPayload) {
        const payload = {
          ...structuredClone(cachedPayload),
          meta: {
            cached: true,
            durationMs: 0,
            requestId
          }
        };

        await recordMetricSilently(metrics, "recordScan", toScanMetric(payload, hostnameHint, requestId, 0, true));
        sendJson(response, request, requestId, 200, payload, rateHeaders);
        return;
      }

      const result = await scan(body.url);
      const payload = {
        ...result,
        meta: {
          cached: false,
          durationMs: Date.now() - startedAt,
          requestId
        }
      };

      if (cacheKey) {
        cache.set(cacheKey, payload);
      }

      await recordMetricSilently(
        metrics,
        "recordScan",
        toScanMetric(payload, hostnameHint, requestId, payload.meta.durationMs, false)
      );

      sendJson(response, request, requestId, 200, payload, rateHeaders);
    } catch (error) {
      const statusCode = error instanceof ScanError ? error.statusCode : 500;
      const code = error instanceof ScanError ? error.code : "INTERNAL_ERROR";
      const message = error instanceof ScanError ? error.message : "Unexpected server error.";

      await recordMetricSilently(
        metrics,
        "recordScan",
        toScanFailureMetric(hostnameHint, requestId, Date.now() - startedAt, code)
      );

      sendJson(response, request, requestId, statusCode, {
        ok: false,
        error: {
          code,
          message
        }
      }, rateHeaders);
    } finally {
      concurrencyGuard.leave();
    }
  };
}

export function createAppServer({ metrics = createMetricsStore(), scan = scanTarget } = {}) {
  const bootedAt = Date.now();
  const cache = createTtlCache({
    ttlMs: CACHE_TTL_MS,
    maxEntries: MAX_CACHE_ENTRIES
  });
  const concurrencyGuard = createConcurrencyGuard({
    limit: MAX_CONCURRENT_SCANS
  });
  const rateLimiter = createFixedWindowRateLimiter({
    limit: RATE_LIMIT_MAX,
    windowMs: RATE_LIMIT_WINDOW_MS
  });
  const handleScan = createScanResponder({
    scan,
    cache,
    concurrencyGuard,
    metrics,
    rateLimiter
  });

  return createServer(async (request, response) => {
    const requestId = randomUUID();

    try {
      const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
      const pathname = url.pathname;

      if (request.method === "GET" && (pathname === "/api/health" || pathname === "/api/ready")) {
        sendJson(response, request, requestId, 200, {
          ok: true,
          service: "siteguard",
          mode: "passive-public-scan",
          uptimeSec: Math.round((Date.now() - bootedAt) / 1000),
          activeScans: concurrencyGuard.size(),
          cacheEntries: cache.size(),
          metricsBackend: metrics.backend || "memory"
        });
        return;
      }

      if (request.method === "POST" && pathname === "/api/scan") {
        await handleScan(request, response, requestId);
        return;
      }

      if (request.method === "POST" && pathname === "/api/metrics/visit") {
        await handleVisitRequest(request, response, requestId, metrics);
        return;
      }

      if (request.method === "POST" && pathname === "/api/admin/login") {
        await handleAdminLoginRequest(request, response, requestId);
        return;
      }

      if (request.method === "POST" && pathname === "/api/admin/logout") {
        handleAdminLogoutRequest(request, response, requestId);
        return;
      }

      if (request.method === "GET" && pathname === "/api/admin/session") {
        handleAdminSessionRequest(request, response, requestId);
        return;
      }

      if (request.method === "GET" && pathname === "/api/admin/metrics") {
        await handleAdminMetricsRequest(request, response, requestId, metrics);
        return;
      }

      if (request.method === "GET" || request.method === "HEAD") {
        await serveStatic(request, response, requestId, pathname);
        return;
      }

      throw new ScanError("Method not allowed.", {
        code: "METHOD_NOT_ALLOWED",
        statusCode: 405
      });
    } catch (error) {
      const statusCode = error instanceof ScanError ? error.statusCode : 500;
      const code = error instanceof ScanError ? error.code : "INTERNAL_ERROR";
      const message = error instanceof ScanError ? error.message : "Unexpected server error.";

      sendJson(response, request, requestId, statusCode, {
        ok: false,
        error: {
          code,
          message
        }
      });
    }
  });
}

export function startServer(port = PORT) {
  const server = createAppServer();
  server.listen(port, "0.0.0.0", () => {
    console.log(`SiteGuard server listening on http://localhost:${port}`);
  });
  return server;
}

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
});
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
});

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startServer();
}
