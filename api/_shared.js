import { randomUUID } from "node:crypto";

import {
  clearAdminSessionCookie,
  createAdminSessionCookie,
  ensureVisitorCookie,
  isAdminConfigured,
  readAdminSession,
  verifyAdminCredentials
} from "../src/admin-auth.js";
import { createMetricsStore } from "../src/metrics-store.js";
import { ScanError, scanTarget } from "../src/scanner.js";
import {
  createConcurrencyGuard,
  createFixedWindowRateLimiter,
  createTtlCache
} from "../src/runtime-guards.js";

const CACHE_TTL_MS = Number(process.env.SCAN_CACHE_TTL_MS || 5 * 60 * 1000);
const MAX_CACHE_ENTRIES = Number(process.env.SCAN_CACHE_MAX_ENTRIES || 300);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60 * 1000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 10);
const MAX_CONCURRENT_SCANS = Number(process.env.MAX_CONCURRENT_SCANS || 4);

function getState() {
  if (!globalThis.__siteguardVercelState) {
    globalThis.__siteguardVercelState = {
      bootedAt: Date.now(),
      cache: createTtlCache({
        ttlMs: CACHE_TTL_MS,
        maxEntries: MAX_CACHE_ENTRIES
      }),
      concurrencyGuard: createConcurrencyGuard({
        limit: MAX_CONCURRENT_SCANS
      }),
      metrics: createMetricsStore(),
      rateLimiter: createFixedWindowRateLimiter({
        limit: RATE_LIMIT_MAX,
        windowMs: RATE_LIMIT_WINDOW_MS
      })
    };
  }

  return globalThis.__siteguardVercelState;
}

function getClientIp(request) {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }

  return request.headers.get("x-real-ip") || "unknown";
}

function isSecureRequest(request) {
  const forwardedProto = request.headers.get("x-forwarded-proto");
  if (forwardedProto) {
    return forwardedProto.split(",")[0].trim().toLowerCase() === "https";
  }

  return new URL(request.url).protocol === "https:";
}

function buildBaseHeaders(request, requestId, { cacheControl = "no-store", contentType } = {}) {
  const headers = new Headers({
    "Cache-Control": cacheControl,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-DNS-Prefetch-Control": "off",
    "X-Request-Id": requestId,
    "Content-Security-Policy": "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
  });

  if (isSecureRequest(request)) {
    headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }

  if (contentType) {
    headers.set("Content-Type", contentType);
  }

  return headers;
}

function jsonResponse(request, requestId, status, payload, extraHeaders = {}) {
  const headers = buildBaseHeaders(request, requestId, {
    cacheControl: "no-store",
    contentType: "application/json; charset=utf-8"
  });

  for (const [key, value] of Object.entries(extraHeaders)) {
    if (value != null) {
      headers.set(key, String(value));
    }
  }

  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers
  });
}

async function readJsonBody(request) {
  const contentType = String(request.headers.get("content-type") || "");
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new ScanError("Content-Type must be application/json.", {
      code: "UNSUPPORTED_CONTENT_TYPE",
      statusCode: 415
    });
  }

  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > 32_768) {
    throw new ScanError("Request body is too large.", {
      code: "BODY_TOO_LARGE",
      statusCode: 413
    });
  }

  if (!raw.trim()) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new ScanError("Request body must be valid JSON.", {
      code: "INVALID_JSON",
      statusCode: 400
    });
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

export async function handleHealthRequest(request) {
  const state = getState();
  const requestId = randomUUID();

  return jsonResponse(request, requestId, 200, {
    ok: true,
    service: "siteguard",
    mode: "passive-public-scan",
    uptimeSec: Math.round((Date.now() - state.bootedAt) / 1000),
    activeScans: state.concurrencyGuard.size(),
    cacheEntries: state.cache.size(),
    metricsBackend: state.metrics.backend || "memory"
  });
}

export async function handleScanRequest(request) {
  const state = getState();
  const requestId = randomUUID();

  if (request.method !== "POST") {
    return jsonResponse(request, requestId, 405, {
      ok: false,
      error: {
        code: "METHOD_NOT_ALLOWED",
        message: "Method not allowed."
      }
    });
  }

  const clientIp = getClientIp(request);
  const rate = state.rateLimiter.check(clientIp);
  const rateHeaders = {
    "Retry-After": Math.max(Math.ceil((rate.resetAt - Date.now()) / 1000), 1),
    "X-RateLimit-Limit": rate.limit,
    "X-RateLimit-Remaining": rate.remaining,
    "X-RateLimit-Reset": new Date(rate.resetAt).toISOString()
  };

  if (!rate.allowed) {
    return jsonResponse(request, requestId, 429, {
      ok: false,
      error: {
        code: "RATE_LIMITED",
        message: "Too many scans from this IP. Please wait and try again."
      }
    }, rateHeaders);
  }

  if (!state.concurrencyGuard.enter()) {
    return jsonResponse(request, requestId, 503, {
      ok: false,
      error: {
        code: "SCAN_QUEUE_FULL",
        message: "The scanner is busy right now. Please retry in a moment."
      }
    }, rateHeaders);
  }

  const startedAt = Date.now();
  let hostnameHint = "";

  try {
    const body = await readJsonBody(request);
    const cacheKey = typeof body.url === "string" ? body.url.trim() : "";
    hostnameHint = extractHostname(cacheKey);
    const cachedPayload = cacheKey ? state.cache.get(cacheKey) : null;

    if (cachedPayload) {
      const payload = {
        ...structuredClone(cachedPayload),
        meta: {
          cached: true,
          durationMs: 0,
          requestId
        }
      };

      await recordMetricSilently(state.metrics, "recordScan", toScanMetric(payload, hostnameHint, requestId, 0, true));
      return jsonResponse(request, requestId, 200, payload, rateHeaders);
    }

    const result = await scanTarget(body.url);
    const payload = {
      ...result,
      meta: {
        cached: false,
        durationMs: Date.now() - startedAt,
        requestId
      }
    };

    if (cacheKey) {
      state.cache.set(cacheKey, payload);
    }

    await recordMetricSilently(
      state.metrics,
      "recordScan",
      toScanMetric(payload, hostnameHint, requestId, payload.meta.durationMs, false)
    );

    return jsonResponse(request, requestId, 200, payload, rateHeaders);
  } catch (error) {
    const statusCode = error instanceof ScanError ? error.statusCode : 500;
    const code = error instanceof ScanError ? error.code : "INTERNAL_ERROR";
    const message = error instanceof ScanError ? error.message : "Unexpected server error.";

    await recordMetricSilently(
      state.metrics,
      "recordScan",
      toScanFailureMetric(hostnameHint, requestId, Date.now() - startedAt, code)
    );

    return jsonResponse(request, requestId, statusCode, {
      ok: false,
      error: {
        code,
        message
      }
    }, rateHeaders);
  } finally {
    state.concurrencyGuard.leave();
  }
}

export async function handleVisitRequest(request) {
  const state = getState();
  const requestId = randomUUID();

  if (request.method !== "POST") {
    return jsonResponse(request, requestId, 405, {
      ok: false,
      error: {
        code: "METHOD_NOT_ALLOWED",
        message: "Method not allowed."
      }
    });
  }

  const visitor = ensureVisitorCookie(request);
  const body = await readJsonBody(request);

  await state.metrics.recordVisit({
    path: typeof body.path === "string" ? body.path : "/",
    visitorId: visitor.visitorId
  });

  return jsonResponse(request, requestId, 200, {
    ok: true,
    tracked: true
  }, visitor.setCookie ? { "Set-Cookie": visitor.setCookie } : {});
}

export async function handleAdminLoginRequest(request) {
  const requestId = randomUUID();

  if (request.method !== "POST") {
    return jsonResponse(request, requestId, 405, {
      ok: false,
      error: {
        code: "METHOD_NOT_ALLOWED",
        message: "Method not allowed."
      }
    });
  }

  if (!isAdminConfigured()) {
    return jsonResponse(request, requestId, 503, {
      ok: false,
      error: {
        code: "ADMIN_NOT_CONFIGURED",
        message: "Admin access is not configured yet."
      }
    });
  }

  const body = await readJsonBody(request);
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const password = typeof body.password === "string" ? body.password : "";

  if (!verifyAdminCredentials(username, password)) {
    return jsonResponse(request, requestId, 401, {
      ok: false,
      error: {
        code: "ADMIN_AUTH_FAILED",
        message: "Incorrect administrator credentials."
      }
    });
  }

  return jsonResponse(request, requestId, 200, {
    ok: true,
    admin: {
      username
    }
  }, {
    "Set-Cookie": createAdminSessionCookie(request, username)
  });
}

export async function handleAdminLogoutRequest(request) {
  const requestId = randomUUID();

  if (request.method !== "POST") {
    return jsonResponse(request, requestId, 405, {
      ok: false,
      error: {
        code: "METHOD_NOT_ALLOWED",
        message: "Method not allowed."
      }
    });
  }

  return jsonResponse(request, requestId, 200, { ok: true }, {
    "Set-Cookie": clearAdminSessionCookie(request)
  });
}

export async function handleAdminSessionRequest(request) {
  const requestId = randomUUID();
  const session = readAdminSession(request);

  return jsonResponse(request, requestId, 200, {
    ok: true,
    admin: {
      authenticated: Boolean(session),
      configured: isAdminConfigured(),
      username: session?.username || null
    }
  });
}

export async function handleAdminMetricsRequest(request) {
  const state = getState();
  const requestId = randomUUID();

  if (request.method !== "GET") {
    return jsonResponse(request, requestId, 405, {
      ok: false,
      error: {
        code: "METHOD_NOT_ALLOWED",
        message: "Method not allowed."
      }
    });
  }

  if (!isAdminConfigured()) {
    return jsonResponse(request, requestId, 503, {
      ok: false,
      error: {
        code: "ADMIN_NOT_CONFIGURED",
        message: "Admin access is not configured yet."
      }
    });
  }

  const session = readAdminSession(request);
  if (!session) {
    return jsonResponse(request, requestId, 401, {
      ok: false,
      error: {
        code: "ADMIN_AUTH_REQUIRED",
        message: "Administrator login is required."
      }
    });
  }

  const snapshot = await state.metrics.getSnapshot();
  return jsonResponse(request, requestId, 200, {
    ok: true,
    admin: {
      username: session.username
    },
    metrics: snapshot
  });
}
