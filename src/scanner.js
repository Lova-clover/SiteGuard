import http from "node:http";
import https from "node:https";
import { lookup } from "node:dns/promises";
import net from "node:net";
import { parse as parseHtml } from "parse5";

import { attachRemediation } from "./remediation.js";

const MAX_REDIRECTS = 6;
const MAX_BODY_BYTES = 262_144;
const REQUEST_TIMEOUT_MS = 8_000;
const TOTAL_REQUEST_TIMEOUT_MS = 10_000;
const TEXTUAL_TYPES = [
  "application/json",
  "application/javascript",
  "application/xml",
  "image/svg+xml",
  "text/"
];

const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3
};

const FINDING_CATEGORY_ORDER = {
  direct: 0,
  hardening: 1,
  maturity: 2
};

const WARN_CREDIT_RATIO = 0.65;

const SENSITIVE_COOKIE_NAME_PATTERN = /(^|[-_])(?:auth|csrf|id|identity|jwt|login|refresh|session|sid|state|token|user)(?:$|[-_])/i;

const MIXED_CONTENT_ATTRIBUTES = new Map([
  ["audio", ["src"]],
  ["embed", ["src"]],
  ["iframe", ["src"]],
  ["img", ["src", "srcset"]],
  ["input", ["src"]],
  ["link", ["href"]],
  ["object", ["data"]],
  ["script", ["src"]],
  ["source", ["src", "srcset"]],
  ["track", ["src"]],
  ["video", ["poster", "src"]]
]);

export class ScanError extends Error {
  constructor(message, { code = "SCAN_ERROR", statusCode = 400 } = {}) {
    super(message);
    this.name = "ScanError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export async function scanTarget(rawUrl) {
  const inputUrl = normalizeInputUrl(rawUrl);
  await resolvePublicTarget(inputUrl);

  const targets = buildProtocolTargets(inputUrl);
  const [httpProbe, httpsProbe] = await Promise.all([
    attemptProbe(targets.http, "http"),
    attemptProbe(targets.https, "https")
  ]);

  const primary = choosePrimaryProbe(httpProbe, httpsProbe);
  const finalResponse = primary.result.finalResponse;
  const cookies = parseCookies(finalResponse.headers["set-cookie"]);
  const htmlProfile = inspectHtmlDocument(finalResponse.body, primary.result.finalUrl, finalResponse.contentType);
  const htmlSignals = extractHtmlSignals(finalResponse.body, primary.result.finalUrl, finalResponse.contentType, htmlProfile);
  const page = extractPageProfile(finalResponse.body, finalResponse.contentType, htmlProfile);
  const securityTxt = await inspectSecurityTxt(primary.result.finalUrl);

  const analysis = {
    cookies,
    csp: analyzeCsp(finalResponse.headers["content-security-policy"]),
    cors: analyzeCors(finalResponse.headers, finalResponse.contentType),
    exposure: analyzeExposure(finalResponse.headers),
    hsts: analyzeHsts(finalResponse.headers["strict-transport-security"]),
    htmlSignals,
    isHtml: htmlSignals.isHtml,
    referrerPolicy: analyzeReferrerPolicy(finalResponse.headers["referrer-policy"]),
    securityTxt: analyzeSecurityTxt(securityTxt),
    tls: analyzeTls(primary.protocol === "https" ? finalResponse.tls : null),
    xFrameOptions: normalizeHeaderText(finalResponse.headers["x-frame-options"])
  };

  const findings = attachRemediation(
    sortFindings(buildFindings({
      analysis,
      finalResponse,
      httpProbe,
      httpsProbe,
      securityTxt
    }))
  );

  const checks = buildChecks({
    analysis,
    findings,
    finalResponse,
    httpProbe,
    httpsProbe,
    securityTxt
  });

  const score = scoreChecks(checks);
  const summary = buildSummary({
    checks,
    findings,
    httpProbe,
    httpsProbe,
    score
  });

  return {
    ok: true,
    target: {
      scannedAt: new Date().toISOString(),
      input: rawUrl,
      normalized: inputUrl.toString(),
      hostname: inputUrl.hostname,
      primaryProtocol: primary.protocol,
      finalUrl: primary.result.finalUrl,
      publicScanMode: "passive"
    },
    summary,
    findings,
    checks,
    evidence: {
      redirectChain: primary.result.redirectChain,
      finalHeaders: finalResponse.headers,
      finalStatusCode: finalResponse.statusCode,
      finalContentType: finalResponse.contentType,
      finalRemoteAddress: finalResponse.remoteAddress,
      tls: primary.protocol === "https" ? finalResponse.tls : null,
      cookies,
      page: {
        ...page,
        isHtml: htmlSignals.isHtml,
        insecureLoginFormCount: htmlSignals.insecureLoginFormCount,
        mixedContentCount: htmlSignals.mixedContentCount
      },
      securityTxt,
      probes: {
        http: summarizeProbe(httpProbe),
        https: summarizeProbe(httpsProbe)
      }
    },
    limitations: [
      "이 스캔은 공개 URL에 대한 패시브 검사만 수행합니다.",
      "IDOR, 권한 우회, SQLi, XSS, 업로드 취약점은 URL만으로 확정할 수 없습니다.",
      "로그인 후 화면, 사설망 자원, 내부 API는 검사하지 않습니다.",
      "실제 비즈니스 로직 보안은 별도의 수동 리뷰와 인증된 테스트가 필요합니다."
    ]
  };
}

function summarizeProbe(probe) {
  if (!probe.success) {
    return {
      ok: false,
      protocol: probe.protocol,
      error: probe.error
    };
  }

  return {
    ok: true,
    protocol: probe.protocol,
    finalUrl: probe.result.finalUrl,
    statusCode: probe.result.finalResponse.statusCode,
    remoteAddress: probe.result.finalResponse.remoteAddress,
    responseTimeMs: probe.result.finalResponse.elapsedMs,
    redirectCount: probe.result.redirectChain.length - 1
  };
}

function normalizeInputUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") {
    throw new ScanError("검사할 URL을 입력해 주세요.", {
      code: "URL_REQUIRED",
      statusCode: 400
    });
  }

  const trimmed = rawUrl.trim();
  const value = /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(trimmed) ? trimmed : `https://${trimmed}`;

  let url;

  try {
    url = new URL(value);
  } catch {
    throw new ScanError("URL 형식이 올바르지 않습니다.", {
      code: "INVALID_URL",
      statusCode: 400
    });
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new ScanError("http 또는 https URL만 검사할 수 있습니다.", {
      code: "UNSUPPORTED_PROTOCOL",
      statusCode: 400
    });
  }

  if (url.username || url.password) {
    throw new ScanError("자격 증명이 포함된 URL은 허용되지 않습니다.", {
      code: "URL_WITH_CREDENTIALS",
      statusCode: 400
    });
  }

  url.hash = "";

  return url;
}

function buildProtocolTargets(inputUrl) {
  const suffix = `${inputUrl.pathname || "/"}${inputUrl.search || ""}`;
  const host = inputUrl.host;

  return {
    http: new URL(`http://${host}${suffix}`),
    https: new URL(`https://${host}${suffix}`)
  };
}

async function attemptProbe(url, protocol) {
  try {
    const result = await requestWithRedirects(url);

    return {
      protocol,
      success: true,
      result
    };
  } catch (error) {
    const normalizedError = error instanceof ScanError
      ? error
      : new ScanError("요청 중 알 수 없는 오류가 발생했습니다.", {
          code: "REQUEST_FAILED",
          statusCode: 502
        });

    return {
      protocol,
      success: false,
      error: {
        code: normalizedError.code,
        message: normalizedError.message
      }
    };
  }
}

function choosePrimaryProbe(httpProbe, httpsProbe) {
  if (httpsProbe.success) {
    return httpsProbe;
  }

  if (httpProbe.success) {
    return httpProbe;
  }

  throw new ScanError("대상 URL에 연결할 수 없습니다. 공개적으로 접근 가능한 URL인지 확인해 주세요.", {
    code: httpsProbe.error?.code || httpProbe.error?.code || "UNREACHABLE_TARGET",
    statusCode: 502
  });
}

async function requestWithRedirects(startUrl) {
  const redirectChain = [];
  let currentUrl = startUrl;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const resolvedTarget = await resolvePublicTarget(currentUrl);
    const response = await requestOnce(currentUrl, resolvedTarget);
    const location = normalizeHeaderText(response.headers.location);
    const isRedirect = [301, 302, 303, 307, 308].includes(response.statusCode) && location;

    redirectChain.push({
      url: currentUrl.toString(),
      statusCode: response.statusCode,
      location: isRedirect ? new URL(location, currentUrl).toString() : null
    });

    if (!isRedirect) {
      return {
        finalUrl: currentUrl.toString(),
        finalResponse: response,
        redirectChain
      };
    }

    currentUrl = new URL(location, currentUrl);
  }

  throw new ScanError("리다이렉트가 너무 많아 검사를 중단했습니다.", {
    code: "TOO_MANY_REDIRECTS",
    statusCode: 502
  });
}

function requestOnce(url, resolvedTarget, policy = {}) {
  if (!Array.isArray(resolvedTarget) && resolvedTarget && typeof resolvedTarget === "object") {
    policy = resolvedTarget;
    resolvedTarget = undefined;
  }

  const startedAt = Date.now();
  const client = url.protocol === "https:" ? https : http;
  const maxBodyBytes = policy.maxBodyBytes ?? MAX_BODY_BYTES;
  const requestTimeoutMs = policy.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
  const totalTimeoutMs = policy.totalTimeoutMs ?? TOTAL_REQUEST_TIMEOUT_MS;
  const pinnedLookup = resolvedTarget?.length ? createPinnedLookup(resolvedTarget) : undefined;

  return new Promise((resolve, reject) => {
    let settled = false;
    let request;

    const finish = (handler) => (value) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(totalTimeout);
      handler(value);
    };

    const finishWithResponse = finish(resolve);
    const finishWithError = finish((error) => reject(normalizeRequestError(error)));

    const requestOptions = {
      hostname: url.hostname,
      port: url.port || undefined,
      path: `${url.pathname || "/"}${url.search || ""}`,
      method: "GET",
      headers: {
        Accept: "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "identity",
        Connection: "close",
        "User-Agent": "SiteGuard/1.0 (Web Security Posture Scanner)"
      },
      rejectUnauthorized: false,
      servername: net.isIP(url.hostname) ? undefined : url.hostname
    };

    if (pinnedLookup) {
      requestOptions.lookup = pinnedLookup;
    }

    const totalTimeout = setTimeout(() => {
      const error = new ScanError("?? ?? ??? ???????.", {
        code: "REQUEST_TOTAL_TIMEOUT",
        statusCode: 504
      });
      request?.destroy(error);
      finishWithError(error);
    }, totalTimeoutMs);

    request = client.request(requestOptions, (response) => {
      try {
        if (resolvedTarget?.length) {
          assertResolvedSocketAddress(response.socket, resolvedTarget);
        }
      } catch (error) {
        finishWithError(error);
        response.destroy();
        return;
      }

      const headers = normalizeHeaders(response.headers);
      const contentType = normalizeHeaderText(headers["content-type"]);
      const shouldCollectBody = isTextualContentType(contentType);
      const chunks = [];
      let totalBytes = 0;
      let bodyTruncated = false;

      const buildResponse = () => ({
        body: shouldCollectBody ? Buffer.concat(chunks).toString("utf8") : "",
        bodyTruncated,
        contentType,
        elapsedMs: Date.now() - startedAt,
        headers,
        remoteAddress: normalizeIpForComparison(response.socket?.remoteAddress),
        statusCode: response.statusCode || 0,
        tls: buildTlsSnapshot(response.socket, url.protocol)
      });

      if (!shouldCollectBody) {
        finishWithResponse(buildResponse());
        response.destroy();
        return;
      }

      response.on("data", (chunk) => {
        if (settled || totalBytes >= maxBodyBytes) {
          return;
        }

        const remaining = maxBodyBytes - totalBytes;
        const nextChunk = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;

        if (nextChunk.length) {
          chunks.push(nextChunk);
          totalBytes += nextChunk.length;
        }

        if (totalBytes >= maxBodyBytes) {
          bodyTruncated = true;
          finishWithResponse(buildResponse());
          response.destroy();
        }
      });

      response.on("end", () => {
        finishWithResponse(buildResponse());
      });

      response.on("aborted", () => {
        if (!settled) {
          finishWithError(new ScanError("?? ??? ??? ??? ??????.", {
            code: "REMOTE_ABORTED",
            statusCode: 502
          }));
        }
      });

      response.on("error", (error) => {
        if (!settled) {
          finishWithError(error);
        }
      });
    });

    request.setTimeout(requestTimeoutMs, () => {
      const error = new ScanError("?? ??? ???????.", {
        code: "REQUEST_TIMEOUT",
        statusCode: 504
      });
      request.destroy(error);
      finishWithError(error);
    });

    request.on("error", (error) => {
      if (!settled) {
        finishWithError(error);
      }
    });

    request.end();
  });
}

function buildTlsSnapshot(socket, protocol) {
  if (protocol !== "https:" || !socket) {
    return null;
  }

  const certificate = socket.getPeerCertificate?.() || null;
  const cipher = socket.getCipher?.() || null;

  return {
    authorized: socket.authorized ?? false,
    authorizationError: socket.authorizationError || null,
    cipher: cipher?.name || null,
    issuer: certificate?.issuer?.CN || null,
    protocol: socket.getProtocol?.() || null,
    subject: certificate?.subject?.CN || null,
    validFrom: certificate?.valid_from || null,
    validTo: certificate?.valid_to || null
  };
}

function normalizeRequestError(error) {
  if (error instanceof ScanError) {
    return error;
  }

  const code = error?.code || "REQUEST_FAILED";

  switch (code) {
    case "ECONNREFUSED":
      return new ScanError("대상 서버가 연결을 거부했습니다.", {
        code,
        statusCode: 502
      });
    case "ENOTFOUND":
      return new ScanError("도메인을 찾을 수 없습니다.", {
        code,
        statusCode: 404
      });
    case "ECONNRESET":
      return new ScanError("대상 서버가 연결을 재설정했습니다.", {
        code,
        statusCode: 502
      });
    default:
      return new ScanError(error?.message || "요청에 실패했습니다.", {
        code,
        statusCode: 502
      });
  }
}

function normalizeHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value])
  );
}

function normalizeHeaderText(value) {
  if (!value) {
    return "";
  }

  return Array.isArray(value) ? value.join(", ") : String(value);
}

function isTextualContentType(contentType) {
  return TEXTUAL_TYPES.some((prefix) => contentType.startsWith(prefix));
}

async function assertPublicTarget(url) {
  await resolvePublicTarget(url);
}

async function resolvePublicTarget(url, dnsLookup = lookup) {
  const hostname = url.hostname.toLowerCase();

  if (isBlockedHostname(hostname)) {
    throw new ScanError("?? ?? ?? ???? ??? ? ????.", {
      code: "PRIVATE_HOST_BLOCKED",
      statusCode: 400
    });
  }

  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new ScanError("?? ?? ??? IP ??? ??? ? ????.", {
        code: "PRIVATE_IP_BLOCKED",
        statusCode: 400
      });
    }

    return [{ address: hostname, family: net.isIP(hostname) }];
  }

  let resolved;

  try {
    resolved = await dnsLookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw normalizeRequestError(error);
  }

  if (!resolved.length) {
    throw new ScanError("???? ??? ? ????.", {
      code: "DNS_LOOKUP_EMPTY",
      statusCode: 404
    });
  }

  const deduped = dedupeResolvedEntries(resolved);

  for (const entry of deduped) {
    if (isPrivateIp(entry.address)) {
      throw new ScanError("?? ?? ??? IP? ???? ???? ??? ? ????.", {
        code: "PRIVATE_DNS_TARGET_BLOCKED",
        statusCode: 400
      });
    }
  }

  return deduped;
}

function dedupeResolvedEntries(entries) {
  const unique = new Map();

  for (const entry of entries) {
    if (!entry?.address || !entry?.family) {
      continue;
    }

    unique.set(`${entry.family}:${entry.address}`, {
      address: entry.address,
      family: entry.family
    });
  }

  return [...unique.values()];
}

function createPinnedLookup(resolvedTarget) {
  const addresses = dedupeResolvedEntries(resolvedTarget);

  if (!addresses.length) {
    throw new ScanError("Pinned DNS target is empty.", {
      code: "DNS_PINNING_EMPTY",
      statusCode: 502
    });
  }

  return (_hostname, options, callback) => {
    const normalizedOptions = typeof options === "number" ? { family: options } : (options || {});
    const family = normalizedOptions.family || 0;
    const matches = family
      ? addresses.filter((entry) => entry.family === family)
      : addresses;

    if (!matches.length) {
      const error = new Error("Pinned DNS target does not provide the requested address family.");
      error.code = "EAI_ADDRFAMILY";
      callback(error);
      return;
    }

    if (normalizedOptions.all) {
      callback(null, matches.map((entry) => ({
        address: entry.address,
        family: entry.family
      })));
      return;
    }

    callback(null, matches[0].address, matches[0].family);
  };
}

function normalizeIpForComparison(ipAddress) {
  if (!ipAddress) {
    return "";
  }

  const normalized = String(ipAddress).toLowerCase().split("%")[0];
  const mappedIpv4 = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return mappedIpv4 ? mappedIpv4[1] : normalized;
}

function assertResolvedSocketAddress(socket, resolvedTarget) {
  const remoteAddress = normalizeIpForComparison(socket?.remoteAddress);

  if (!remoteAddress) {
    throw new ScanError("원격 소켓 주소를 확인할 수 없습니다.", {
      code: "SOCKET_ADDRESS_MISSING",
      statusCode: 502
    });
  }

  const allowedAddresses = new Set(
    dedupeResolvedEntries(resolvedTarget).map((entry) => normalizeIpForComparison(entry.address))
  );

  if (!allowedAddresses.has(remoteAddress)) {
    throw new ScanError("실제 연결 주소가 검증한 DNS 대상과 일치하지 않습니다.", {
      code: "SOCKET_ADDRESS_MISMATCH",
      statusCode: 502
    });
  }

  return remoteAddress;
}

function isBlockedHostname(hostname) {
  return hostname === "localhost"
    || hostname.endsWith(".localhost")
    || hostname.endsWith(".local")
    || hostname.endsWith(".internal")
    || hostname.endsWith(".localdomain");
}

function isPrivateIp(ipAddress) {
  const family = net.isIP(ipAddress);

  if (!family) {
    return true;
  }

  if (family === 4) {
    const octets = ipAddress.split(".").map(Number);
    const [a, b] = octets;

    if (octets.some((value) => Number.isNaN(value) || value < 0 || value > 255)) {
      return true;
    }

    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true;
    return false;
  }

  const normalized = ipAddress.toLowerCase().split("%")[0];

  if (normalized === "::" || normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (/^fe[89ab]/.test(normalized)) return true;
  if (normalized.startsWith("ff")) return true;
  if (normalized.startsWith("2001:db8")) return true;

  const mappedIpv4 = normalized.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mappedIpv4) {
    return isPrivateIp(mappedIpv4[1]);
  }

  return false;
}

function analyzeTls(tls) {
  if (!tls) {
    return {
      applicable: false,
      daysUntilExpiry: null,
      hasTrustChainWarning: false,
      isValid: false,
      isExpiringSoon: false
    };
  }

  const trustChainWarnings = new Set([
    "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
  ]);
  const expiresAt = tls.validTo ? new Date(tls.validTo) : null;
  const daysUntilExpiry = expiresAt
    ? Math.round((expiresAt.getTime() - Date.now()) / 86_400_000)
    : null;
  const hasTrustChainWarning = Boolean(tls.authorizationError && trustChainWarnings.has(tls.authorizationError));

  return {
    applicable: true,
    daysUntilExpiry,
    hasTrustChainWarning,
    isExpiringSoon: typeof daysUntilExpiry === "number" && daysUntilExpiry <= 21,
    isValid: !tls.authorizationError || hasTrustChainWarning
  };
}

function analyzeHsts(headerValue) {
  const raw = normalizeHeaderText(headerValue);

  if (!raw) {
    return {
      enabled: false,
      maxAge: 0,
      strong: false
    };
  }

  const match = raw.match(/max-age\s*=\s*(\d+)/i);
  const maxAge = match ? Number(match[1]) : 0;

  return {
    enabled: true,
    maxAge,
    strong: maxAge >= 15_552_000
  };
}

function analyzeCsp(headerValue) {
  const raw = normalizeHeaderText(headerValue);

  if (!raw) {
    return {
      enabled: false,
      weak: false
    };
  }

  const lowered = raw.toLowerCase();

  return {
    enabled: true,
    weak: lowered.includes("'unsafe-inline'")
      || lowered.includes("'unsafe-eval'")
      || lowered.includes("default-src *")
      || lowered.includes("script-src *")
  };
}

function analyzeReferrerPolicy(headerValue) {
  const raw = normalizeHeaderText(headerValue).toLowerCase();
  const weakPolicies = new Set(["unsafe-url", "origin", "origin-when-cross-origin"]);

  return {
    defined: Boolean(raw),
    value: raw || null,
    weak: weakPolicies.has(raw)
  };
}

function analyzeCors(headers, contentType = "") {
  const origin = normalizeHeaderText(headers["access-control-allow-origin"]);
  const credentials = normalizeHeaderText(headers["access-control-allow-credentials"]).toLowerCase();
  const normalizedContentType = normalizeHeaderText(contentType || headers["content-type"]).toLowerCase();
  const publicDocumentWildcard = origin === "*"
    && credentials !== "true"
    && normalizedContentType.startsWith("text/html");

  if (!origin) {
    return {
      configured: false,
      publicDocumentWildcard: false,
      permissive: false,
      wildcardWithCredentials: false
    };
  }

  return {
    configured: true,
    permissive: origin === "*" && !publicDocumentWildcard,
    publicDocumentWildcard,
    wildcardWithCredentials: origin === "*" && credentials === "true"
  };
}

function analyzeExposure(headers) {
  const server = normalizeHeaderText(headers.server);
  const poweredBy = normalizeHeaderText(headers["x-powered-by"]);
  const combined = `${server} ${poweredBy}`.trim();

  return {
    server,
    poweredBy,
    verbose: /apache\/|nginx\/|iis|express|next\.js|php|asp\.net|openresty|gunicorn|uvicorn|\d+\.\d+/.test(combined.toLowerCase())
  };
}

function parseCookies(headerValue) {
  const entries = Array.isArray(headerValue) ? headerValue : headerValue ? [headerValue] : [];

  return entries.map((raw) => {
    const segments = String(raw).split(";").map((segment) => segment.trim());
    const [nameValue, ...flags] = segments;
    const [name = "", value = ""] = nameValue.split("=");
    const normalizedFlags = flags.map((flag) => flag.toLowerCase());
    const sameSiteEntry = flags.find((flag) => /^samesite=/i.test(flag)) || "";

    return {
      name,
      valuePreview: value ? `${value.slice(0, 6)}${value.length > 6 ? "..." : ""}` : "",
      raw,
      secure: normalizedFlags.includes("secure"),
      httpOnly: normalizedFlags.includes("httponly"),
      sameSite: sameSiteEntry ? sameSiteEntry.split("=")[1] : null
    };
  });
}

function isLikelySensitiveCookie(cookie) {
  const name = String(cookie?.name || "");
  return name.startsWith("__Host-")
    || SENSITIVE_COOKIE_NAME_PATTERN.test(name);
}

function assessCookieHardening(cookies) {
  if (!cookies.length) {
    return {
      applicable: false,
      category: "hardening",
      insecureCookies: [],
      insecureSensitiveCookies: [],
      likelySensitiveCookies: [],
      severity: null,
      status: "na"
    };
  }

  const insecureCookies = cookies.filter((cookie) => !cookie.secure || !cookie.httpOnly || !cookie.sameSite);
  const likelySensitiveCookies = cookies.filter(isLikelySensitiveCookie);
  const insecureSensitiveCookies = likelySensitiveCookies.filter((cookie) => !cookie.secure || !cookie.httpOnly);

  if (!insecureCookies.length) {
    return {
      applicable: true,
      category: "hardening",
      insecureCookies,
      insecureSensitiveCookies,
      likelySensitiveCookies,
      severity: null,
      status: "pass"
    };
  }

  if (insecureSensitiveCookies.length > 0) {
    return {
      applicable: true,
      category: "direct",
      insecureCookies,
      insecureSensitiveCookies,
      likelySensitiveCookies,
      severity: "high",
      status: "fail"
    };
  }

  return {
    applicable: true,
    category: "hardening",
    insecureCookies,
    insecureSensitiveCookies,
    likelySensitiveCookies,
    severity: insecureCookies.length >= Math.max(2, Math.ceil(cookies.length / 2)) ? "medium" : "low",
    status: "warn"
  };
}

function inspectHtmlDocument(body, finalUrl, contentType) {
  const isHtml = contentType.startsWith("text/html") || /<html[\s>]/i.test(body) || /<!doctype html/i.test(body);

  if (!isHtml || !body) {
    return {
      description: null,
      insecureLoginFormCount: 0,
      isHtml: false,
      lang: null,
      mixedContentCount: 0,
      title: null
    };
  }

  const document = parseHtml(body);
  const finalUrlObject = finalUrl ? new URL(finalUrl) : null;
  let description = null;
  let insecureLoginFormCount = 0;
  let lang = null;
  let mixedContentCount = 0;
  let title = null;

  walkHtmlNodes(document, (node) => {
    if (!node?.tagName) {
      return;
    }

    const tagName = String(node.tagName).toLowerCase();

    if (tagName === "html" && !lang) {
      lang = normalizeHtmlText(getHtmlAttribute(node, "lang") || "");
    }

    if (tagName === "title" && !title) {
      title = normalizeHtmlText(readHtmlText(node));
    }

    if (tagName === "meta" && !description) {
      const name = (getHtmlAttribute(node, "name") || "").toLowerCase();
      if (name === "description") {
        description = normalizeHtmlText(getHtmlAttribute(node, "content") || "");
      }
    }

    if (finalUrlObject?.protocol === "https:" && isMixedContentNode(node)) {
      for (const attributeName of MIXED_CONTENT_ATTRIBUTES.get(tagName) || []) {
        const value = getHtmlAttribute(node, attributeName);
        if (isInsecureSubresourceReference(value, tagName, attributeName, node)) {
          mixedContentCount += 1;
        }
      }
    }

    if (tagName === "form" && formContainsPasswordField(node)) {
      const method = (getHtmlAttribute(node, "method") || "get").toLowerCase();
      const action = getHtmlAttribute(node, "action");

      if (method === "get") {
        insecureLoginFormCount += 1;
        return;
      }

      if (action && finalUrlObject) {
        try {
          const resolvedAction = new URL(action, finalUrlObject);
          if (resolvedAction.protocol === "http:") {
            insecureLoginFormCount += 1;
          }
        } catch {
          insecureLoginFormCount += 1;
        }
      }
    }
  });

  return {
    description,
    insecureLoginFormCount,
    isHtml: true,
    lang,
    mixedContentCount,
    title
  };
}

function extractHtmlSignals(body, finalUrl, contentType, cachedProfile) {
  const profile = cachedProfile || inspectHtmlDocument(body, finalUrl, contentType);

  return {
    insecureLoginFormCount: profile.insecureLoginFormCount,
    isHtml: profile.isHtml,
    mixedContentCount: profile.mixedContentCount
  };
}

function extractPageProfile(body, contentType, cachedProfile) {
  const profile = cachedProfile || inspectHtmlDocument(body, null, contentType);

  return {
    description: profile.description,
    lang: profile.lang,
    title: profile.title
  };
}

function walkHtmlNodes(node, visit) {
  visit(node);

  for (const child of node?.childNodes || []) {
    walkHtmlNodes(child, visit);
  }
}

function getHtmlAttribute(node, name) {
  const attribute = node?.attrs?.find((entry) => entry.name?.toLowerCase() === name.toLowerCase());
  return attribute?.value || "";
}

function readHtmlText(node) {
  if (!node) {
    return "";
  }

  if (node.nodeName === "#text") {
    return node.value || "";
  }

  return (node.childNodes || []).map((child) => readHtmlText(child)).join("");
}

function formContainsPasswordField(node) {
  let hasPasswordField = false;

  walkHtmlNodes(node, (child) => {
    if (hasPasswordField || child?.tagName !== "input") {
      return;
    }

    hasPasswordField = (getHtmlAttribute(child, "type") || "").toLowerCase() === "password";
  });

  return hasPasswordField;
}

function isMixedContentNode(node) {
  const tagName = String(node?.tagName || "").toLowerCase();
  return MIXED_CONTENT_ATTRIBUTES.has(tagName);
}

function isInsecureSubresourceReference(value, tagName, attributeName, node) {
  if (!value) {
    return false;
  }

  const normalizedValue = String(value).trim().toLowerCase();

  if (attributeName === "srcset") {
    return normalizedValue
      .split(",")
      .map((entry) => entry.trim().split(/\s+/)[0])
      .some((candidate) => candidate.startsWith("http://"));
  }

  if (!normalizedValue.startsWith("http://")) {
    return false;
  }

  if (tagName !== "link" || attributeName !== "href") {
    return true;
  }

  const rel = (getHtmlAttribute(node, "rel") || "").toLowerCase();
  return /(?:^|\s)(?:stylesheet|preload|modulepreload|icon|mask-icon|apple-touch-icon|manifest)(?:\s|$)/.test(rel);
}

async function inspectSecurityTxt(finalUrl) {
  const origin = new URL(finalUrl).origin;
  const candidates = [
    new URL("/.well-known/security.txt", origin),
    new URL("/security.txt", origin)
  ];

  for (const candidate of candidates) {
    try {
      const result = await requestWithRedirects(candidate);
      const response = result.finalResponse;

      if (response.statusCode < 200 || response.statusCode >= 300 || !response.body.trim()) {
        continue;
      }

      return {
        available: true,
        ...parseSecurityTxt(response.body),
        scannedUrl: candidate.toString(),
        url: result.finalUrl
      };
    } catch {
      // security.txt is a best-effort maturity signal, so failures stay silent
    }
  }

  return {
    acknowledgments: null,
    available: false,
    canonical: null,
    contact: null,
    expires: null,
    hiring: null,
    preferredLanguages: [],
    preview: "",
    scannedUrl: candidates[0].toString(),
    url: candidates[0].toString()
  };
}

function parseSecurityTxt(body) {
  const lines = body
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const contentLines = lines.filter((line) => !line.startsWith("#"));
  const readFirst = (field) => {
    const prefix = `${field.toLowerCase()}:`;
    const match = contentLines.find((line) => line.toLowerCase().startsWith(prefix));
    return match ? match.slice(prefix.length).trim() : null;
  };
  const readMany = (field) => {
    const prefix = `${field.toLowerCase()}:`;
    return contentLines
      .filter((line) => line.toLowerCase().startsWith(prefix))
      .map((line) => line.slice(prefix.length).trim())
      .filter(Boolean);
  };

  return {
    acknowledgments: readFirst("Acknowledgments"),
    canonical: readFirst("Canonical"),
    contact: readFirst("Contact"),
    expires: readFirst("Expires"),
    hiring: readFirst("Hiring"),
    preferredLanguages: readMany("Preferred-Languages"),
    preview: contentLines.slice(0, 6).join("\n")
  };
}

function analyzeSecurityTxt(securityTxt) {
  if (!securityTxt?.available) {
    return {
      available: false,
      daysUntilExpiry: null,
      hasContact: false,
      hasExpires: false,
      isExpired: false,
      isExpiringSoon: false
    };
  }

  const expiresAt = securityTxt.expires ? new Date(securityTxt.expires) : null;
  const isValidDate = Boolean(expiresAt) && !Number.isNaN(expiresAt.getTime());
  const daysUntilExpiry = isValidDate
    ? Math.round((expiresAt.getTime() - Date.now()) / 86_400_000)
    : null;

  return {
    available: true,
    daysUntilExpiry,
    hasContact: Boolean(securityTxt.contact),
    hasExpires: Boolean(securityTxt.expires),
    isExpired: typeof daysUntilExpiry === "number" && daysUntilExpiry < 0,
    isExpiringSoon: typeof daysUntilExpiry === "number" && daysUntilExpiry >= 0 && daysUntilExpiry <= 30
  };
}

function normalizeHtmlText(value) {
  const text = decodeHtmlEntities(String(value || ""))
    .replace(/\s+/g, " ")
    .trim();

  return text || null;
}

function decodeHtmlEntities(value) {
  return value
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", "\"")
    .replaceAll("&#39;", "'")
    .replaceAll("&nbsp;", " ");
}


function buildFindings({ analysis, finalResponse, httpProbe, httpsProbe, securityTxt }) {
  const findings = [];
  const httpsAvailable = httpsProbe.success;
  const httpRedirectsToHttps = httpProbe.success && httpProbe.result.finalUrl.startsWith("https://");
  const cookieAssessment = assessCookieHardening(analysis.cookies);

  if (!httpsAvailable) {
    findings.push(createFinding(
      "no_https",
      "critical",
      "HTTPS가 제공되지 않습니다",
      "공개 웹사이트는 기본적으로 HTTPS를 제공해야 합니다.",
      "HTTPS 응답을 확인하지 못했습니다.",
      { category: "direct" }
    ));
  }

  if (httpsAvailable && httpProbe.success && !httpRedirectsToHttps) {
    findings.push(createFinding(
      "no_https_redirect",
      "medium",
      "HTTP 진입점이 HTTPS로 강제되지 않습니다",
      "브라우저가 자동으로 업그레이드하지 못하는 환경에서는 평문 HTTP에 머물 수 있습니다.",
      "최종 HTTP URL: " + httpProbe.result.finalUrl,
      { category: "hardening" }
    ));
  }

  if (analysis.tls.applicable && !analysis.tls.isValid) {
    findings.push(createFinding(
      "invalid_tls_cert",
      "critical",
      "TLS 인증서 검증이 실패합니다",
      "브라우저 경고나 인증서 검증 실패가 발생할 수 있습니다.",
      finalResponse.tls?.authorizationError || "인증서 검증에 실패했습니다.",
      { category: "direct" }
    ));
  }

  if (analysis.tls.applicable && analysis.tls.isExpiringSoon) {
    findings.push(createFinding(
      "expiring_tls_cert",
      "low",
      "TLS 인증서가 곧 만료됩니다",
      "만료 전에 인증서 갱신 자동화와 운영 절차를 점검하는 편이 좋습니다.",
      String(analysis.tls.daysUntilExpiry) + "일 남음",
      { category: "hardening" }
    ));
  }

  if (httpsAvailable && !analysis.hsts.enabled) {
    findings.push(createFinding(
      "missing_hsts",
      "medium",
      "HSTS가 설정되어 있지 않습니다",
      "HTTPS를 사용하더라도 브라우저가 강제 HTTPS를 기억하지 못합니다.",
      "Strict-Transport-Security 헤더가 없습니다.",
      { category: "hardening" }
    ));
  }

  if (analysis.hsts.enabled && !analysis.hsts.strong) {
    findings.push(createFinding(
      "weak_hsts",
      "low",
      "HSTS max-age가 충분히 길지 않습니다",
      "짧은 max-age는 HTTPS 강제 효과를 약하게 만들 수 있습니다.",
      "max-age=" + analysis.hsts.maxAge,
      { category: "hardening" }
    ));
  }

  if (analysis.isHtml && !analysis.csp.enabled) {
    findings.push(createFinding(
      "missing_csp",
      "medium",
      "CSP가 설정되어 있지 않습니다",
      "CSP는 스크립트 주입과 악성 리소스 로딩 피해 범위를 줄이는 데 도움이 됩니다.",
      "Content-Security-Policy 헤더가 없습니다.",
      { category: "hardening" }
    ));
  }

  if (analysis.csp.enabled && analysis.csp.weak) {
    findings.push(createFinding(
      "weak_csp",
      "low",
      "CSP가 느슨하게 구성되어 있습니다",
      "unsafe-inline, unsafe-eval 또는 와일드카드는 CSP 보호 효과를 크게 약화시킬 수 있습니다.",
      normalizeHeaderText(finalResponse.headers["content-security-policy"]),
      { category: "hardening" }
    ));
  }

  const hasFrameProtection = Boolean(analysis.xFrameOptions)
    || /frame-ancestors/i.test(normalizeHeaderText(finalResponse.headers["content-security-policy"]));

  if (analysis.isHtml && !hasFrameProtection) {
    findings.push(createFinding(
      "missing_frame_protection",
      "medium",
      "클릭재킹 방어가 보이지 않습니다",
      "frame-ancestors 또는 X-Frame-Options가 없으면 클릭재킹 대응이 약해질 수 있습니다.",
      "X-Frame-Options와 CSP frame-ancestors가 모두 없습니다.",
      { category: "hardening" }
    ));
  }

  if (!/nosniff/i.test(normalizeHeaderText(finalResponse.headers["x-content-type-options"]))) {
    findings.push(createFinding(
      "missing_nosniff",
      "low",
      "X-Content-Type-Options: nosniff가 없습니다",
      "브라우저의 MIME sniffing을 제한하지 못합니다.",
      "X-Content-Type-Options 헤더가 없습니다.",
      { category: "hardening" }
    ));
  }

  if (!analysis.referrerPolicy.defined) {
    findings.push(createFinding(
      "missing_referrer_policy",
      "low",
      "Referrer-Policy가 없습니다",
      "외부로 전달되는 참조 정보 범위를 명시하지 않습니다.",
      "Referrer-Policy 헤더가 없습니다.",
      { category: "hardening" }
    ));
  } else if (analysis.referrerPolicy.weak) {
    findings.push(createFinding(
      "weak_referrer_policy",
      "low",
      "Referrer-Policy가 다소 느슨합니다",
      "더 보수적인 정책을 쓰면 외부로 전달되는 URL 정보를 줄일 수 있습니다.",
      analysis.referrerPolicy.value,
      { category: "hardening" }
    ));
  }

  if (!normalizeHeaderText(finalResponse.headers["permissions-policy"])) {
    findings.push(createFinding(
      "missing_permissions_policy",
      "low",
      "Permissions-Policy가 없습니다",
      "브라우저 기능 접근을 더 세밀하게 제한할 수 있습니다.",
      "Permissions-Policy 헤더가 없습니다.",
      { category: "maturity" }
    ));
  }

  if (cookieAssessment.insecureCookies.length) {
    findings.push(createFinding(
      "insecure_cookie",
      cookieAssessment.severity,
      "쿠키 보안 속성이 충분하지 않습니다",
      cookieAssessment.category === "direct"
        ? "세션 성격의 쿠키는 Secure와 HttpOnly를 빠뜨리면 탈취 위험이 커질 수 있습니다."
        : "쿠키 속성 보강이 필요하지만, 바로 치명 취약점으로 단정하기보다 용도와 노출 범위를 함께 보는 편이 좋습니다.",
      cookieAssessment.insecureCookies
        .map((cookie) => cookie.name + ": secure=" + cookie.secure + ", httpOnly=" + cookie.httpOnly + ", sameSite=" + (cookie.sameSite || "없음"))
        .join(" | "),
      { category: cookieAssessment.category }
    ));
  }

  if (analysis.cors.wildcardWithCredentials || analysis.cors.permissive) {
    findings.push(createFinding(
      "permissive_cors",
      analysis.cors.wildcardWithCredentials ? "high" : "medium",
      "CORS 정책이 과하게 열려 있을 수 있습니다",
      analysis.cors.wildcardWithCredentials
        ? "Credentials와 wildcard를 함께 허용하면 교차 출처 요청 위험이 커질 수 있습니다."
        : "필요한 출처만 허용하는 편이 안전합니다.",
      "Access-Control-Allow-Origin=" + normalizeHeaderText(finalResponse.headers["access-control-allow-origin"]) + ", Access-Control-Allow-Credentials=" + normalizeHeaderText(finalResponse.headers["access-control-allow-credentials"]),
      { category: analysis.cors.wildcardWithCredentials ? "direct" : "hardening" }
    ));
  }

  if (analysis.exposure.verbose) {
    findings.push(createFinding(
      "stack_header_exposed",
      "low",
      "기술 스택 정보가 노출됩니다",
      "버전과 프레임워크 단서가 공격자에게 유용한 힌트가 될 수 있습니다.",
      "Server=" + (analysis.exposure.server || "없음") + ", X-Powered-By=" + (analysis.exposure.poweredBy || "없음"),
      { category: "maturity" }
    ));
  }

  if (analysis.htmlSignals.mixedContentCount > 0) {
    findings.push(createFinding(
      "mixed_content",
      "high",
      "HTTPS 페이지에 혼합 콘텐츠가 보입니다",
      "HTTP 리소스가 섞이면 경고나 변조 위험이 생길 수 있습니다.",
      "HTTP 리소스 참조 " + analysis.htmlSignals.mixedContentCount + "개",
      { category: "direct" }
    ));
  }

  if (analysis.htmlSignals.insecureLoginFormCount > 0) {
    findings.push(createFinding(
      "insecure_login_form",
      "high",
      "로그인 폼 전송 방식이 안전하지 않을 수 있습니다",
      "비밀번호 전송은 POST와 HTTPS 조합으로 제한하는 편이 좋습니다.",
      "전달되는 비밀번호 폼 " + analysis.htmlSignals.insecureLoginFormCount + "개",
      { category: "direct" }
    ));
  }

  if (!analysis.securityTxt.available) {
    findings.push(createFinding(
      "missing_security_txt",
      "low",
      "security.txt가 공개되어 있지 않습니다",
      "외부 제보자와 파트너가 책임 있게 연락할 수 있는 채널을 보여주면 대응 흐름이 좋아집니다.",
      "확인 위치: " + securityTxt.scannedUrl,
      { category: "maturity" }
    ));
  } else if (!analysis.securityTxt.hasContact || !analysis.securityTxt.hasExpires) {
    findings.push(createFinding(
      "incomplete_security_txt",
      "low",
      "security.txt 정보가 충분하지 않습니다",
      "Contact와 Expires가 없으면 제보 채널과 운영 기준이 흐려질 수 있습니다.",
      "contact=" + (securityTxt.contact || "없음") + ", expires=" + (securityTxt.expires || "없음"),
      { category: "maturity" }
    ));
  } else if (analysis.securityTxt.isExpired) {
    findings.push(createFinding(
      "stale_security_txt",
      "low",
      "security.txt가 만료되었습니다",
      "만료된 security.txt는 현재도 유효한 제보 채널인지 판단하기 어렵게 만듭니다.",
      "expires=" + securityTxt.expires,
      { category: "maturity" }
    ));
  }

  return findings;
}

function createFinding(id, severity, title, summary, evidence, metadata = {}) {
  return {
    id,
    category: metadata.category || "hardening",
    severity,
    title,
    summary,
    evidence
  };
}

function sortFindings(findings) {
  return [...findings].sort((left, right) => {
    const categoryDiff = (FINDING_CATEGORY_ORDER[left.category] ?? 99) - (FINDING_CATEGORY_ORDER[right.category] ?? 99);
    if (categoryDiff !== 0) {
      return categoryDiff;
    }

    const severityDiff = SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity];
    if (severityDiff !== 0) {
      return severityDiff;
    }

    return left.title.localeCompare(right.title, "ko");
  });
}

function buildChecks({ analysis, findings, finalResponse, httpProbe, httpsProbe, securityTxt }) {
  const findingIds = new Set(findings.map((finding) => finding.id));
  const httpsAvailable = httpsProbe.success;
  const httpRedirectsToHttps = httpProbe.success && httpProbe.result.finalUrl.startsWith("https://");
  const hasFrameProtection = Boolean(analysis.xFrameOptions)
    || /frame-ancestors/i.test(normalizeHeaderText(finalResponse.headers["content-security-policy"]));
  const cookieAssessment = assessCookieHardening(analysis.cookies);

  return [
    makeCheck("https_support", "HTTPS 지원", 16, httpsAvailable ? "pass" : "fail", httpsAvailable ? "HTTPS 응답 확인됨" : "HTTPS 응답 없음"),
    makeCheck("https_redirect", "HTTP -> HTTPS 리다이렉트", 6, !httpsAvailable ? "na" : httpProbe.success ? (httpRedirectsToHttps ? "pass" : "warn") : "warn", httpProbe.success ? httpProbe.result.finalUrl : "HTTP 응답은 확인하지 못했습니다."),
    makeCheck("tls_validity", "TLS 인증서 상태", 10, !analysis.tls.applicable ? "na" : !analysis.tls.isValid ? "fail" : analysis.tls.hasTrustChainWarning || analysis.tls.isExpiringSoon ? "warn" : "pass", analysis.tls.applicable ? (finalResponse.tls?.authorizationError || "정상") + (analysis.tls.daysUntilExpiry != null ? ", " + analysis.tls.daysUntilExpiry + "일 후 만료" : "") : "HTTPS 미적용"),
    makeCheck("hsts", "HSTS", 8, !httpsAvailable ? "na" : !analysis.hsts.enabled ? "warn" : analysis.hsts.strong ? "pass" : "warn", !httpsAvailable ? "HTTPS 미적용" : analysis.hsts.enabled ? "max-age=" + analysis.hsts.maxAge : "헤더 없음"),
    makeCheck("csp", "Content-Security-Policy", 10, !analysis.isHtml ? "na" : !analysis.csp.enabled ? "warn" : analysis.csp.weak ? "warn" : "pass", analysis.isHtml ? (normalizeHeaderText(finalResponse.headers["content-security-policy"]) || "헤더 없음") : "HTML 응답 아님"),
    makeCheck("frame_protection", "클릭재킹 방어", 7, !analysis.isHtml ? "na" : hasFrameProtection ? "pass" : "warn", analysis.isHtml ? (hasFrameProtection ? normalizeHeaderText(finalResponse.headers["x-frame-options"]) || "CSP frame-ancestors 확인됨" : "없음") : "HTML 응답 아님"),
    makeCheck("nosniff", "nosniff", 3, findingIds.has("missing_nosniff") ? "warn" : "pass", normalizeHeaderText(finalResponse.headers["x-content-type-options"]) || "헤더 없음"),
    makeCheck("referrer_policy", "Referrer-Policy", 3, !analysis.referrerPolicy.defined ? "warn" : analysis.referrerPolicy.weak ? "warn" : "pass", analysis.referrerPolicy.value || "헤더 없음"),
    makeCheck("permissions_policy", "Permissions-Policy", 1, normalizeHeaderText(finalResponse.headers["permissions-policy"]) ? "pass" : "warn", normalizeHeaderText(finalResponse.headers["permissions-policy"]) || "헤더 없음"),
    makeCheck("cookie_hardening", "쿠키 보안 속성", 8, cookieAssessment.status, analysis.cookies.length ? "보완 필요한 쿠키 " + cookieAssessment.insecureCookies.length + "/" + analysis.cookies.length + "개" : "Set-Cookie 헤더 없음"),
    makeCheck("cors", "CORS 구성", 5, !analysis.cors.configured ? "na" : analysis.cors.wildcardWithCredentials ? "fail" : analysis.cors.permissive ? "warn" : "pass", analysis.cors.configured ? "origin=" + normalizeHeaderText(finalResponse.headers["access-control-allow-origin"]) : "CORS 헤더 없음"),
    makeCheck("stack_exposure", "기술 스택 노출", 1, analysis.exposure.verbose ? "warn" : "pass", "Server=" + (analysis.exposure.server || "없음") + ", X-Powered-By=" + (analysis.exposure.poweredBy || "없음")),
    makeCheck("mixed_content", "혼합 콘텐츠", 7, !analysis.isHtml ? "na" : analysis.htmlSignals.mixedContentCount > 0 ? "fail" : "pass", analysis.isHtml ? "안전하지 않은 참조 " + analysis.htmlSignals.mixedContentCount + "개" : "HTML 응답 아님"),
    makeCheck("login_form_transport", "로그인 폼 전송 안전성", 6, !analysis.isHtml ? "na" : analysis.htmlSignals.insecureLoginFormCount > 0 ? "fail" : "pass", analysis.isHtml ? "의심되는 비밀번호 폼 " + analysis.htmlSignals.insecureLoginFormCount + "개" : "HTML 응답 아님"),
    makeCheck("security_txt", "security.txt", 1, !analysis.securityTxt.available ? "warn" : analysis.securityTxt.isExpired ? "warn" : (!analysis.securityTxt.hasContact || !analysis.securityTxt.hasExpires) ? "warn" : "pass", !analysis.securityTxt.available ? "확인 위치 " + securityTxt.scannedUrl : "contact=" + (securityTxt.contact || "없음") + ", expires=" + (securityTxt.expires || "없음"))
  ];
}
function makeCheck(id, label, weight, status, detail) {
  return { id, label, weight, status, detail };
}


function scoreChecks(checks) {
  let earned = 0;
  let possible = 0;

  for (const check of checks) {
    if (check.status === "na") {
      continue;
    }

    possible += check.weight;

    if (check.status === "pass") {
      earned += check.weight;
    } else if (check.status === "warn") {
      earned += check.weight * WARN_CREDIT_RATIO;
    }
  }

  const value = possible ? Math.round((earned / possible) * 100) : 0;

  return {
    value,
    grade: gradeForScore(value),
    riskLevel: riskLevelForScore(value),
    applicableWeight: possible
  };
}
function gradeForScore(score) {
  if (score >= 95) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function riskLevelForScore(score) {
  if (score >= 90) return "Low";
  if (score >= 75) return "Moderate";
  if (score >= 60) return "High";
  return "Critical";
}

function applyScoreGuardrails(baseScore, categoryCounts) {
  if (categoryCounts.directCritical > 0) {
    return Math.min(baseScore, 49);
  }

  if (categoryCounts.directHigh > 0) {
    return Math.min(baseScore, 74);
  }

  if (categoryCounts.directMedium > 0) {
    return Math.min(baseScore, 79);
  }

  return baseScore;
}


function buildSummary({ checks, findings, httpProbe, httpsProbe, score }) {
  const counts = {
    critical: findings.filter((finding) => finding.severity === "critical").length,
    high: findings.filter((finding) => finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    total: findings.length,
    redirects: Math.max(
      httpProbe.success ? httpProbe.result.redirectChain.length - 1 : 0,
      httpsProbe.success ? httpsProbe.result.redirectChain.length - 1 : 0
    )
  };

  const categoryCounts = {
    direct: findings.filter((finding) => finding.category === "direct").length,
    hardening: findings.filter((finding) => finding.category === "hardening").length,
    maturity: findings.filter((finding) => finding.category === "maturity").length,
    directCritical: findings.filter((finding) => finding.category === "direct" && finding.severity === "critical").length,
    directHigh: findings.filter((finding) => finding.category === "direct" && finding.severity === "high").length,
    directMedium: findings.filter((finding) => finding.category === "direct" && finding.severity === "medium").length,
    hardeningHigh: findings.filter((finding) => finding.category === "hardening" && finding.severity === "high").length,
    hardeningMedium: findings.filter((finding) => finding.category === "hardening" && finding.severity === "medium").length
  };

  const adjustedScore = applyScoreGuardrails(score.value, categoryCounts);
  const adjustedGrade = gradeForScore(adjustedScore);
  let riskLevel = score.riskLevel;

  if (categoryCounts.directCritical > 0) {
    riskLevel = "Critical";
  } else if (categoryCounts.directHigh > 0) {
    riskLevel = "High";
  } else if (categoryCounts.directMedium > 0 || categoryCounts.hardeningHigh > 0 || categoryCounts.hardeningMedium >= 2) {
    riskLevel = "Moderate";
  } else if (riskLevel === "Critical" || riskLevel === "High") {
    riskLevel = "Moderate";
  }

  const headline = findings.length
    ? "가장 먼저 볼 문제: " + findings[0].title
    : "공개적으로 확인 가능한 핵심 보안 항목은 대체로 잘 갖춰져 있습니다.";

  return {
    score: adjustedScore,
    grade: adjustedGrade,
    riskLevel,
    headline,
    counts,
    categoryCounts,
    passes: checks.filter((check) => check.status === "pass").length,
    warnings: checks.filter((check) => check.status === "warn").length,
    failures: checks.filter((check) => check.status === "fail").length
  };
}

export const __internals = {
  analyzeSecurityTxt,
  analyzeCors,
  analyzeCsp,
  analyzeExposure,
  analyzeHsts,
  analyzeReferrerPolicy,
  assessCookieHardening,
  assertResolvedSocketAddress,
  buildChecks,
  buildFindings,
  buildSummary,
  createPinnedLookup,
  dedupeResolvedEntries,
  extractHtmlSignals,
  extractPageProfile,
  inspectHtmlDocument,
  isBlockedHostname,
  isPrivateIp,
  normalizeIpForComparison,
  normalizeInputUrl,
  parseCookies,
  requestOnce,
  resolvePublicTarget,
  scoreChecks,
  sortFindings
};
