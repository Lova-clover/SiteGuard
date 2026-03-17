import http from "node:http";
import https from "node:https";
import { lookup } from "node:dns/promises";
import net from "node:net";

import { attachRemediation } from "./remediation.js";

const MAX_REDIRECTS = 6;
const MAX_BODY_BYTES = 262_144;
const REQUEST_TIMEOUT_MS = 8_000;
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
  await assertPublicTarget(inputUrl);

  const targets = buildProtocolTargets(inputUrl);
  const [httpProbe, httpsProbe] = await Promise.all([
    attemptProbe(targets.http, "http"),
    attemptProbe(targets.https, "https")
  ]);

  const primary = choosePrimaryProbe(httpProbe, httpsProbe);
  const finalResponse = primary.result.finalResponse;
  const cookies = parseCookies(finalResponse.headers["set-cookie"]);
  const htmlSignals = extractHtmlSignals(finalResponse.body, primary.result.finalUrl, finalResponse.contentType);

  const analysis = {
    cookies,
    csp: analyzeCsp(finalResponse.headers["content-security-policy"]),
    cors: analyzeCors(finalResponse.headers),
    exposure: analyzeExposure(finalResponse.headers),
    hsts: analyzeHsts(finalResponse.headers["strict-transport-security"]),
    htmlSignals,
    isHtml: htmlSignals.isHtml,
    referrerPolicy: analyzeReferrerPolicy(finalResponse.headers["referrer-policy"]),
    tls: analyzeTls(primary.protocol === "https" ? finalResponse.tls : null),
    xFrameOptions: normalizeHeaderText(finalResponse.headers["x-frame-options"])
  };

  const findings = attachRemediation(
    sortFindings(buildFindings({
      analysis,
      finalResponse,
      httpProbe,
      httpsProbe
    }))
  );

  const checks = buildChecks({
    analysis,
    findings,
    finalResponse,
    httpProbe,
    httpsProbe
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
      tls: primary.protocol === "https" ? finalResponse.tls : null,
      cookies,
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
    await assertPublicTarget(currentUrl);

    const response = await requestOnce(currentUrl);
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

function requestOnce(url) {
  const startedAt = Date.now();
  const client = url.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    const request = client.request({
      hostname: url.hostname,
      port: url.port || undefined,
      path: `${url.pathname || "/"}${url.search || ""}`,
      method: "GET",
      headers: {
        Accept: "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "identity",
        Connection: "close",
        "User-Agent": "SiteGuard/1.0 (+https://siteguard.local/passive-public-security-posture-scan)"
      },
      rejectUnauthorized: false
    }, (response) => {
      const headers = normalizeHeaders(response.headers);
      const contentType = normalizeHeaderText(headers["content-type"]);
      const shouldCollectBody = isTextualContentType(contentType);
      const chunks = [];
      let totalBytes = 0;

      response.on("data", (chunk) => {
        if (!shouldCollectBody || totalBytes >= MAX_BODY_BYTES) {
          return;
        }

        const remaining = MAX_BODY_BYTES - totalBytes;
        const nextChunk = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
        chunks.push(nextChunk);
        totalBytes += nextChunk.length;
      });

      response.on("end", () => {
        const body = shouldCollectBody ? Buffer.concat(chunks).toString("utf8") : "";
        resolve({
          body,
          contentType,
          elapsedMs: Date.now() - startedAt,
          headers,
          statusCode: response.statusCode || 0,
          tls: buildTlsSnapshot(response.socket, url.protocol)
        });
      });
    });

    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy(new ScanError("요청 시간이 초과되었습니다.", {
        code: "REQUEST_TIMEOUT",
        statusCode: 504
      }));
    });

    request.on("error", (error) => {
      reject(normalizeRequestError(error));
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
  const hostname = url.hostname.toLowerCase();

  if (isBlockedHostname(hostname)) {
    throw new ScanError("사설 또는 내부 호스트는 검사할 수 없습니다.", {
      code: "PRIVATE_HOST_BLOCKED",
      statusCode: 400
    });
  }

  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new ScanError("사설 또는 예약된 IP 주소는 검사할 수 없습니다.", {
        code: "PRIVATE_IP_BLOCKED",
        statusCode: 400
      });
    }
    return;
  }

  let resolved;

  try {
    resolved = await lookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw normalizeRequestError(error);
  }

  if (!resolved.length) {
    throw new ScanError("도메인을 확인할 수 없습니다.", {
      code: "DNS_LOOKUP_EMPTY",
      statusCode: 404
    });
  }

  for (const entry of resolved) {
    if (isPrivateIp(entry.address)) {
      throw new ScanError("사설 또는 예약된 IP로 해석되는 도메인은 검사할 수 없습니다.", {
        code: "PRIVATE_DNS_TARGET_BLOCKED",
        statusCode: 400
      });
    }
  }
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

function analyzeCors(headers) {
  const origin = normalizeHeaderText(headers["access-control-allow-origin"]);
  const credentials = normalizeHeaderText(headers["access-control-allow-credentials"]).toLowerCase();

  if (!origin) {
    return {
      configured: false,
      permissive: false,
      wildcardWithCredentials: false
    };
  }

  return {
    configured: true,
    permissive: origin === "*",
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

function extractHtmlSignals(body, finalUrl, contentType) {
  const isHtml = contentType.startsWith("text/html") || /<html[\s>]/i.test(body) || /<!doctype html/i.test(body);

  if (!isHtml || !body) {
    return {
      insecureLoginFormCount: 0,
      isHtml: false,
      mixedContentCount: 0
    };
  }

  const mixedMatches = body.match(/\b(?:src|href|action)=["']http:\/\//gi) || [];
  const finalUrlObject = new URL(finalUrl);
  let insecureLoginFormCount = 0;
  const forms = body.match(/<form\b[\s\S]*?<\/form>/gi) || [];

  for (const form of forms) {
    if (!/type=["']password["']/i.test(form)) {
      continue;
    }

    const methodMatch = form.match(/\bmethod=["']([^"']+)["']/i);
    const actionMatch = form.match(/\baction=["']([^"']+)["']/i);
    const method = (methodMatch?.[1] || "get").toLowerCase();
    const action = actionMatch?.[1];

    if (method === "get") {
      insecureLoginFormCount += 1;
      continue;
    }

    if (action) {
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

  return {
    insecureLoginFormCount,
    isHtml: true,
    mixedContentCount: finalUrlObject.protocol === "https:" ? mixedMatches.length : 0
  };
}

function buildFindings({ analysis, finalResponse, httpProbe, httpsProbe }) {
  const findings = [];
  const httpsAvailable = httpsProbe.success;
  const httpRedirectsToHttps = httpProbe.success && httpProbe.result.finalUrl.startsWith("https://");

  if (!httpsAvailable) {
    findings.push(createFinding(
      "no_https",
      "critical",
      "HTTPS가 제공되지 않습니다",
      "공개 웹사이트는 기본적으로 HTTPS를 제공해야 합니다.",
      "https probe failed"
    ));
  }

  if (httpProbe.success && !httpRedirectsToHttps) {
    findings.push(createFinding(
      "no_https_redirect",
      "high",
      "HTTP 진입점이 HTTPS로 강제되지 않습니다",
      "사용자가 평문 HTTP에 머물 수 있습니다.",
      `final HTTP URL: ${httpProbe.result.finalUrl}`
    ));
  }

  if (analysis.tls.applicable && !analysis.tls.isValid) {
    findings.push(createFinding(
      "invalid_tls_cert",
      "critical",
      "TLS 인증서가 신뢰되지 않습니다",
      "브라우저 경고 또는 인증서 검증 실패가 발생할 수 있습니다.",
      finalResponse.tls?.authorizationError || "certificate validation failed"
    ));
  }

  if (analysis.tls.applicable && analysis.tls.isExpiringSoon) {
    findings.push(createFinding(
      "expiring_tls_cert",
      "medium",
      "TLS 인증서가 곧 만료됩니다",
      "만료 전에 갱신 자동화를 점검하는 것이 좋습니다.",
      `${analysis.tls.daysUntilExpiry}일 남음`
    ));
  }

  if (httpsAvailable && !analysis.hsts.enabled) {
    findings.push(createFinding(
      "missing_hsts",
      "high",
      "HSTS가 설정되어 있지 않습니다",
      "브라우저가 HTTPS 강제를 기억하지 못합니다.",
      "Strict-Transport-Security header missing"
    ));
  }

  if (analysis.hsts.enabled && !analysis.hsts.strong) {
    findings.push(createFinding(
      "weak_hsts",
      "medium",
      "HSTS max-age가 충분히 길지 않습니다",
      "짧은 max-age는 강제 HTTPS 효과를 약하게 만듭니다.",
      `max-age=${analysis.hsts.maxAge}`
    ));
  }

  if (analysis.isHtml && !analysis.csp.enabled) {
    findings.push(createFinding(
      "missing_csp",
      "high",
      "CSP가 설정되어 있지 않습니다",
      "XSS와 악성 리소스 로딩 피해를 줄일 방어선이 없습니다.",
      "Content-Security-Policy header missing"
    ));
  }

  if (analysis.csp.enabled && analysis.csp.weak) {
    findings.push(createFinding(
      "weak_csp",
      "medium",
      "CSP가 느슨하게 구성되어 있습니다",
      "unsafe-inline, unsafe-eval 또는 와일드카드가 포함되어 있습니다.",
      normalizeHeaderText(finalResponse.headers["content-security-policy"])
    ));
  }

  const hasFrameProtection = Boolean(analysis.xFrameOptions) || /frame-ancestors/i.test(normalizeHeaderText(finalResponse.headers["content-security-policy"]));
  if (analysis.isHtml && !hasFrameProtection) {
    findings.push(createFinding(
      "missing_frame_protection",
      "medium",
      "클릭재킹 방어가 보이지 않습니다",
      "X-Frame-Options 또는 frame-ancestors가 필요합니다.",
      "No X-Frame-Options and no CSP frame-ancestors directive"
    ));
  }

  if (!/nosniff/i.test(normalizeHeaderText(finalResponse.headers["x-content-type-options"]))) {
    findings.push(createFinding(
      "missing_nosniff",
      "medium",
      "X-Content-Type-Options: nosniff가 없습니다",
      "브라우저의 MIME sniffing을 제한하지 못합니다.",
      "X-Content-Type-Options header missing"
    ));
  }

  if (!analysis.referrerPolicy.defined) {
    findings.push(createFinding(
      "missing_referrer_policy",
      "medium",
      "Referrer-Policy가 없습니다",
      "외부 사이트로 전달되는 참조 정보 범위를 명시하지 않습니다.",
      "Referrer-Policy header missing"
    ));
  } else if (analysis.referrerPolicy.weak) {
    findings.push(createFinding(
      "weak_referrer_policy",
      "low",
      "Referrer-Policy가 다소 느슨합니다",
      "더 보수적인 정책으로 정보 노출을 줄일 수 있습니다.",
      analysis.referrerPolicy.value
    ));
  }

  if (!normalizeHeaderText(finalResponse.headers["permissions-policy"])) {
    findings.push(createFinding(
      "missing_permissions_policy",
      "low",
      "Permissions-Policy가 없습니다",
      "브라우저 기능 접근을 더 세밀하게 제한할 수 있습니다.",
      "Permissions-Policy header missing"
    ));
  }

  const insecureCookies = analysis.cookies.filter((cookie) => !cookie.secure || !cookie.httpOnly || !cookie.sameSite);
  if (insecureCookies.length) {
    findings.push(createFinding(
      "insecure_cookie",
      "high",
      "쿠키 보안 속성이 충분하지 않습니다",
      "민감한 쿠키는 Secure, HttpOnly, SameSite를 함께 검토해야 합니다.",
      insecureCookies.map((cookie) => `${cookie.name}: secure=${cookie.secure}, httpOnly=${cookie.httpOnly}, sameSite=${cookie.sameSite || "missing"}`).join(" | ")
    ));
  }

  if (analysis.cors.wildcardWithCredentials || analysis.cors.permissive) {
    findings.push(createFinding(
      "permissive_cors",
      analysis.cors.wildcardWithCredentials ? "high" : "medium",
      "CORS 정책이 과하게 열려 있을 수 있습니다",
      "필요한 출처만 허용하는 편이 안전합니다.",
      `Access-Control-Allow-Origin=${normalizeHeaderText(finalResponse.headers["access-control-allow-origin"])}, Access-Control-Allow-Credentials=${normalizeHeaderText(finalResponse.headers["access-control-allow-credentials"])}`
    ));
  }

  if (analysis.exposure.verbose) {
    findings.push(createFinding(
      "stack_header_exposed",
      "low",
      "기술 스택 정보가 노출됩니다",
      "버전과 프레임워크 단서는 공격자에게 유용한 힌트가 될 수 있습니다.",
      `Server=${analysis.exposure.server || "none"}, X-Powered-By=${analysis.exposure.poweredBy || "none"}`
    ));
  }

  if (analysis.htmlSignals.mixedContentCount > 0) {
    findings.push(createFinding(
      "mixed_content",
      "high",
      "HTTPS 페이지에 혼합 콘텐츠가 보입니다",
      "HTTP 리소스가 포함되면 경고나 변조 위험이 생길 수 있습니다.",
      `http resource references=${analysis.htmlSignals.mixedContentCount}`
    ));
  }

  if (analysis.htmlSignals.insecureLoginFormCount > 0) {
    findings.push(createFinding(
      "insecure_login_form",
      "high",
      "로그인 폼 전송 방식이 안전하지 않을 수 있습니다",
      "비밀번호는 POST + HTTPS 조합으로만 전송되어야 합니다.",
      `suspicious password forms=${analysis.htmlSignals.insecureLoginFormCount}`
    ));
  }

  return findings;
}

function createFinding(id, severity, title, summary, evidence) {
  return {
    id,
    severity,
    title,
    summary,
    evidence
  };
}

function sortFindings(findings) {
  return [...findings].sort((left, right) => {
    const severityDiff = SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity];
    if (severityDiff !== 0) {
      return severityDiff;
    }
    return left.title.localeCompare(right.title, "ko");
  });
}

function buildChecks({ analysis, findings, finalResponse, httpProbe, httpsProbe }) {
  const findingIds = new Set(findings.map((finding) => finding.id));
  const httpsAvailable = httpsProbe.success;
  const httpRedirectsToHttps = httpProbe.success && httpProbe.result.finalUrl.startsWith("https://");
  const hasFrameProtection = Boolean(analysis.xFrameOptions) || /frame-ancestors/i.test(normalizeHeaderText(finalResponse.headers["content-security-policy"]));
  const insecureCookies = analysis.cookies.filter((cookie) => !cookie.secure || !cookie.httpOnly || !cookie.sameSite);

  return [
    makeCheck("https_support", "HTTPS 지원", 16, httpsAvailable ? "pass" : "fail", httpsAvailable ? "HTTPS endpoint reachable" : "HTTPS endpoint unavailable"),
    makeCheck("https_redirect", "HTTP -> HTTPS 리다이렉트", 8, httpProbe.success ? (httpRedirectsToHttps ? "pass" : "fail") : "warn", httpProbe.success ? httpProbe.result.finalUrl : "HTTP endpoint not reachable"),
    makeCheck("tls_validity", "TLS 인증서 상태", 10, !analysis.tls.applicable ? "na" : !analysis.tls.isValid ? "fail" : analysis.tls.hasTrustChainWarning || analysis.tls.isExpiringSoon ? "warn" : "pass", analysis.tls.applicable ? `${finalResponse.tls?.authorizationError || "valid"}${analysis.tls.daysUntilExpiry != null ? `, expires in ${analysis.tls.daysUntilExpiry} days` : ""}` : "HTTPS not available"),
    makeCheck("hsts", "HSTS", 10, !httpsAvailable ? "na" : !analysis.hsts.enabled ? "fail" : analysis.hsts.strong ? "pass" : "warn", !httpsAvailable ? "HTTPS not available" : analysis.hsts.enabled ? `max-age=${analysis.hsts.maxAge}` : "header missing"),
    makeCheck("csp", "Content-Security-Policy", 12, !analysis.isHtml ? "na" : !analysis.csp.enabled ? "fail" : analysis.csp.weak ? "warn" : "pass", analysis.isHtml ? (normalizeHeaderText(finalResponse.headers["content-security-policy"]) || "header missing") : "Non-HTML response"),
    makeCheck("frame_protection", "클릭재킹 방어", 8, !analysis.isHtml ? "na" : hasFrameProtection ? "pass" : "fail", analysis.isHtml ? (hasFrameProtection ? normalizeHeaderText(finalResponse.headers["x-frame-options"]) || "CSP frame-ancestors present" : "missing") : "Non-HTML response"),
    makeCheck("nosniff", "nosniff", 6, findingIds.has("missing_nosniff") ? "fail" : "pass", normalizeHeaderText(finalResponse.headers["x-content-type-options"]) || "header missing"),
    makeCheck("referrer_policy", "Referrer-Policy", 5, !analysis.referrerPolicy.defined ? "fail" : analysis.referrerPolicy.weak ? "warn" : "pass", analysis.referrerPolicy.value || "header missing"),
    makeCheck("permissions_policy", "Permissions-Policy", 4, normalizeHeaderText(finalResponse.headers["permissions-policy"]) ? "pass" : "fail", normalizeHeaderText(finalResponse.headers["permissions-policy"]) || "header missing"),
    makeCheck("cookie_hardening", "쿠키 보안 속성", 10, analysis.cookies.length === 0 ? "na" : insecureCookies.length ? "fail" : "pass", analysis.cookies.length ? `${insecureCookies.length}/${analysis.cookies.length} cookies need hardening` : "No set-cookie observed"),
    makeCheck("cors", "CORS 구성", 5, !analysis.cors.configured ? "na" : analysis.cors.wildcardWithCredentials ? "fail" : analysis.cors.permissive ? "warn" : "pass", analysis.cors.configured ? `origin=${normalizeHeaderText(finalResponse.headers["access-control-allow-origin"])}` : "No CORS headers observed"),
    makeCheck("stack_exposure", "기술 스택 노출", 3, analysis.exposure.verbose ? "warn" : "pass", `Server=${analysis.exposure.server || "none"}, X-Powered-By=${analysis.exposure.poweredBy || "none"}`),
    makeCheck("mixed_content", "혼합 콘텐츠", 2, !analysis.isHtml ? "na" : analysis.htmlSignals.mixedContentCount > 0 ? "fail" : "pass", analysis.isHtml ? `${analysis.htmlSignals.mixedContentCount} insecure references` : "Non-HTML response"),
    makeCheck("login_form_transport", "로그인 폼 전송 안전성", 1, !analysis.isHtml ? "na" : analysis.htmlSignals.insecureLoginFormCount > 0 ? "fail" : "pass", analysis.isHtml ? `${analysis.htmlSignals.insecureLoginFormCount} suspicious password forms` : "Non-HTML response")
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
      earned += check.weight * 0.5;
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

  const headline = findings.length
    ? `가장 먼저 볼 문제: ${findings[0].title}`
    : "공개적으로 확인 가능한 핵심 보안 구성이 안정적으로 보입니다.";

  return {
    score: score.value,
    grade: score.grade,
    riskLevel: counts.critical > 0 ? "Critical" : counts.high > 1 ? "High" : score.riskLevel,
    headline,
    counts,
    passes: checks.filter((check) => check.status === "pass").length,
    warnings: checks.filter((check) => check.status === "warn").length,
    failures: checks.filter((check) => check.status === "fail").length
  };
}

export const __internals = {
  analyzeCors,
  analyzeCsp,
  analyzeExposure,
  analyzeHsts,
  analyzeReferrerPolicy,
  extractHtmlSignals,
  isBlockedHostname,
  isPrivateIp,
  normalizeInputUrl,
  parseCookies,
  scoreChecks
};
