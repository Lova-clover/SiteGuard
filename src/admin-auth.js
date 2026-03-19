import { createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";

const ADMIN_SESSION_COOKIE = "siteguard_admin_session";
const VISITOR_COOKIE = "siteguard_visitor";
const ADMIN_SESSION_TTL_SEC = Number(process.env.ADMIN_SESSION_TTL_SEC || 60 * 60 * 24 * 14);

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");

  return Buffer.from(normalized, "base64").toString("utf8");
}

function getRequestHeader(request, name) {
  if (!request?.headers) {
    return "";
  }

  if (typeof request.headers.get === "function") {
    return String(request.headers.get(name) || "");
  }

  const lower = name.toLowerCase();
  const value = request.headers[lower];
  return Array.isArray(value) ? value.join(", ") : String(value || "");
}

export function parseCookieHeader(cookieHeader = "") {
  return Object.fromEntries(
    String(cookieHeader)
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const separator = part.indexOf("=");
        if (separator === -1) {
          return [part, ""];
        }

        const key = part.slice(0, separator).trim();
        const value = part.slice(separator + 1).trim();
        return [key, decodeURIComponent(value)];
      })
  );
}

export function getRequestCookies(request) {
  return parseCookieHeader(getRequestHeader(request, "cookie"));
}

export function isSecureRequestLike(request) {
  const forwardedProto = getRequestHeader(request, "x-forwarded-proto");
  if (forwardedProto) {
    return forwardedProto.split(",")[0].trim().toLowerCase() === "https";
  }

  if (typeof request?.socket?.encrypted === "boolean") {
    return request.socket.encrypted;
  }

  if (typeof request?.url === "string") {
    try {
      return new URL(request.url, "http://localhost").protocol === "https:";
    } catch {
      return false;
    }
  }

  return false;
}

export function serializeCookie(name, value, options = {}) {
  const attributes = [`${name}=${encodeURIComponent(value)}`];

  if (options.maxAge != null) {
    attributes.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
  }

  if (options.domain) {
    attributes.push(`Domain=${options.domain}`);
  }

  attributes.push(`Path=${options.path || "/"}`);

  if (options.httpOnly) {
    attributes.push("HttpOnly");
  }

  if (options.sameSite) {
    attributes.push(`SameSite=${options.sameSite}`);
  }

  if (options.secure) {
    attributes.push("Secure");
  }

  return attributes.join("; ");
}

function signValue(value, secret) {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

function hashForCompare(value) {
  return createHmac("sha256", "siteguard-admin-compare").update(value).digest();
}

function safeEqual(left, right) {
  const leftHash = hashForCompare(left);
  const rightHash = hashForCompare(right);
  return timingSafeEqual(leftHash, rightHash);
}

export function createPasswordHash(password, salt = randomBytes(16)) {
  const passwordValue = Buffer.from(String(password || ""), "utf8");
  const saltBuffer = Buffer.isBuffer(salt) ? salt : Buffer.from(String(salt || ""), "utf8");
  const derivedKey = scryptSync(passwordValue, saltBuffer, 64);
  return `scrypt$${saltBuffer.toString("hex")}$${derivedKey.toString("hex")}`;
}

function verifyPasswordHash(password, hash) {
  const [algorithm, saltHex, digestHex] = String(hash || "").split("$");

  if (algorithm !== "scrypt" || !saltHex || !digestHex) {
    return false;
  }

  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(digestHex, "hex");
  const actual = scryptSync(Buffer.from(String(password || ""), "utf8"), salt, expected.length);

  return timingSafeEqual(actual, expected);
}

function getAdminConfig() {
  const username = process.env.ADMIN_USERNAME || "";
  const password = process.env.ADMIN_PASSWORD || "";
  const passwordHash = process.env.ADMIN_PASSWORD_HASH || "";
  const sessionSecret = process.env.ADMIN_SESSION_SECRET || "";

  return {
    configured: Boolean(username && (password || passwordHash) && sessionSecret),
    password,
    passwordHash,
    sessionSecret,
    username
  };
}

export function isAdminConfigured() {
  return getAdminConfig().configured;
}

export function verifyAdminCredentials(username, password) {
  const config = getAdminConfig();

  if (!config.configured) {
    return false;
  }

  if (!safeEqual(String(username || ""), config.username)) {
    return false;
  }

  if (config.passwordHash) {
    return verifyPasswordHash(password, config.passwordHash);
  }

  return safeEqual(String(password || ""), config.password);
}

export function createAdminSessionCookie(request, username) {
  const { sessionSecret } = getAdminConfig();
  const payload = {
    exp: Date.now() + ADMIN_SESSION_TTL_SEC * 1000,
    nonce: randomUUID(),
    username
  };
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = signValue(encodedPayload, sessionSecret);

  return serializeCookie(ADMIN_SESSION_COOKIE, `${encodedPayload}.${signature}`, {
    httpOnly: true,
    maxAge: ADMIN_SESSION_TTL_SEC,
    path: "/",
    sameSite: "Strict",
    secure: isSecureRequestLike(request)
  });
}

export function clearAdminSessionCookie(request) {
  return serializeCookie(ADMIN_SESSION_COOKIE, "", {
    httpOnly: true,
    maxAge: 0,
    path: "/",
    sameSite: "Strict",
    secure: isSecureRequestLike(request)
  });
}

export function readAdminSession(request) {
  const config = getAdminConfig();

  if (!config.configured) {
    return null;
  }

  const token = getRequestCookies(request)[ADMIN_SESSION_COOKIE];

  if (!token) {
    return null;
  }

  const separator = token.lastIndexOf(".");
  if (separator === -1) {
    return null;
  }

  const encodedPayload = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  const expectedSignature = signValue(encodedPayload, config.sessionSecret);

  if (!safeEqual(signature, expectedSignature)) {
    return null;
  }

  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    if (!payload?.username || !payload?.exp || payload.exp < Date.now()) {
      return null;
    }

    if (!safeEqual(payload.username, config.username)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export function getVisitorCookie(request) {
  return getRequestCookies(request)[VISITOR_COOKIE] || "";
}

export function ensureVisitorCookie(request) {
  const current = getVisitorCookie(request);
  if (current) {
    return {
      created: false,
      setCookie: null,
      visitorId: current
    };
  }

  const visitorId = randomUUID();
  return {
    created: true,
    setCookie: serializeCookie(VISITOR_COOKIE, visitorId, {
      httpOnly: true,
      maxAge: 60 * 60 * 24 * 365,
      path: "/",
      sameSite: "Lax",
      secure: isSecureRequestLike(request)
    }),
    visitorId
  };
}

export const __adminInternals = {
  createPasswordHash,
  getAdminConfig,
  safeEqual,
  signValue,
  verifyPasswordHash
};
