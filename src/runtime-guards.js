export function createFixedWindowRateLimiter({ limit, windowMs, maxKeys = 5000 }) {
  const buckets = new Map();

  function prune(now) {
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) {
        buckets.delete(key);
      }
    }

    while (buckets.size > maxKeys) {
      const oldestKey = buckets.keys().next().value;
      buckets.delete(oldestKey);
    }
  }

  return {
    check(key, now = Date.now()) {
      prune(now);

      const bucket = buckets.get(key);

      if (!bucket || bucket.resetAt <= now) {
        const nextBucket = {
          count: 1,
          resetAt: now + windowMs
        };
        buckets.set(key, nextBucket);
        return {
          allowed: true,
          limit,
          remaining: Math.max(limit - nextBucket.count, 0),
          resetAt: nextBucket.resetAt
        };
      }

      if (bucket.count >= limit) {
        return {
          allowed: false,
          limit,
          remaining: 0,
          resetAt: bucket.resetAt
        };
      }

      bucket.count += 1;

      return {
        allowed: true,
        limit,
        remaining: Math.max(limit - bucket.count, 0),
        resetAt: bucket.resetAt
      };
    },
    clear() {
      buckets.clear();
    },
    size() {
      return buckets.size;
    }
  };
}

export function createConcurrencyGuard({ limit }) {
  let active = 0;

  return {
    enter() {
      if (active >= limit) {
        return false;
      }

      active += 1;
      return true;
    },
    leave() {
      active = Math.max(active - 1, 0);
    },
    size() {
      return active;
    }
  };
}

export function createTtlCache({ ttlMs, maxEntries = 500 }) {
  const entries = new Map();

  function prune(now) {
    for (const [key, entry] of entries) {
      if (entry.expiresAt <= now) {
        entries.delete(key);
      }
    }

    while (entries.size > maxEntries) {
      const oldestKey = entries.keys().next().value;
      entries.delete(oldestKey);
    }
  }

  return {
    get(key, now = Date.now()) {
      prune(now);
      const entry = entries.get(key);

      if (!entry) {
        return null;
      }

      return entry.value;
    },
    set(key, value, now = Date.now()) {
      prune(now);
      entries.delete(key);
      entries.set(key, {
        expiresAt: now + ttlMs,
        value
      });
    },
    clear() {
      entries.clear();
    },
    size() {
      return entries.size;
    }
  };
}

export function getClientIp(request) {
  const forwarded = request.headers["x-forwarded-for"];

  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }

  return request.socket.remoteAddress || "unknown";
}

export function isSecureRequest(request) {
  const forwardedProto = request.headers["x-forwarded-proto"];

  if (typeof forwardedProto === "string" && forwardedProto.trim()) {
    return forwardedProto.split(",")[0].trim().toLowerCase() === "https";
  }

  return Boolean(request.socket.encrypted);
}
