import { Redis } from "@upstash/redis";

const DEFAULT_TIME_ZONE = process.env.SITEGUARD_METRICS_TIMEZONE || "Asia/Seoul";
const DAILY_KEY_TTL_SEC = Number(process.env.SITEGUARD_METRICS_TTL_SEC || 60 * 60 * 24 * 120);
const RECENT_SCAN_LIMIT = Number(process.env.SITEGUARD_RECENT_SCAN_LIMIT || 20);
const TOP_DOMAIN_LIMIT = Number(process.env.SITEGUARD_TOP_DOMAIN_LIMIT || 5);

function formatDayKey(input, timeZone = DEFAULT_TIME_ZONE) {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    day: "2-digit",
    month: "2-digit",
    timeZone,
    year: "numeric"
  });
  const parts = Object.fromEntries(
    formatter.formatToParts(new Date(input)).map((part) => [part.type, part.value])
  );
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function buildDayWindow(days, now = Date.now(), timeZone = DEFAULT_TIME_ZONE) {
  return Array.from({ length: days }, (_, index) => {
    const date = new Date(now);
    date.setDate(date.getDate() - index);
    return formatDayKey(date, timeZone);
  }).reverse();
}

function normalizePath(pathname) {
  const value = String(pathname || "/").trim();
  if (!value.startsWith("/")) {
    return "/";
  }
  return value.slice(0, 120) || "/";
}

function normalizeHostname(hostname) {
  const value = String(hostname || "").trim().toLowerCase();
  return value.slice(0, 255);
}

function clampDuration(durationMs) {
  const value = Number(durationMs);
  if (!Number.isFinite(value) || value < 0) {
    return 0;
  }
  return Math.min(Math.round(value), 600_000);
}

function toInteger(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

function sumValues(values) {
  return values.reduce((total, value) => total + toInteger(value), 0);
}

function parseRecentEntry(entry) {
  if (typeof entry !== "string") {
    return null;
  }

  try {
    return JSON.parse(entry);
  } catch {
    return null;
  }
}

function normalizeTopDomainsResponse(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return [];
  }

  if (entries.every((entry) => entry && typeof entry === "object" && "member" in entry && "score" in entry)) {
    return entries.map((entry) => ({
      count: toInteger(entry.score),
      hostname: String(entry.member || "")
    }));
  }

  if (entries.every((entry) => Array.isArray(entry) && entry.length >= 2)) {
    return entries.map((entry) => ({
      count: toInteger(entry[1]),
      hostname: String(entry[0] || "")
    }));
  }

  const normalized = [];
  for (let index = 0; index < entries.length; index += 2) {
    const hostname = String(entries[index] || "");
    const count = toInteger(entries[index + 1]);
    if (hostname) {
      normalized.push({ count, hostname });
    }
  }

  return normalized;
}

function buildDailySeries(days, viewsByDay, scansByDay, uniqueByDay) {
  return days.map((day) => ({
    day,
    scans: toInteger(scansByDay[day]),
    uniqueVisitors: toInteger(uniqueByDay[day]),
    views: toInteger(viewsByDay[day])
  }));
}

function createRecentScanEntry(details, at = new Date()) {
  return {
    at: new Date(at).toISOString(),
    cached: Boolean(details.cached),
    durationMs: clampDuration(details.durationMs),
    errorCode: details.errorCode || null,
    hostname: normalizeHostname(details.hostname) || "(unknown)",
    ok: Boolean(details.ok),
    requestId: details.requestId || null,
    score: Number.isFinite(Number(details.score)) ? Number(details.score) : null
  };
}

class MemoryMetricsStore {
  constructor({ timeZone = DEFAULT_TIME_ZONE } = {}) {
    this.backend = "memory";
    this.timeZone = timeZone;
    this.state = {
      recentScans: [],
      scanCounts: {
        cachedTotal: 0,
        failedTotal: 0,
        freshTotal: 0,
        successfulTotal: 0,
        totalRequests: 0
      },
      scanCountsByDay: new Map(),
      topDomains: new Map(),
      uniqueVisitorsAll: new Set(),
      uniqueVisitorsByDay: new Map(),
      viewCounts: {
        total: 0
      },
      viewCountsByDay: new Map()
    };
  }

  recordVisit({ path = "/", visitorId, now = Date.now() }) {
    if (!visitorId) {
      return;
    }

    const day = formatDayKey(now, this.timeZone);
    const pathKey = normalizePath(path);

    this.state.viewCounts.total += 1;
    this.state.uniqueVisitorsAll.add(visitorId);

    if (!this.state.viewCountsByDay.has(day)) {
      this.state.viewCountsByDay.set(day, 0);
    }
    this.state.viewCountsByDay.set(day, this.state.viewCountsByDay.get(day) + 1);

    if (!this.state.uniqueVisitorsByDay.has(day)) {
      this.state.uniqueVisitorsByDay.set(day, new Set());
    }
    this.state.uniqueVisitorsByDay.get(day).add(visitorId);
    this.state.lastPath = pathKey;
  }

  recordScan(details) {
    const day = formatDayKey(details.now || Date.now(), this.timeZone);
    const hostname = normalizeHostname(details.hostname);
    const dayCounts = this.state.scanCountsByDay.get(day) || {
      cached: 0,
      failed: 0,
      fresh: 0,
      successful: 0,
      totalRequests: 0
    };

    this.state.scanCounts.totalRequests += 1;
    dayCounts.totalRequests += 1;

    if (details.ok) {
      this.state.scanCounts.successfulTotal += 1;
      dayCounts.successful += 1;

      if (details.cached) {
        this.state.scanCounts.cachedTotal += 1;
        dayCounts.cached += 1;
      } else {
        this.state.scanCounts.freshTotal += 1;
        dayCounts.fresh += 1;
      }
    } else {
      this.state.scanCounts.failedTotal += 1;
      dayCounts.failed += 1;
    }

    this.state.scanCountsByDay.set(day, dayCounts);

    if (hostname) {
      this.state.topDomains.set(hostname, (this.state.topDomains.get(hostname) || 0) + 1);
    }

    this.state.recentScans.unshift(createRecentScanEntry(details));
    this.state.recentScans = this.state.recentScans.slice(0, RECENT_SCAN_LIMIT);
  }

  async getSnapshot({ now = Date.now() } = {}) {
    const today = formatDayKey(now, this.timeZone);
    const days = buildDayWindow(7, now, this.timeZone);
    const last7VisitorIds = new Set();
    const viewsByDay = {};
    const scansByDay = {};
    const uniqueByDay = {};

    for (const day of days) {
      const visitors = this.state.uniqueVisitorsByDay.get(day) || new Set();
      const dayScanCounts = this.state.scanCountsByDay.get(day) || { totalRequests: 0 };
      const dayViews = this.state.viewCountsByDay.get(day) || 0;

      viewsByDay[day] = dayViews;
      scansByDay[day] = dayScanCounts.totalRequests || 0;
      uniqueByDay[day] = visitors.size;

      for (const visitorId of visitors) {
        last7VisitorIds.add(visitorId);
      }
    }

    const todayScanCounts = this.state.scanCountsByDay.get(today) || {};

    return {
      backend: this.backend,
      generatedAt: new Date(now).toISOString(),
      timeZone: this.timeZone,
      scans: {
        cachedTotal: this.state.scanCounts.cachedTotal,
        failedTotal: this.state.scanCounts.failedTotal,
        freshTotal: this.state.scanCounts.freshTotal,
        successfulTotal: this.state.scanCounts.successfulTotal,
        successRate: this.state.scanCounts.totalRequests
          ? Math.round((this.state.scanCounts.successfulTotal / this.state.scanCounts.totalRequests) * 1000) / 10
          : 0,
        todayRequests: toInteger(todayScanCounts.totalRequests),
        totalRequests: this.state.scanCounts.totalRequests,
        totalRequestsLast7Days: sumValues(Object.values(scansByDay))
      },
      series: buildDailySeries(days, viewsByDay, scansByDay, uniqueByDay),
      topDomains: [...this.state.topDomains.entries()]
        .sort((left, right) => right[1] - left[1])
        .slice(0, TOP_DOMAIN_LIMIT)
        .map(([hostname, count]) => ({ count, hostname })),
      visitors: {
        pageViewsLast7Days: sumValues(Object.values(viewsByDay)),
        pageViewsToday: toInteger(viewsByDay[today]),
        pageViewsTotal: this.state.viewCounts.total,
        uniqueLast7Days: last7VisitorIds.size,
        uniqueToday: toInteger(uniqueByDay[today]),
        uniqueTotal: this.state.uniqueVisitorsAll.size
      },
      recentScans: this.state.recentScans.slice(0, RECENT_SCAN_LIMIT)
    };
  }
}

class RedisMetricsStore {
  constructor(redis, { timeZone = DEFAULT_TIME_ZONE } = {}) {
    this.backend = "redis";
    this.redis = redis;
    this.timeZone = timeZone;
  }

  dailyKey(prefix, day) {
    return `siteguard:${prefix}:day:${day}`;
  }

  async expireDailyKeys(...keys) {
    await Promise.all(keys.map((key) => this.redis.expire(key, DAILY_KEY_TTL_SEC)));
  }

  async recordVisit({ path = "/", visitorId, now = Date.now() }) {
    if (!visitorId) {
      return;
    }

    const day = formatDayKey(now, this.timeZone);
    const pathKey = normalizePath(path);

    const totalViewsKey = "siteguard:visits:pageviews:total";
    const dayViewsKey = this.dailyKey("visits:pageviews", day);
    const visitorAllKey = "siteguard:visits:visitors:all";
    const visitorDayKey = this.dailyKey("visits:visitors", day);

    await Promise.all([
      this.redis.incr(totalViewsKey),
      this.redis.incr(dayViewsKey),
      this.redis.sadd(visitorAllKey, visitorId),
      this.redis.sadd(visitorDayKey, visitorId),
      this.redis.hincrby("siteguard:visits:paths", pathKey, 1)
    ]);

    await this.expireDailyKeys(dayViewsKey, visitorDayKey);
  }

  async recordScan(details) {
    const at = details.now || Date.now();
    const day = formatDayKey(at, this.timeZone);
    const hostname = normalizeHostname(details.hostname);
    const totalKey = "siteguard:scans:total";
    const dayKey = this.dailyKey("scans", day);
    const recentKey = "siteguard:scans:recent";
    const commands = [
      this.redis.incr(totalKey),
      this.redis.incr(dayKey),
      this.redis.lpush(recentKey, JSON.stringify(createRecentScanEntry(details, at))),
      this.redis.ltrim(recentKey, 0, RECENT_SCAN_LIMIT - 1)
    ];

    if (details.ok) {
      commands.push(
        this.redis.incr("siteguard:scans:successful:total"),
        this.redis.incr(this.dailyKey("scans:successful", day))
      );

      if (details.cached) {
        commands.push(
          this.redis.incr("siteguard:scans:cached:total"),
          this.redis.incr(this.dailyKey("scans:cached", day))
        );
      } else {
        commands.push(
          this.redis.incr("siteguard:scans:fresh:total"),
          this.redis.incr(this.dailyKey("scans:fresh", day))
        );
      }
    } else {
      commands.push(
        this.redis.incr("siteguard:scans:failed:total"),
        this.redis.incr(this.dailyKey("scans:failed", day))
      );
    }

    if (hostname) {
      commands.push(this.redis.zincrby("siteguard:scans:domains", 1, hostname));
    }

    await Promise.all(commands);
    await this.expireDailyKeys(
      dayKey,
      this.dailyKey("scans:successful", day),
      this.dailyKey("scans:cached", day),
      this.dailyKey("scans:fresh", day),
      this.dailyKey("scans:failed", day)
    );
  }

  async getSnapshot({ now = Date.now() } = {}) {
    const today = formatDayKey(now, this.timeZone);
    const days = buildDayWindow(7, now, this.timeZone);
    const [
      totalUniqueVisitors,
      uniqueTodayMembers,
      last7UniqueMembers,
      totalViews,
      todayViews,
      totalScanRequests,
      totalSuccessful,
      totalFailed,
      totalCached,
      totalFresh,
      topDomains,
      recentScans,
      viewsLast7,
      scansLast7,
      uniqueByDay
    ] = await Promise.all([
      this.redis.scard("siteguard:visits:visitors:all"),
      this.redis.smembers(this.dailyKey("visits:visitors", today)),
      this.redis.sunion(...days.map((day) => this.dailyKey("visits:visitors", day))),
      this.redis.get("siteguard:visits:pageviews:total"),
      this.redis.get(this.dailyKey("visits:pageviews", today)),
      this.redis.get("siteguard:scans:total"),
      this.redis.get("siteguard:scans:successful:total"),
      this.redis.get("siteguard:scans:failed:total"),
      this.redis.get("siteguard:scans:cached:total"),
      this.redis.get("siteguard:scans:fresh:total"),
      this.redis.zrange("siteguard:scans:domains", 0, TOP_DOMAIN_LIMIT - 1, { rev: true, withScores: true }),
      this.redis.lrange("siteguard:scans:recent", 0, RECENT_SCAN_LIMIT - 1),
      Promise.all(days.map((day) => this.redis.get(this.dailyKey("visits:pageviews", day)))),
      Promise.all(days.map((day) => this.redis.get(this.dailyKey("scans", day)))),
      Promise.all(days.map((day) => this.redis.scard(this.dailyKey("visits:visitors", day))))
    ]);

    const viewsByDay = Object.fromEntries(days.map((day, index) => [day, toInteger(viewsLast7[index])]));
    const scansByDay = Object.fromEntries(days.map((day, index) => [day, toInteger(scansLast7[index])]));
    const uniqueVisitorsByDay = Object.fromEntries(days.map((day, index) => [day, toInteger(uniqueByDay[index])]));

    return {
      backend: this.backend,
      generatedAt: new Date(now).toISOString(),
      timeZone: this.timeZone,
      scans: {
        cachedTotal: toInteger(totalCached),
        failedTotal: toInteger(totalFailed),
        freshTotal: toInteger(totalFresh),
        successfulTotal: toInteger(totalSuccessful),
        successRate: toInteger(totalScanRequests)
          ? Math.round((toInteger(totalSuccessful) / toInteger(totalScanRequests)) * 1000) / 10
          : 0,
        todayRequests: toInteger(scansByDay[today]),
        totalRequests: toInteger(totalScanRequests),
        totalRequestsLast7Days: sumValues(Object.values(scansByDay))
      },
      series: buildDailySeries(days, viewsByDay, scansByDay, uniqueVisitorsByDay),
      topDomains: normalizeTopDomainsResponse(topDomains).filter((entry) => entry.hostname),
      visitors: {
        pageViewsLast7Days: sumValues(Object.values(viewsByDay)),
        pageViewsToday: toInteger(todayViews),
        pageViewsTotal: toInteger(totalViews),
        uniqueLast7Days: Array.isArray(last7UniqueMembers) ? last7UniqueMembers.length : 0,
        uniqueToday: Array.isArray(uniqueTodayMembers) ? uniqueTodayMembers.length : 0,
        uniqueTotal: toInteger(totalUniqueVisitors)
      },
      recentScans: Array.isArray(recentScans)
        ? recentScans.map(parseRecentEntry).filter(Boolean)
        : []
    };
  }
}

export function createMetricsStore(options = {}) {
  const timeZone = options.timeZone || DEFAULT_TIME_ZONE;
  const redisUrl = options.url || process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const redisToken = options.token || process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

  if (options.mode === "memory" || !(redisUrl && redisToken)) {
    return new MemoryMetricsStore({ timeZone });
  }

  const redis = options.redis || new Redis({
    token: redisToken,
    url: redisUrl
  });

  return new RedisMetricsStore(redis, { timeZone });
}

export const __metricsInternals = {
  buildDayWindow,
  clampDuration,
  createRecentScanEntry,
  formatDayKey,
  normalizeTopDomainsResponse,
  normalizeHostname,
  normalizePath,
  parseRecentEntry
};
