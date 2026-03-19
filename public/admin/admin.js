const elements = {};

document.addEventListener("DOMContentLoaded", () => {
  cacheElements();
  bindEvents();
  hydrateAdmin();
});

function cacheElements() {
  elements.sessionStatus = document.getElementById("session-status");
  elements.logoutButton = document.getElementById("logout-button");
  elements.setupPanel = document.getElementById("setup-panel");
  elements.loginPanel = document.getElementById("login-panel");
  elements.dashboardPanel = document.getElementById("dashboard-panel");
  elements.loginForm = document.getElementById("login-form");
  elements.loginError = document.getElementById("login-error");
  elements.generatedAt = document.getElementById("generated-at");
  elements.metricsBackend = document.getElementById("metrics-backend");
  elements.timeZone = document.getElementById("time-zone");

  elements.visitorsTotal = document.getElementById("visitors-total");
  elements.visitorsToday = document.getElementById("visitors-today");
  elements.visitorsWeek = document.getElementById("visitors-week");
  elements.viewsTotal = document.getElementById("views-total");
  elements.viewsToday = document.getElementById("views-today");
  elements.viewsWeek = document.getElementById("views-week");

  elements.scansTotal = document.getElementById("scans-total");
  elements.scansToday = document.getElementById("scans-today");
  elements.scansWeek = document.getElementById("scans-week");
  elements.scansSuccessRate = document.getElementById("scans-success-rate");
  elements.scansSuccessful = document.getElementById("scans-successful");
  elements.scansFailed = document.getElementById("scans-failed");
  elements.scansCached = document.getElementById("scans-cached");
  elements.scansFresh = document.getElementById("scans-fresh");

  elements.seriesGrid = document.getElementById("series-grid");
  elements.topDomains = document.getElementById("top-domains");
  elements.recentScans = document.getElementById("recent-scans");
}

function bindEvents() {
  elements.loginForm.addEventListener("submit", handleLogin);
  elements.logoutButton.addEventListener("click", handleLogout);
}

async function hydrateAdmin() {
  setStatus("세션 확인 중");
  hideAllPanels();

  try {
    const response = await fetch("/api/admin/session", {
      credentials: "same-origin"
    });
    const data = await response.json();
    const admin = data.admin || {};

    if (!admin.configured) {
      elements.setupPanel.hidden = false;
      setStatus("설정 필요");
      return;
    }

    if (!admin.authenticated) {
      elements.loginPanel.hidden = false;
      setStatus("로그인 필요");
      return;
    }

    elements.logoutButton.hidden = false;
    setStatus(`${admin.username} 로그인됨`);
    await loadMetrics();
  } catch (error) {
    elements.setupPanel.hidden = false;
    elements.setupPanel.querySelector("p").textContent = "관리자 세션을 확인하지 못했습니다. 잠시 후 다시 시도해주세요.";
    setStatus("접속 오류");
  }
}

function hideAllPanels() {
  elements.setupPanel.hidden = true;
  elements.loginPanel.hidden = true;
  elements.dashboardPanel.hidden = true;
  elements.logoutButton.hidden = true;
  elements.loginError.hidden = true;
}

function setStatus(text) {
  elements.sessionStatus.textContent = text;
}

async function handleLogin(event) {
  event.preventDefault();
  elements.loginError.hidden = true;
  setStatus("로그인 확인 중");

  const formData = new FormData(elements.loginForm);
  const payload = {
    password: String(formData.get("password") || ""),
    username: String(formData.get("username") || "").trim()
  };

  try {
    const response = await fetch("/api/admin/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      credentials: "same-origin",
      body: JSON.stringify(payload)
    });
    const data = await response.json();

    if (!response.ok || !data.ok) {
      throw new Error(data.error?.message || "로그인에 실패했습니다.");
    }

    elements.loginForm.reset();
    await hydrateAdmin();
  } catch (error) {
    elements.loginError.textContent = error.message || "로그인에 실패했습니다.";
    elements.loginError.hidden = false;
    setStatus("로그인 실패");
  }
}

async function handleLogout() {
  await fetch("/api/admin/logout", {
    method: "POST",
    credentials: "same-origin"
  });

  await hydrateAdmin();
}

async function loadMetrics() {
  const response = await fetch("/api/admin/metrics", {
    credentials: "same-origin"
  });
  const data = await response.json();

  if (!response.ok || !data.ok) {
    if (response.status === 401) {
      await hydrateAdmin();
      return;
    }

    throw new Error(data.error?.message || "메트릭을 불러오지 못했습니다.");
  }

  renderMetrics(data.metrics);
  elements.dashboardPanel.hidden = false;
}

function renderMetrics(metrics) {
  const visitors = metrics.visitors || {};
  const scans = metrics.scans || {};
  const series = Array.isArray(metrics.series) ? metrics.series : [];
  const topDomains = Array.isArray(metrics.topDomains) ? metrics.topDomains : [];
  const recentScans = Array.isArray(metrics.recentScans) ? metrics.recentScans : [];

  elements.generatedAt.textContent = formatDateTime(metrics.generatedAt);
  elements.metricsBackend.textContent = metrics.backend === "redis" ? "Upstash Redis" : "Memory";
  elements.timeZone.textContent = metrics.timeZone || "-";

  elements.visitorsTotal.textContent = formatNumber(visitors.uniqueTotal);
  elements.visitorsToday.textContent = formatNumber(visitors.uniqueToday);
  elements.visitorsWeek.textContent = formatNumber(visitors.uniqueLast7Days);
  elements.viewsTotal.textContent = formatNumber(visitors.pageViewsTotal);
  elements.viewsToday.textContent = formatNumber(visitors.pageViewsToday);
  elements.viewsWeek.textContent = formatNumber(visitors.pageViewsLast7Days);

  elements.scansTotal.textContent = formatNumber(scans.totalRequests);
  elements.scansToday.textContent = formatNumber(scans.todayRequests);
  elements.scansWeek.textContent = formatNumber(scans.totalRequestsLast7Days);
  elements.scansSuccessRate.textContent = `${Number(scans.successRate || 0).toFixed(1)}%`;
  elements.scansSuccessful.textContent = formatNumber(scans.successfulTotal);
  elements.scansFailed.textContent = formatNumber(scans.failedTotal);
  elements.scansCached.textContent = formatNumber(scans.cachedTotal);
  elements.scansFresh.textContent = formatNumber(scans.freshTotal);

  renderSeries(series);
  renderTopDomains(topDomains);
  renderRecentScans(recentScans);
}

function renderSeries(series) {
  if (!series.length) {
    elements.seriesGrid.innerHTML = '<div class="empty-state">최근 흐름을 아직 만들지 못했습니다.</div>';
    return;
  }

  const maxViews = Math.max(...series.map((item) => Number(item.views || 0)), 1);
  const maxScans = Math.max(...series.map((item) => Number(item.scans || 0)), 1);
  const maxVisitors = Math.max(...series.map((item) => Number(item.uniqueVisitors || 0)), 1);

  elements.seriesGrid.innerHTML = series.map((item) => {
    const label = formatDay(item.day);
    return `
      <div class="series-row">
        <div class="series-head">
          <strong>${escapeHtml(label)}</strong>
          <span class="series-label">방문 ${formatNumber(item.uniqueVisitors)} / 페이지뷰 ${formatNumber(item.views)} / 실행 ${formatNumber(item.scans)}</span>
        </div>
        <div class="series-bars">
          ${renderSeriesBar("고유 방문자", item.uniqueVisitors, maxVisitors, "visitors")}
          ${renderSeriesBar("페이지뷰", item.views, maxViews, "views")}
          ${renderSeriesBar("점검 실행", item.scans, maxScans, "scans")}
        </div>
      </div>
    `;
  }).join("");
}

function renderSeriesBar(label, value, max, kind) {
  const width = max ? Math.max(8, Math.round((Number(value || 0) / max) * 100)) : 0;
  return `
    <div class="series-bar">
      <span class="series-label">${escapeHtml(label)}</span>
      <div class="series-track">
        <div class="series-fill ${kind}" style="width:${width}%"></div>
      </div>
      <strong>${formatNumber(value)}</strong>
    </div>
  `;
}

function renderTopDomains(domains) {
  if (!domains.length) {
    elements.topDomains.textContent = "아직 실행 기록이 없습니다.";
    elements.topDomains.className = "list-block empty-state";
    return;
  }

  elements.topDomains.className = "list-block";
  elements.topDomains.innerHTML = domains.map((item, index) => `
    <div class="list-item">
      <strong>${index + 1}. ${escapeHtml(item.hostname)}</strong>
      <span class="list-subtle">누적 점검 ${formatNumber(item.count)}회</span>
    </div>
  `).join("");
}

function renderRecentScans(items) {
  if (!items.length) {
    elements.recentScans.textContent = "아직 실행 기록이 없습니다.";
    elements.recentScans.className = "table-shell empty-state";
    return;
  }

  elements.recentScans.className = "table-shell";
  elements.recentScans.innerHTML = `
    <div class="recent-header">
      <span>대상</span>
      <span>상태</span>
      <span>방식</span>
      <span>점수</span>
      <span>응답 시간</span>
      <span>시각</span>
    </div>
    ${items.map((item) => `
      <div class="recent-row">
        <div class="recent-main">${escapeHtml(item.hostname || "(unknown)")}</div>
        <div><span class="badge ${item.ok ? "success" : "fail"}">${item.ok ? "성공" : "실패"}</span></div>
        <div><span class="badge ${item.cached ? "cached" : "fresh"}">${item.cached ? "캐시" : "실시간"}</span></div>
        <div>${item.score == null ? (item.errorCode ? escapeHtml(item.errorCode) : "-") : formatNumber(item.score)}</div>
        <div>${formatDuration(item.durationMs)}</div>
        <div>${escapeHtml(formatDateTime(item.at))}</div>
      </div>
    `).join("")}
  `;
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("ko-KR");
}

function formatDateTime(value) {
  if (!value) {
    return "-";
  }

  try {
    return new Date(value).toLocaleString("ko-KR");
  } catch {
    return String(value);
  }
}

function formatDay(value) {
  if (!value) {
    return "-";
  }

  try {
    const date = new Date(`${value}T00:00:00`);
    return new Intl.DateTimeFormat("ko-KR", { month: "numeric", day: "numeric", weekday: "short" }).format(date);
  } catch {
    return value;
  }
}

function formatDuration(value) {
  const duration = Number(value || 0);
  if (!Number.isFinite(duration)) {
    return "-";
  }
  return `${Math.round(duration)}ms`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
