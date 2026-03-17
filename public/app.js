const HISTORY_KEY = "siteguard:recent-scans";
const MAX_HISTORY_ITEMS = 6;
const FINDING_FILTERS = [
  { id: "all", label: "All" },
  { id: "urgent", label: "Urgent" },
  { id: "medium", label: "Medium" },
  { id: "low", label: "Low" }
];

const severityStyles = {
  critical: "bg-red-500 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-200 text-amber-900",
  low: "bg-stone-200 text-stone-700"
};

const statusStyles = {
  pass: "bg-emerald-500 text-white",
  warn: "bg-amber-200 text-amber-900",
  fail: "bg-red-500 text-white",
  na: "bg-stone-200 text-stone-700"
};

const riskStyles = {
  Critical: "bg-red-50 text-red-700",
  High: "bg-orange-50 text-orange-700",
  Moderate: "bg-amber-50 text-amber-700",
  Low: "bg-emerald-50 text-emerald-700"
};

const loadingMessages = [
  "공개 호스트를 확인하는 중...",
  "리다이렉트 체인을 따라가는 중...",
  "헤더와 쿠키 구성을 읽는 중...",
  "TLS와 HTML 신호를 점검하는 중...",
  "수정 가이드를 준비하는 중..."
];

const errorCodeMessages = {
  BODY_TOO_LARGE: "요청 데이터가 너무 큽니다.",
  ENOTFOUND: "도메인을 찾을 수 없습니다.",
  INVALID_JSON: "요청 형식이 올바르지 않습니다.",
  INVALID_URL: "URL 형식이 올바르지 않습니다.",
  PRIVATE_DNS_TARGET_BLOCKED: "사설 또는 내부망으로 해석되는 도메인은 검사할 수 없습니다.",
  PRIVATE_HOST_BLOCKED: "localhost, internal, local 도메인은 검사할 수 없습니다.",
  PRIVATE_IP_BLOCKED: "사설 또는 예약된 IP는 검사할 수 없습니다.",
  RATE_LIMITED: "지금 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
  REQUEST_TIMEOUT: "대상 서버 응답이 너무 오래 걸립니다.",
  SCAN_QUEUE_FULL: "스캐너가 바쁩니다. 잠시 후 다시 시도해 주세요.",
  UNSUPPORTED_CONTENT_TYPE: "서버 요청 형식이 올바르지 않습니다.",
  UNSUPPORTED_PROTOCOL: "http 또는 https URL만 검사할 수 있습니다.",
  URL_REQUIRED: "검사할 URL을 입력해 주세요.",
  URL_WITH_CREDENTIALS: "아이디나 비밀번호가 포함된 URL은 지원하지 않습니다."
};

const form = document.querySelector("#scan-form");
const urlInput = document.querySelector("#url-input");
const loadingPanel = document.querySelector("#loading-panel");
const loadingText = document.querySelector("#loading-text");
const errorPanel = document.querySelector("#error-panel");
const resultsSection = document.querySelector("#results");
const reportToolbar = document.querySelector("#report-toolbar");
const reportMeta = document.querySelector("#report-meta");
const recentPanel = document.querySelector("#recent-panel");
const recentList = document.querySelector("#recent-list");
const clearHistoryButton = document.querySelector("#clear-history-button");
const limitationsList = document.querySelector("#limitations-list");
const actionStack = document.querySelector("#action-stack");
const findingFilters = document.querySelector("#finding-filters");
const heroRiskPill = document.querySelector("#hero-risk-pill");

const scoreRing = document.querySelector("#score-ring");
const scoreValue = document.querySelector("#score-value");
const scoreGrade = document.querySelector("#score-grade");
const scoreHeadline = document.querySelector("#score-headline");
const scoreRisk = document.querySelector("#score-risk");
const statGrid = document.querySelector("#stat-grid");
const findingsList = document.querySelector("#findings-list");
const checksGrid = document.querySelector("#checks-grid");
const redirectTimeline = document.querySelector("#redirect-timeline");
const headersBlock = document.querySelector("#headers-block");
const tlsCard = document.querySelector("#tls-card");
const cookiesCard = document.querySelector("#cookies-card");

const copySummaryButton = document.querySelector("#copy-summary-button");
const copyJsonButton = document.querySelector("#copy-json-button");
const downloadJsonButton = document.querySelector("#download-json-button");
const downloadMarkdownButton = document.querySelector("#download-md-button");

let loadingTimer = null;
let lastReport = null;
let activeFindingFilter = "all";

setupSamples();
setupRevealObserver();
setupHistory();
setupToolbarActions();
setupJumpNavigation();

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = urlInput.value.trim();
  if (!url) {
    showError(errorCodeMessages.URL_REQUIRED);
    return;
  }

  clearError();
  setLoading(true);

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    const payload = await response.json();

    if (!response.ok || !payload.ok) {
      const errorCode = payload?.error?.code;
      throw new Error(errorCodeMessages[errorCode] || payload?.error?.message || "검사에 실패했습니다.");
    }

    activeFindingFilter = "all";
    lastReport = payload;
    renderReport(payload);
    saveRecentScan(payload.target.finalUrl || payload.target.normalized || url);
    resultsSection.classList.remove("hidden");
    reportToolbar.classList.remove("hidden");
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    showError(error.message || "검사 중 오류가 발생했습니다.");
  } finally {
    setLoading(false);
  }
});

function setupSamples() {
  document.querySelectorAll("[data-sample]").forEach((button) => {
    button.addEventListener("click", () => {
      urlInput.value = button.dataset.sample || "";
      urlInput.focus();
    });
  });
}

function setupRevealObserver() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.remove("opacity-0", "translate-y-4");
        entry.target.classList.add("opacity-100", "translate-y-0");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12 });

  document.querySelectorAll("[data-reveal]").forEach((element) => {
    observer.observe(element);
  });
}

function setupToolbarActions() {
  copySummaryButton.addEventListener("click", async () => {
    if (!lastReport) return;
    await navigator.clipboard.writeText(buildSummaryText(lastReport));
    flashButton(copySummaryButton, "복사됨", "요약 복사");
  });

  copyJsonButton.addEventListener("click", async () => {
    if (!lastReport) return;
    await navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2));
    flashButton(copyJsonButton, "복사됨", "JSON 복사");
  });

  downloadJsonButton.addEventListener("click", () => {
    if (!lastReport) return;
    downloadFile(
      buildFilename(lastReport, "json"),
      JSON.stringify(lastReport, null, 2),
      "application/json"
    );
  });

  downloadMarkdownButton.addEventListener("click", () => {
    if (!lastReport) return;
    downloadFile(
      buildFilename(lastReport, "md"),
      buildMarkdown(lastReport),
      "text/markdown"
    );
  });
}

function setupJumpNavigation() {
  document.querySelectorAll("[data-scroll-target]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.getElementById(button.dataset.scrollTarget || "");
      if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });
}

function setupHistory() {
  renderHistory();

  clearHistoryButton?.addEventListener("click", () => {
    window.localStorage.removeItem(HISTORY_KEY);
    renderHistory();
  });
}

function setLoading(isLoading) {
  loadingPanel.classList.toggle("hidden", !isLoading);
  form.querySelector(".submit-button").disabled = isLoading;

  if (isLoading) {
    let index = 0;
    loadingText.textContent = loadingMessages[0];
    loadingTimer = window.setInterval(() => {
      index = (index + 1) % loadingMessages.length;
      loadingText.textContent = loadingMessages[index];
    }, 950);
  } else if (loadingTimer) {
    clearInterval(loadingTimer);
    loadingTimer = null;
  }
}

function showError(message) {
  errorPanel.textContent = message;
  errorPanel.classList.remove("hidden");
}

function clearError() {
  errorPanel.textContent = "";
  errorPanel.classList.add("hidden");
}

function renderReport(report) {
  renderScore(report.summary);
  renderMeta(report);
  renderStats(report.summary, report.evidence);
  renderActionStack(report.findings);
  renderFindingFilters(report.findings);
  renderFindings(report.findings);
  renderChecks(report.checks);
  renderTimeline(report.evidence.redirectChain);
  renderHeaders(report.evidence.finalHeaders);
  renderTls(report.evidence.tls);
  renderCookies(report.evidence.cookies);
  renderLimitations(report.limitations || []);
}

function renderScore(summary) {
  scoreValue.textContent = String(summary.score);
  scoreGrade.textContent = `${summary.grade} Grade`;
  scoreHeadline.textContent = summary.headline;
  scoreRisk.textContent = `Risk level: ${summary.riskLevel}`;

  const safeScore = Math.max(0, Math.min(summary.score, 100));
  const degrees = safeScore * 3.6;
  scoreRing.style.background = `conic-gradient(rgb(249 115 22) 0deg, rgb(251 146 60) ${degrees}deg, rgba(253,186,116,0.22) ${degrees}deg, rgba(253,186,116,0.22) 360deg)`;

  heroRiskPill.className = `rounded-full px-3 py-1 text-sm font-semibold ${riskClass(summary.riskLevel)}`;
  heroRiskPill.textContent = `${summary.riskLevel} Risk`;
}

function renderMeta(report) {
  const scanTime = new Date(report.target.scannedAt).toLocaleString("ko-KR");
  const cachedLabel = report.meta?.cached ? "cached result" : "fresh scan";

  reportMeta.innerHTML = `
    <strong class="text-base font-semibold text-slate-900">${escapeHtml(report.target.finalUrl || report.target.normalized)}</strong>
    <span>${escapeHtml(scanTime)} · ${escapeHtml(cachedLabel)} · ${escapeHtml(report.target.publicScanMode || "passive")}</span>
    <span>request id: ${escapeHtml(report.meta?.requestId || "n/a")} · ${escapeHtml(String(report.meta?.durationMs ?? 0))} ms</span>
  `;
}

function renderStats(summary, evidence) {
  const cards = [
    { label: "Critical", value: summary.counts.critical },
    { label: "High", value: summary.counts.high },
    { label: "Redirects", value: summary.counts.redirects },
    { label: "Cookies", value: evidence.cookies.length }
  ];

  statGrid.innerHTML = cards.map((card) => `
    <article class="rounded-2xl border border-orange-100 bg-orange-50/60 p-4">
      <small class="text-xs uppercase tracking-[0.18em] text-slate-500">${escapeHtml(card.label)}</small>
      <strong class="mt-2 block text-2xl font-bold text-slate-900">${escapeHtml(String(card.value))}</strong>
    </article>
  `).join("");
}

function renderActionStack(findings) {
  const items = findings.slice(0, 4).map((finding) => ({
    severity: finding.severity,
    title: finding.title,
    action: finding.remediation?.actions?.[0] || finding.summary
  }));

  if (!items.length) {
    actionStack.innerHTML = `
      <article class="rounded-2xl border border-orange-100 bg-orange-50/50 p-4">
        <strong class="block text-sm font-semibold text-slate-900">지금 바로 고칠 고위험 항목은 보이지 않습니다</strong>
        <p class="mt-2 text-sm leading-6 text-slate-500">그래도 인증 흐름과 권한 모델은 별도의 테스트가 필요합니다.</p>
      </article>
    `;
    return;
  }

  actionStack.innerHTML = items.map((item) => `
    <article class="rounded-2xl border border-orange-100 bg-orange-50/50 p-4">
      <span class="inline-flex rounded-full px-3 py-1 text-xs font-semibold ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span>
      <strong class="mt-3 block text-sm font-semibold text-slate-900">${escapeHtml(item.title)}</strong>
      <p class="mt-2 text-sm leading-6 text-slate-500">${escapeHtml(item.action)}</p>
    </article>
  `).join("");
}

function renderFindingFilters(findings) {
  const counts = {
    all: findings.length,
    urgent: findings.filter((finding) => finding.severity === "critical" || finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    low: findings.filter((finding) => finding.severity === "low").length
  };

  findingFilters.innerHTML = FINDING_FILTERS.map((filter) => {
    const activeClasses = filter.id === activeFindingFilter
      ? "bg-orange-500 text-white border-orange-500"
      : "bg-orange-50 text-slate-700 border-orange-200 hover:bg-orange-100";

    return `
      <button
        type="button"
        data-finding-filter="${escapeHtml(filter.id)}"
        class="rounded-full border px-4 py-2 text-sm font-semibold transition ${activeClasses}"
      >
        ${escapeHtml(filter.label)} (${escapeHtml(String(counts[filter.id] || 0))})
      </button>
    `;
  }).join("");

  findingFilters.querySelectorAll("[data-finding-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      activeFindingFilter = button.dataset.findingFilter || "all";
      renderFindingFilters(findings);
      renderFindings(findings);
    });
  });
}

function renderFindings(findings) {
  const filteredFindings = findings.filter((finding) => matchesFindingFilter(finding, activeFindingFilter));

  if (!filteredFindings.length) {
    findingsList.innerHTML = `
      <article class="rounded-2xl border border-orange-100 bg-orange-50/50 p-5">
        <div class="flex items-center justify-between gap-4">
          <h4 class="text-lg font-semibold text-slate-900">이 필터에 해당하는 항목이 없습니다</h4>
          <span class="inline-flex rounded-full px-3 py-1 text-xs font-semibold ${severityClass("low")}">empty</span>
        </div>
        <p class="mt-3 text-sm leading-7 text-slate-500">다른 필터를 선택해서 전체 결과를 다시 확인해 보세요.</p>
      </article>
    `;
    return;
  }

  findingsList.innerHTML = filteredFindings.map((finding) => {
    const remediation = finding.remediation;
    const actions = remediation?.actions?.length
      ? `<ul class="mt-3 list-disc space-y-2 pl-5 text-sm leading-7 text-slate-500">${remediation.actions.map((action) => `<li>${escapeHtml(action)}</li>`).join("")}</ul>`
      : "";
    const snippets = remediation?.snippets?.length
      ? `<div class="mt-4 grid gap-3">${remediation.snippets.map((snippet) => `
          <div class="rounded-2xl border border-gray-800 bg-gray-900 p-4 text-gray-100">
            <strong class="block text-sm font-semibold text-white">${escapeHtml(snippet.label)}</strong>
            <pre class="mt-3 overflow-auto text-sm leading-7 text-gray-100">${escapeHtml(snippet.code)}</pre>
          </div>
        `).join("")}</div>`
      : "";
    const references = remediation?.references?.length
      ? `<div class="mt-4 flex flex-wrap gap-2">${remediation.references.map((ref) => `
          <a
            href="${escapeHtml(ref.href)}"
            target="_blank"
            rel="noreferrer"
            class="rounded-full border border-orange-200 bg-orange-50 px-3 py-1.5 text-sm font-semibold text-orange-700 transition hover:bg-orange-100"
          >${escapeHtml(ref.label)}</a>
        `).join("")}</div>`
      : "";

    return `
      <article class="rounded-2xl border border-orange-100 bg-orange-50/40 p-5">
        <div class="flex items-start justify-between gap-4">
          <h4 class="text-xl font-semibold tracking-tight text-slate-900">${escapeHtml(finding.title)}</h4>
          <span class="inline-flex rounded-full px-3 py-1 text-xs font-semibold ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
        </div>
        <p class="mt-3 text-sm leading-7 text-slate-600">${escapeHtml(finding.summary)}</p>
        <p class="mt-3 text-sm leading-7 text-slate-500"><strong class="font-semibold text-slate-700">Evidence:</strong> ${escapeHtml(finding.evidence || "n/a")}</p>
        ${remediation ? `
          <div class="mt-4 border-t border-orange-100 pt-4">
            <strong class="block text-sm font-semibold text-slate-900">${escapeHtml(remediation.title)}</strong>
            <p class="mt-2 text-sm leading-7 text-slate-500">${escapeHtml(remediation.whyItMatters)}</p>
            ${actions}
            ${snippets}
            ${references}
          </div>
        ` : ""}
      </article>
    `;
  }).join("");
}

function renderChecks(checks) {
  checksGrid.innerHTML = checks.map((check) => `
    <article class="rounded-2xl border border-orange-100 bg-orange-50/40 p-5">
      <div class="flex items-center justify-between gap-3">
        <strong class="text-base font-semibold text-slate-900">${escapeHtml(check.label)}</strong>
        <span class="inline-flex rounded-full px-3 py-1 text-xs font-semibold ${statusClass(check.status)}">${escapeHtml(check.status)}</span>
      </div>
      <p class="mt-3 text-sm leading-7 text-slate-500">${escapeHtml(check.detail)}</p>
    </article>
  `).join("");
}

function renderTimeline(redirectChain) {
  redirectTimeline.innerHTML = redirectChain.map((step, index) => `
    <article class="rounded-2xl border border-orange-100 bg-orange-50/50 p-4">
      <small class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Hop ${index + 1} · ${escapeHtml(String(step.statusCode))}</small>
      <code class="mt-3 block break-all text-sm font-medium text-slate-800">${escapeHtml(step.url)}</code>
      ${step.location ? `<code class="mt-2 block break-all text-sm text-slate-500">→ ${escapeHtml(step.location)}</code>` : ""}
    </article>
  `).join("");
}

function renderHeaders(headers) {
  headersBlock.textContent = Object.entries(headers)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join("; ") : value}`)
    .join("\n");
}

function renderTls(tls) {
  if (!tls) {
    tlsCard.innerHTML = `
      <h4 class="text-lg font-semibold text-slate-900">TLS</h4>
      <p class="mt-2 text-sm leading-7 text-slate-500">HTTPS가 감지되지 않았거나 TLS 정보를 읽을 수 없었습니다.</p>
    `;
    return;
  }

  tlsCard.innerHTML = `
    <h4 class="text-lg font-semibold text-slate-900">TLS</h4>
    <dl class="mt-4 grid grid-cols-[120px_1fr] gap-x-4 gap-y-3 text-sm">
      <dt class="font-semibold text-slate-700">Protocol</dt><dd class="break-all text-slate-500">${escapeHtml(tls.protocol || "unknown")}</dd>
      <dt class="font-semibold text-slate-700">Cipher</dt><dd class="break-all text-slate-500">${escapeHtml(tls.cipher || "unknown")}</dd>
      <dt class="font-semibold text-slate-700">Authorized</dt><dd class="break-all text-slate-500">${escapeHtml(String(Boolean(tls.authorized)))}</dd>
      <dt class="font-semibold text-slate-700">Error</dt><dd class="break-all text-slate-500">${escapeHtml(tls.authorizationError || "none")}</dd>
      <dt class="font-semibold text-slate-700">Subject</dt><dd class="break-all text-slate-500">${escapeHtml(tls.subject || "unknown")}</dd>
      <dt class="font-semibold text-slate-700">Issuer</dt><dd class="break-all text-slate-500">${escapeHtml(tls.issuer || "unknown")}</dd>
      <dt class="font-semibold text-slate-700">Valid from</dt><dd class="break-all text-slate-500">${escapeHtml(tls.validFrom || "unknown")}</dd>
      <dt class="font-semibold text-slate-700">Valid to</dt><dd class="break-all text-slate-500">${escapeHtml(tls.validTo || "unknown")}</dd>
    </dl>
  `;
}

function renderCookies(cookies) {
  if (!cookies.length) {
    cookiesCard.innerHTML = `
      <h4 class="text-lg font-semibold text-slate-900">Set-Cookie</h4>
      <p class="mt-2 text-sm leading-7 text-slate-500">이번 응답에서는 Set-Cookie 헤더가 관찰되지 않았습니다.</p>
    `;
    return;
  }

  cookiesCard.innerHTML = `
    <h4 class="text-lg font-semibold text-slate-900">Set-Cookie</h4>
    <div class="mt-4 grid gap-3">
      ${cookies.map((cookie) => `
        <article class="rounded-2xl border border-orange-100 bg-white p-4">
          <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div>
              <div class="font-semibold text-slate-900">${escapeHtml(cookie.name || "(unnamed)")}</div>
              <small class="mt-1 block text-slate-500">${escapeHtml(cookie.valuePreview || "(value hidden)")}</small>
            </div>
            <div class="flex flex-wrap gap-2">
              <span class="rounded-full bg-orange-50 px-3 py-1 text-xs font-semibold text-slate-700">Secure: ${cookie.secure ? "yes" : "no"}</span>
              <span class="rounded-full bg-orange-50 px-3 py-1 text-xs font-semibold text-slate-700">HttpOnly: ${cookie.httpOnly ? "yes" : "no"}</span>
              <span class="rounded-full bg-orange-50 px-3 py-1 text-xs font-semibold text-slate-700">SameSite: ${escapeHtml(cookie.sameSite || "missing")}</span>
            </div>
          </div>
        </article>
      `).join("")}
    </div>
  `;
}

function renderLimitations(limitations) {
  limitationsList.innerHTML = limitations.map((item) => `
    <article class="rounded-2xl border border-orange-100 bg-orange-50/50 p-4 text-sm leading-7 text-slate-500">${escapeHtml(item)}</article>
  `).join("");
}

function matchesFindingFilter(finding, filterId) {
  switch (filterId) {
    case "urgent":
      return finding.severity === "critical" || finding.severity === "high";
    case "medium":
      return finding.severity === "medium";
    case "low":
      return finding.severity === "low";
    default:
      return true;
  }
}

function renderHistory() {
  const history = readHistory();
  recentPanel?.classList.toggle("hidden", history.length === 0);

  if (!history.length) {
    recentList.innerHTML = "";
    return;
  }

  recentList.innerHTML = history.map((item) => `
    <article class="rounded-2xl border border-orange-100 bg-orange-50/50 p-4">
      <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <code class="break-all text-sm font-medium text-slate-800">${escapeHtml(item)}</code>
        <button type="button" data-recent="${escapeHtml(item)}" class="rounded-full border border-orange-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition hover:bg-orange-100">다시 검사</button>
      </div>
    </article>
  `).join("");

  recentList.querySelectorAll("[data-recent]").forEach((button) => {
    button.addEventListener("click", () => {
      urlInput.value = button.dataset.recent || "";
      urlInput.focus();
    });
  });
}

function saveRecentScan(url) {
  const list = readHistory().filter((item) => item !== url);
  list.unshift(url);
  window.localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, MAX_HISTORY_ITEMS)));
  renderHistory();
}

function readHistory() {
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((item) => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function flashButton(button, temporaryLabel, originalLabel) {
  button.textContent = temporaryLabel;
  window.setTimeout(() => {
    button.textContent = originalLabel;
  }, 1200);
}

function buildSummaryText(report) {
  const topFindings = report.findings.slice(0, 3).map((finding) => `- ${finding.title}`).join("\n") || "- 없음";
  return [
    `[SiteGuard] ${report.target.finalUrl || report.target.normalized}`,
    `score: ${report.summary.score} (${report.summary.grade})`,
    `risk: ${report.summary.riskLevel}`,
    `headline: ${report.summary.headline}`,
    "",
    "top findings:",
    topFindings
  ].join("\n");
}

function buildMarkdown(report) {
  const checks = report.checks.map((check) => `- ${check.label}: ${check.status} (${check.detail})`).join("\n");
  const findings = report.findings.length
    ? report.findings.map((finding) => [
        `## ${finding.title}`,
        `- Severity: ${finding.severity}`,
        `- Summary: ${finding.summary}`,
        `- Evidence: ${finding.evidence || "n/a"}`
      ].join("\n")).join("\n\n")
    : "문제 없음";

  return [
    "# SiteGuard Report",
    "",
    `- URL: ${report.target.finalUrl || report.target.normalized}`,
    `- Scanned at: ${report.target.scannedAt}`,
    `- Score: ${report.summary.score} (${report.summary.grade})`,
    `- Risk: ${report.summary.riskLevel}`,
    `- Cached: ${report.meta?.cached ? "yes" : "no"}`,
    "",
    "## Headline",
    report.summary.headline,
    "",
    "## Findings",
    findings,
    "",
    "## Checks",
    checks,
    "",
    "## Limitations",
    report.limitations.map((item) => `- ${item}`).join("\n")
  ].join("\n");
}

function buildFilename(report, extension) {
  const hostname = new URL(report.target.finalUrl || report.target.normalized).hostname.replaceAll(".", "-");
  return `siteguard-${hostname}.${extension}`;
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function severityClass(severity) {
  return severityStyles[severity] || severityStyles.low;
}

function statusClass(status) {
  return statusStyles[status] || statusStyles.na;
}

function riskClass(risk) {
  return riskStyles[risk] || riskStyles.Moderate;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
