const STORAGE_KEY = "siteguard:scan-snapshots:v2";
const MAX_HISTORY_ITEMS = 8;

const FINDING_FILTERS = [
  { id: "all", label: "전체" },
  { id: "critical", label: "치명" },
  { id: "high", label: "높음" },
  { id: "medium", label: "중간" },
  { id: "low", label: "낮음" }
];

const LOADING_MESSAGES = [
  "보안 점검을 진행하고 있습니다...",
  "응답 헤더를 분석하고 있습니다...",
  "TLS 설정을 확인하고 있습니다...",
  "쿠키 보안을 점검하고 있습니다..."
];

const ERROR_MESSAGES = {
  BODY_TOO_LARGE: "요청 데이터가 너무 큽니다.",
  ENOTFOUND: "도메인을 찾을 수 없습니다.",
  INVALID_JSON: "요청 형식이 올바르지 않습니다.",
  INVALID_URL: "URL 형식이 올바르지 않습니다.",
  PRIVATE_DNS_TARGET_BLOCKED: "사설망으로 해석되는 대상은 검사할 수 없습니다.",
  PRIVATE_HOST_BLOCKED: "localhost, internal, local 도메인은 검사할 수 없습니다.",
  PRIVATE_IP_BLOCKED: "사설 또는 예약된 IP는 검사할 수 없습니다.",
  RATE_LIMITED: "요청이 많습니다. 잠시 후 다시 시도해 주세요.",
  REQUEST_TIMEOUT: "대상 서버 응답이 오래 걸려 스캔을 중단했습니다.",
  SCAN_QUEUE_FULL: "현재 스캐너가 바쁩니다. 잠시 후 다시 시도해 주세요.",
  UNSUPPORTED_CONTENT_TYPE: "요청은 JSON 형식이어야 합니다.",
  UNSUPPORTED_PROTOCOL: "http 또는 https URL만 검사할 수 있습니다.",
  URL_REQUIRED: "검사할 URL을 입력해 주세요.",
  URL_WITH_CREDENTIALS: "아이디나 비밀번호가 포함된 URL은 지원하지 않습니다."
};

const severityLabels = {
  critical: "치명",
  high: "높음",
  medium: "중간",
  low: "낮음",
  info: "정보",
  pass: "통과"
};

let currentResult = null;
let currentFilter = "all";
let loadingInterval = null;

// DOM Elements
const elements = {};

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  cacheElements();
  setupEventListeners();
  renderHistory();
  checkHashNavigation();
});

function cacheElements() {
  elements.scanForm = document.getElementById("scan-form");
  elements.urlInput = document.getElementById("url-input");
  elements.submitButton = document.getElementById("submit-button");
  elements.loadingPanel = document.getElementById("loading-panel");
  elements.loadingText = document.getElementById("loading-text");
  elements.errorPanel = document.getElementById("error-panel");

  elements.scannerSection = document.getElementById("scanner-section");
  elements.resultsSection = document.getElementById("results-section");
  elements.historySection = document.getElementById("history-section");

  elements.resultUrl = document.getElementById("result-url");
  elements.resultMeta = document.getElementById("result-meta");
  elements.scoreNumber = document.getElementById("score-number");
  elements.scoreGrade = document.getElementById("score-grade");
  elements.scoreRingProgress = document.getElementById("score-ring-progress");
  elements.riskBadge = document.getElementById("risk-badge");
  elements.summaryHeadline = document.getElementById("summary-headline");
  elements.summaryBody = document.getElementById("summary-body");

  elements.statPasses = document.getElementById("stat-passes");
  elements.statWarnings = document.getElementById("stat-warnings");
  elements.statFailures = document.getElementById("stat-failures");

  elements.actionsList = document.getElementById("actions-list");
  elements.findingsFilters = document.getElementById("findings-filters");
  elements.findingsList = document.getElementById("findings-list");
  elements.checksGrid = document.getElementById("checks-grid");
  elements.redirectTimeline = document.getElementById("redirect-timeline");
  elements.headersBlock = document.getElementById("headers-block");
  elements.tlsCard = document.getElementById("tls-card");
  elements.cookiesCard = document.getElementById("cookies-card");

  elements.historyGrid = document.getElementById("history-grid");
  elements.historyEmpty = document.getElementById("history-empty");
  elements.clearHistoryBtn = document.getElementById("clear-history-btn");

  elements.backToScanner = document.getElementById("back-to-scanner");
  elements.copySummaryBtn = document.getElementById("copy-summary-btn");
  elements.copyJsonBtn = document.getElementById("copy-json-btn");
  elements.downloadJsonBtn = document.getElementById("download-json-btn");
  elements.downloadMdBtn = document.getElementById("download-md-btn");
}

function setupEventListeners() {
  elements.scanForm.addEventListener("submit", handleScan);

  document.querySelectorAll("[data-sample]").forEach(btn => {
    btn.addEventListener("click", () => {
      elements.urlInput.value = btn.dataset.sample;
      elements.scanForm.dispatchEvent(new Event("submit"));
    });
  });

  document.querySelectorAll("[data-nav]").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const target = link.dataset.nav;
      if (target === "scanner") showScanner();
      else if (target === "history") showHistory();
    });
  });

  elements.backToScanner.addEventListener("click", showScanner);
  document.getElementById("logo-link").addEventListener("click", (e) => {
    e.preventDefault();
    showScanner();
  });

  elements.clearHistoryBtn.addEventListener("click", clearHistory);

  elements.copySummaryBtn.addEventListener("click", copySummary);
  elements.copyJsonBtn.addEventListener("click", copyJson);
  elements.downloadJsonBtn.addEventListener("click", downloadJson);
  elements.downloadMdBtn.addEventListener("click", downloadMarkdown);
}

function checkHashNavigation() {
  const hash = window.location.hash;
  if (hash === "#history") showHistory();
  else if (hash === "#results" && currentResult) showResults();
}

// Scanning
async function handleScan(e) {
  e.preventDefault();

  const url = elements.urlInput.value.trim();
  if (!url) return;

  showLoading();

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    if (!response.ok || !data.ok) {
      throw new Error(data.error?.code || "UNKNOWN_ERROR");
    }

    currentResult = data;
    saveToHistory(data);
    renderResults(data);
    showResults();
  } catch (err) {
    showError(ERROR_MESSAGES[err.message] || err.message || "점검 중 오류가 발생했습니다.");
  } finally {
    hideLoading();
  }
}

function showLoading() {
  elements.loadingPanel.classList.add("show");
  elements.errorPanel.classList.remove("show");
  elements.submitButton.disabled = true;

  let msgIndex = 0;
  elements.loadingText.textContent = LOADING_MESSAGES[0];
  loadingInterval = setInterval(() => {
    msgIndex = (msgIndex + 1) % LOADING_MESSAGES.length;
    elements.loadingText.textContent = LOADING_MESSAGES[msgIndex];
  }, 2000);
}

function hideLoading() {
  elements.loadingPanel.classList.remove("show");
  elements.submitButton.disabled = false;
  if (loadingInterval) {
    clearInterval(loadingInterval);
    loadingInterval = null;
  }
}

function showError(message) {
  elements.errorPanel.textContent = message;
  elements.errorPanel.classList.add("show");
}

// Views
function showScanner() {
  elements.scannerSection.style.display = "block";
  elements.resultsSection.classList.remove("show");
  elements.historySection.classList.remove("show");
  window.location.hash = "";
}

function showResults() {
  elements.scannerSection.style.display = "none";
  elements.resultsSection.classList.add("show");
  elements.historySection.classList.remove("show");
  window.location.hash = "results";
  window.scrollTo(0, 0);
}

function showHistory() {
  elements.scannerSection.style.display = "none";
  elements.resultsSection.classList.remove("show");
  elements.historySection.classList.add("show");
  window.location.hash = "history";
  renderHistory();
}

// Render Results
function renderResults(data) {
  // Extract data from API response
  const summary = data.summary || {};
  const target = data.target || {};
  const evidence = data.evidence || {};
  const findings = data.findings || [];
  const checks = data.checks || [];

  const score = summary.score ?? 0;
  const grade = summary.grade || "-";
  const riskLevel = summary.riskLevel || "-";

  // URL and meta
  if (elements.resultUrl) {
    elements.resultUrl.textContent = target.hostname || target.finalUrl || "";
  }
  if (elements.resultMeta) {
    elements.resultMeta.textContent = `${target.finalUrl || ""} • ${new Date(target.scannedAt || Date.now()).toLocaleString("ko-KR")}`;
  }

  // Score ring animation
  const circumference = 2 * Math.PI * 42;
  const offset = circumference - (score / 100) * circumference;
  elements.scoreRingProgress.style.strokeDashoffset = offset;

  // Use gradient for score ring, but change based on grade for accessibility
  const gradeColor = getGradeColor(grade);
  // Keep using gradient, but update gradient stops dynamically would be complex
  // So we'll use the defined gradient in SVG

  // Animate score number
  animateNumber(elements.scoreNumber, score);

  // Grade badge
  elements.scoreGrade.textContent = grade;
  elements.scoreGrade.className = `score-grade ${getGradeClass(grade)}`;

  // Risk badge
  if (elements.riskBadge) {
    elements.riskBadge.textContent = `위험도: ${riskLevel}`;
    elements.riskBadge.className = `risk-badge ${getRiskClass(riskLevel)}`;
  }

  // Summary
  elements.summaryHeadline.textContent = summary.headline || "";
  elements.summaryBody.innerHTML = generateSummaryBody(summary, findings);

  // Stats
  if (elements.statPasses) elements.statPasses.textContent = summary.passes ?? 0;
  if (elements.statWarnings) elements.statWarnings.textContent = summary.warnings ?? 0;
  if (elements.statFailures) elements.statFailures.textContent = summary.failures ?? 0;

  // Actions (generate from findings)
  renderActions(findings);

  // Finding filters
  renderFindingFilters();

  // Findings
  renderFindings(findings);

  // Checks
  renderChecks(checks);

  // Redirect timeline
  renderRedirects(evidence.redirectChain);

  // Headers
  renderHeaders(evidence.finalHeaders);

  // TLS
  renderTLS(evidence.tls);

  // Cookies
  renderCookies(evidence.cookies);
}

function generateSummaryBody(summary, findings) {
  const counts = summary.counts || {};
  const parts = [];

  if (counts.critical > 0) parts.push(`<span class="text-danger">치명 ${counts.critical}개</span>`);
  if (counts.high > 0) parts.push(`<span class="text-warning">높음 ${counts.high}개</span>`);
  if (counts.medium > 0) parts.push(`<span class="text-muted">중간 ${counts.medium}개</span>`);

  if (parts.length > 0) {
    return `발견된 문제: ${parts.join(", ")}`;
  }
  return "공개적으로 확인 가능한 기본 보안 항목은 양호합니다.";
}

function getGradeClass(grade) {
  if (grade === "A" || grade === "A+") return "excellent";
  if (grade === "B" || grade === "B+") return "good";
  if (grade === "C" || grade === "C+") return "warning";
  return "danger";
}

function getGradeColor(grade) {
  if (grade === "A" || grade === "A+") return "#16a34a";
  if (grade === "B" || grade === "B+") return "#2563eb";
  if (grade === "C" || grade === "C+") return "#ca8a04";
  return "#dc2626";
}

function getRiskClass(risk) {
  if (risk === "Low") return "low";
  if (risk === "Moderate") return "moderate";
  if (risk === "High") return "high";
  return "critical";
}

function animateNumber(element, target) {
  if (!element) return;
  const targetNum = Number(target) || 0;
  let current = 0;
  const duration = 800;
  const step = targetNum / (duration / 16);

  const animate = () => {
    current += step;
    if (current >= targetNum) {
      element.textContent = targetNum;
    } else {
      element.textContent = Math.floor(current);
      requestAnimationFrame(animate);
    }
  };
  animate();
}

function renderActions(findings) {
  if (!elements.actionsList) return;

  // Generate action items from findings
  const urgentFindings = findings.filter(f => f.severity === "critical" || f.severity === "high");
  const otherFindings = findings.filter(f => f.severity === "medium" || f.severity === "low");

  if (!findings.length) {
    elements.actionsList.innerHTML = `<div class="empty-state-inline">모든 보안 점검 항목이 양호합니다.</div>`;
    return;
  }

  let html = "";

  if (urgentFindings.length > 0) {
    html += `<div class="action-group">
      <div class="action-group-title urgent">즉시 조치 필요</div>
      ${urgentFindings.slice(0, 5).map((f, i) => `
        <div class="action-item urgent">
          <span class="action-num">${i + 1}</span>
          <div class="action-content">
            <div class="action-title">${f.title}</div>
            <div class="action-desc">${f.summary || ""}</div>
          </div>
        </div>
      `).join("")}
    </div>`;
  }

  if (otherFindings.length > 0) {
    html += `<div class="action-group">
      <div class="action-group-title">권장 개선 사항</div>
      ${otherFindings.slice(0, 5).map((f, i) => `
        <div class="action-item">
          <span class="action-num">${urgentFindings.length + i + 1}</span>
          <div class="action-content">
            <div class="action-title">${f.title}</div>
            <div class="action-desc">${f.summary || ""}</div>
          </div>
        </div>
      `).join("")}
    </div>`;
  }

  elements.actionsList.innerHTML = html;
}

function renderFindingFilters() {
  if (!elements.findingsFilters) return;

  elements.findingsFilters.innerHTML = FINDING_FILTERS.map(filter => `
    <button type="button" class="filter-btn ${filter.id === currentFilter ? "active" : ""}" data-filter="${filter.id}">
      ${filter.label}
    </button>
  `).join("");

  elements.findingsFilters.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      currentFilter = btn.dataset.filter;
      renderFindingFilters();
      renderFindings(currentResult?.findings || []);
    });
  });
}

function renderFindings(findings) {
  if (!elements.findingsList) return;

  if (!findings || !findings.length) {
    elements.findingsList.innerHTML = `<div class="empty-state-inline">발견된 문제가 없습니다.</div>`;
    return;
  }

  const filtered = currentFilter === "all"
    ? findings
    : findings.filter(f => f.severity === currentFilter);

  if (!filtered.length) {
    elements.findingsList.innerHTML = `<div class="empty-state-inline">해당 필터에 맞는 항목이 없습니다.</div>`;
    return;
  }

  elements.findingsList.innerHTML = filtered.map(finding => `
    <div class="finding-card ${finding.severity}">
      <div class="finding-header">
        <span class="finding-title">${finding.title}</span>
        <span class="finding-badge ${finding.severity}">${severityLabels[finding.severity] || finding.severity}</span>
      </div>
      <div class="finding-desc">${finding.summary || ""}</div>
      ${finding.evidence ? `<div class="finding-evidence">${finding.evidence}</div>` : ""}
    </div>
  `).join("");
}

function renderChecks(checks) {
  if (!elements.checksGrid || !checks || !checks.length) return;

  elements.checksGrid.innerHTML = checks.map(check => {
    const statusClass = check.status === "pass" ? "pass" : check.status === "warn" ? "warn" : check.status === "fail" ? "fail" : "na";
    const statusIcon = check.status === "pass" ? "✓" : check.status === "warn" ? "!" : check.status === "fail" ? "✗" : "-";

    return `
      <div class="check-card ${statusClass}">
        <div class="check-status ${statusClass}">${statusIcon}</div>
        <div class="check-info">
          <div class="check-label">${check.label}</div>
          <div class="check-detail">${check.detail || ""}</div>
        </div>
      </div>
    `;
  }).join("");
}

function renderRedirects(chain) {
  if (!elements.redirectTimeline) return;

  if (!chain || !chain.length) {
    elements.redirectTimeline.innerHTML = `<div class="empty-state-inline">리다이렉트가 없습니다.</div>`;
    return;
  }

  elements.redirectTimeline.innerHTML = chain.map((item, i) => `
    <div class="redirect-item">
      <div class="redirect-num">${i + 1}</div>
      <div class="redirect-info">
        <div class="redirect-url">${item.url}</div>
        <div class="redirect-status">${item.statusCode || ""} ${item.location ? `→ ${item.location}` : ""}</div>
      </div>
    </div>
  `).join("");
}

function renderHeaders(headers) {
  if (!elements.headersBlock) return;

  if (!headers || !Object.keys(headers).length) {
    elements.headersBlock.innerHTML = `<div class="empty-state-inline">헤더 정보가 없습니다.</div>`;
    return;
  }

  // Security-relevant headers first
  const securityHeaders = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"];
  const sorted = Object.entries(headers).sort((a, b) => {
    const aIdx = securityHeaders.indexOf(a[0].toLowerCase());
    const bIdx = securityHeaders.indexOf(b[0].toLowerCase());
    if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
    if (aIdx !== -1) return -1;
    if (bIdx !== -1) return 1;
    return a[0].localeCompare(b[0]);
  });

  elements.headersBlock.innerHTML = sorted.slice(0, 20).map(([name, value]) => `
    <div class="header-item">
      <div class="header-name">${name}</div>
      <div class="header-value">${Array.isArray(value) ? value.join(", ") : value}</div>
    </div>
  `).join("");
}

function renderTLS(tls) {
  if (!elements.tlsCard) return;

  if (!tls) {
    elements.tlsCard.innerHTML = `<div class="empty-state-inline">TLS 정보가 없습니다.</div>`;
    return;
  }

  elements.tlsCard.innerHTML = `
    <div class="tls-grid">
      <div class="tls-item">
        <div class="tls-label">프로토콜</div>
        <div class="tls-value">${tls.protocol || "-"}</div>
      </div>
      <div class="tls-item">
        <div class="tls-label">암호화</div>
        <div class="tls-value">${tls.cipher || "-"}</div>
      </div>
      <div class="tls-item">
        <div class="tls-label">발급자</div>
        <div class="tls-value">${tls.issuer || "-"}</div>
      </div>
      <div class="tls-item">
        <div class="tls-label">대상</div>
        <div class="tls-value">${tls.subject || "-"}</div>
      </div>
      <div class="tls-item">
        <div class="tls-label">유효 기간</div>
        <div class="tls-value">${tls.validFrom ? new Date(tls.validFrom).toLocaleDateString("ko-KR") : "-"} ~ ${tls.validTo ? new Date(tls.validTo).toLocaleDateString("ko-KR") : "-"}</div>
      </div>
      <div class="tls-item">
        <div class="tls-label">상태</div>
        <div class="tls-value ${tls.authorized ? "text-success" : "text-danger"}">${tls.authorized ? "유효" : (tls.authorizationError || "검증 실패")}</div>
      </div>
    </div>
  `;
}

function renderCookies(cookies) {
  if (!elements.cookiesCard) return;

  if (!cookies || !cookies.length) {
    elements.cookiesCard.innerHTML = `<div class="empty-state-inline">쿠키가 없습니다.</div>`;
    return;
  }

  elements.cookiesCard.innerHTML = cookies.map(cookie => {
    const flags = [];
    flags.push({ text: "Secure", ok: cookie.secure });
    flags.push({ text: "HttpOnly", ok: cookie.httpOnly });
    flags.push({ text: `SameSite=${cookie.sameSite || "없음"}`, ok: !!cookie.sameSite });

    return `
      <div class="cookie-item">
        <div class="cookie-name">${cookie.name}</div>
        <div class="cookie-flags">
          ${flags.map(f => `<span class="cookie-flag ${f.ok ? "ok" : "bad"}">${f.text}</span>`).join("")}
        </div>
      </div>
    `;
  }).join("");
}

// History
function getHistory() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
  } catch {
    return [];
  }
}

function saveToHistory(data) {
  const history = getHistory();
  const target = data.target || {};
  const summary = data.summary || {};

  const entry = {
    id: Date.now(),
    url: target.finalUrl || target.normalized || "",
    hostname: target.hostname || "",
    score: summary.score ?? 0,
    grade: summary.grade || "-",
    riskLevel: summary.riskLevel || "-",
    timestamp: new Date().toISOString(),
    data
  };

  history.unshift(entry);
  if (history.length > MAX_HISTORY_ITEMS) history.pop();

  localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
}

function renderHistory() {
  const history = getHistory();

  if (!history.length) {
    elements.historyGrid.innerHTML = "";
    elements.historyEmpty.classList.remove("hidden");
    return;
  }

  elements.historyEmpty.classList.add("hidden");
  elements.historyGrid.innerHTML = history.map(entry => {
    const gradeClass = getGradeClass(entry.grade);
    const date = new Date(entry.timestamp).toLocaleString("ko-KR", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });

    return `
      <div class="history-card" data-id="${entry.id}">
        <div class="history-score ${gradeClass}">${entry.score}</div>
        <div class="history-info">
          <div class="history-url">${entry.hostname || new URL(entry.url).hostname}</div>
          <div class="history-meta">${date} • 등급 ${entry.grade}</div>
        </div>
      </div>
    `;
  }).join("");

  elements.historyGrid.querySelectorAll(".history-card").forEach(card => {
    card.addEventListener("click", () => {
      const entry = history.find(h => h.id === parseInt(card.dataset.id));
      if (entry) {
        currentResult = entry.data;
        renderResults(entry.data);
        showResults();
      }
    });
  });
}

function clearHistory() {
  if (confirm("모든 점검 기록을 삭제하시겠습니까?")) {
    localStorage.removeItem(STORAGE_KEY);
    renderHistory();
  }
}

// Export functions
function copySummary() {
  if (!currentResult) return;
  const target = currentResult.target || {};
  const summary = currentResult.summary || {};

  const text = `[SiteGuard 보안 점검 결과]
URL: ${target.finalUrl || ""}
점수: ${summary.score ?? 0}/100 (등급 ${summary.grade || "-"})
위험도: ${summary.riskLevel || "-"}
${summary.headline || ""}`;

  navigator.clipboard.writeText(text).then(() => {
    showToast("요약이 복사되었습니다");
  });
}

function copyJson() {
  if (!currentResult) return;
  navigator.clipboard.writeText(JSON.stringify(currentResult, null, 2)).then(() => {
    showToast("JSON이 복사되었습니다");
  });
}

function downloadJson() {
  if (!currentResult) return;
  const target = currentResult.target || {};
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: "application/json" });
  downloadBlob(blob, `siteguard-${target.hostname || "result"}-${Date.now()}.json`);
}

function downloadMarkdown() {
  if (!currentResult) return;
  const md = generateMarkdown(currentResult);
  const target = currentResult.target || {};
  const blob = new Blob([md], { type: "text/markdown" });
  downloadBlob(blob, `siteguard-${target.hostname || "result"}-${Date.now()}.md`);
}

function generateMarkdown(data) {
  const target = data.target || {};
  const summary = data.summary || {};
  const findings = data.findings || [];

  let md = `# SiteGuard 보안 점검 결과\n\n`;
  md += `- **URL**: ${target.finalUrl || ""}\n`;
  md += `- **점수**: ${summary.score ?? 0}/100 (등급 ${summary.grade || "-"})\n`;
  md += `- **위험도**: ${summary.riskLevel || "-"}\n`;
  md += `- **점검 일시**: ${new Date(target.scannedAt || Date.now()).toLocaleString("ko-KR")}\n\n`;

  if (summary.headline) {
    md += `## 요약\n\n${summary.headline}\n\n`;
  }

  if (findings.length) {
    md += `## 발견 항목\n\n`;
    findings.forEach(f => {
      md += `- **[${severityLabels[f.severity]}]** ${f.title}: ${f.summary || ""}\n`;
    });
    md += "\n";
  }

  return md;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function showToast(message) {
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("hide");
    setTimeout(() => toast.remove(), 300);
  }, 2000);
}
