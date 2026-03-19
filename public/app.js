const STORAGE_KEY = "siteguard:scan-snapshots:v2";
const MAX_HISTORY_ITEMS = 8;

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
let loadingInterval = null;

// DOM Elements
const elements = {};

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  cacheElements();
  setupEventListeners();
  trackVisit();
  renderHistory();
  checkHashNavigation();
});

function trackVisit() {
  fetch("/api/metrics/visit", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      path: window.location.pathname
    }),
    credentials: "same-origin",
    keepalive: true
  }).catch(() => {});
}

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
  elements.decisionTitle = document.getElementById("decision-title");
  elements.decisionSummary = document.getElementById("decision-summary");
  elements.deployBadge = document.getElementById("deploy-badge");
  elements.focusBadge = document.getElementById("focus-badge");
  elements.priorityImmediate = document.getElementById("priority-immediate");
  elements.priorityPredeploy = document.getElementById("priority-predeploy");
  elements.priorityStrengths = document.getElementById("priority-strengths");
  elements.priorityEvidence = document.getElementById("priority-evidence");
  elements.summaryHeadline = document.getElementById("summary-headline");
  elements.summaryBody = document.getElementById("summary-body");
  elements.actionsCaption = document.getElementById("actions-caption");

  elements.statPasses = document.getElementById("stat-passes");
  elements.statWarnings = document.getElementById("stat-warnings");
  elements.statFailures = document.getElementById("stat-failures");

  elements.actionsList = document.getElementById("actions-list");
  elements.findingsList = document.getElementById("findings-list");
  elements.strengthsList = document.getElementById("strengths-list");
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
  const summary = data.summary || {};
  const target = data.target || {};
  const evidence = data.evidence || {};
  const findings = sortFindingsBySeverity(data.findings || []);
  const checks = data.checks || [];
  const findingCounts = countFindings(findings);
  const strengths = getStrengthChecks(checks);
  const decision = getDeploymentDecision(summary, findingCounts);
  const primaryFocus = getPrimaryFocus(findings);

  const score = summary.score ?? 0;
  const grade = summary.grade || "-";
  const riskLevel = summary.riskLevel || "-";

  if (elements.resultUrl) {
    elements.resultUrl.textContent = target.hostname || target.finalUrl || "";
  }
  if (elements.resultMeta) {
    elements.resultMeta.textContent = `${target.finalUrl || ""} • ${new Date(target.scannedAt || Date.now()).toLocaleString("ko-KR")}`;
  }

  const circumference = 2 * Math.PI * 42;
  const offset = circumference - (score / 100) * circumference;
  elements.scoreRingProgress.style.strokeDashoffset = offset;

  animateNumber(elements.scoreNumber, score);

  elements.scoreGrade.textContent = grade;
  elements.scoreGrade.className = `score-grade ${getGradeClass(grade)}`;

  if (elements.riskBadge) {
    elements.riskBadge.textContent = `위험도: ${riskLevel}`;
    elements.riskBadge.className = `risk-badge ${getRiskClass(riskLevel)}`;
  }

  renderDecision(decision, summary, findings, checks, strengths, primaryFocus);
  renderSnapshot(summary, findingCounts, checks);
  renderActions(findings, decision);
  renderStrengths(strengths);
  renderFindings(findings);
  renderChecks(checks);
  renderRedirects(evidence.redirectChain);
  renderHeaders(evidence.finalHeaders);
  renderTLS(evidence.tls);
  renderCookies(evidence.cookies);
}

function getGradeClass(grade) {
  if (grade === "A" || grade === "A+") return "excellent";
  if (grade === "B" || grade === "B+") return "good";
  if (grade === "C" || grade === "C+") return "warning";
  return "danger";
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

function sortFindingsBySeverity(findings) {
  const order = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
  };

  return [...findings].sort((left, right) => {
    const severityDelta = (order[left.severity] ?? 99) - (order[right.severity] ?? 99);
    if (severityDelta !== 0) {
      return severityDelta;
    }
    return String(left.title || "").localeCompare(String(right.title || ""), "ko");
  });
}

function countFindings(findings) {
  return findings.reduce((counts, finding) => {
    counts.total += 1;
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    return counts;
  }, {
    critical: 0,
    high: 0,
    low: 0,
    medium: 0,
    total: 0
  });
}

function getStrengthChecks(checks) {
  return checks.filter(check => check.status === "pass");
}

function getPrimaryFocus(findings) {
  const first = findings[0];
  if (!first) {
    return "양호";
  }

  return first.remediation?.title || first.title || "우선 확인 필요";
}

function getDeploymentDecision(summary, counts) {
  const urgent = (counts.critical || 0) + (counts.high || 0);
  const medium = counts.medium || 0;
  const risk = String(summary.riskLevel || "");
  const score = Number(summary.score || 0);

  if (counts.critical > 0 || urgent >= 3 || risk === "Critical" || risk === "High" || score < 50) {
    return {
      label: "배포 전 보완 필요",
      summary: "치명도 높은 항목이 남아 있어 공개 상태를 유지하기 전에 먼저 정리하는 편이 좋습니다.",
      title: "배포 전에 즉시 보완이 필요합니다",
      tone: "danger"
    };
  }

  if (urgent > 0 || medium >= 2 || risk === "Moderate" || score < 80) {
    return {
      label: "조건부 진행 가능",
      summary: "서비스는 동작할 수 있지만, 중요한 설정을 먼저 정리하면 운영 리스크를 크게 줄일 수 있습니다.",
      title: "중요한 항목부터 정리하면 더 안전해집니다",
      tone: "warning"
    };
  }

  return {
    label: "현재 상태 양호",
    summary: "공개적으로 확인 가능한 핵심 보안 항목은 대체로 잘 갖춰져 있습니다.",
    title: "현재 공개 상태는 대체로 안정적입니다",
    tone: "good"
  };
}

function renderDecision(decision, summary, findings, checks, strengths, primaryFocus) {
  if (elements.decisionTitle) {
    elements.decisionTitle.textContent = decision.title;
  }

  if (elements.decisionSummary) {
    elements.decisionSummary.textContent = buildDecisionNarrative(decision, findings, primaryFocus);
  }

  if (elements.deployBadge) {
    elements.deployBadge.textContent = decision.label;
    elements.deployBadge.className = `decision-tag ${decision.tone}`;
  }

  if (elements.focusBadge) {
    elements.focusBadge.textContent = findings.length ? `우선 확인: ${primaryFocus}` : "우선 확인 없음";
  }

  if (elements.priorityImmediate) {
    elements.priorityImmediate.textContent = `${(findings.filter(f => f.severity === "critical" || f.severity === "high")).length}건`;
  }

  if (elements.priorityPredeploy) {
    elements.priorityPredeploy.textContent = `${(findings.filter(f => f.severity === "medium")).length}건`;
  }

  if (elements.priorityStrengths) {
    elements.priorityStrengths.textContent = `${strengths.length}건`;
  }

  if (elements.priorityEvidence) {
    elements.priorityEvidence.textContent = `${checks.length}개`;
  }
}

function buildDecisionNarrative(decision, findings, primaryFocus) {
  if (!findings.length) {
    return decision.summary;
  }

  if (decision.tone === "good") {
    return `즉시 위험은 낮지만, ${primaryFocus} 항목은 다음 점검 전까지 정리해 두는 편이 좋습니다.`;
  }

  if (decision.tone === "warning") {
    return `가장 먼저 볼 항목은 ${primaryFocus}입니다. 영향이 큰 순서대로 정리하면 공개 상태를 더 안정적으로 유지할 수 있습니다.`;
  }

  return `가장 먼저 볼 항목은 ${primaryFocus}입니다. 이 항목부터 정리한 뒤 나머지 문제를 이어서 확인해 주세요.`;
}

function renderSnapshot(summary, counts, checks) {
  if (elements.statPasses) {
    elements.statPasses.textContent = summary.passes ?? checks.filter(check => check.status === "pass").length;
  }
  if (elements.statWarnings) {
    elements.statWarnings.textContent = summary.warnings ?? checks.filter(check => check.status === "warn").length;
  }
  if (elements.statFailures) {
    elements.statFailures.textContent = summary.failures ?? checks.filter(check => check.status === "fail").length;
  }

  if (elements.summaryHeadline) {
    elements.summaryHeadline.textContent = counts.total
      ? `문제 ${counts.total}건 발견`
      : "즉시 대응할 문제는 없습니다";
  }

  if (elements.summaryBody) {
    const parts = [];
    if (counts.critical) parts.push(`치명 ${counts.critical}건`);
    if (counts.high) parts.push(`높음 ${counts.high}건`);
    if (counts.medium) parts.push(`중간 ${counts.medium}건`);
    if (counts.low) parts.push(`낮음 ${counts.low}건`);
    elements.summaryBody.textContent = parts.length ? parts.join(" · ") : "공개적으로 확인 가능한 핵심 보안 항목은 양호합니다.";
  }
}

function getActionStep(finding) {
  return finding.remediation?.actions?.[0] || "해당 설정을 먼저 확인해 주세요.";
}

function getActionTitle(finding) {
  return finding.remediation?.title || finding.title || "우선 조치 필요";
}

function getActionTone(finding) {
  if (finding.severity === "critical" || finding.severity === "high") return "urgent";
  if (finding.severity === "medium") return "planned";
  return "later";
}

function renderActions(findings, decision) {
  if (!elements.actionsList) return;

  const actionFindings = findings.slice(0, 3);

  if (elements.actionsCaption) {
    elements.actionsCaption.textContent = findings.length
      ? "영향이 큰 순서대로 3개만 먼저 보여줍니다."
      : decision.label;
  }

  if (!actionFindings.length) {
    elements.actionsList.innerHTML = `<div class="empty-state-inline">즉시 진행할 조치는 많지 않습니다. 현재 상태를 유지하면서 정기 점검을 이어가면 됩니다.</div>`;
    return;
  }

  elements.actionsList.innerHTML = actionFindings.map((finding, index) => `
    <article class="action-plan ${getActionTone(finding)}">
      <div class="action-plan-top">
        <span class="action-num">${index + 1}</span>
        <span class="action-chip ${getActionTone(finding)}">${severityLabels[finding.severity] || "우선"}</span>
      </div>
      <div class="action-content">
        <h3 class="action-title">${escapeHtml(getActionTitle(finding))}</h3>
        <p class="action-desc">${escapeHtml(finding.remediation?.whyItMatters || finding.summary || "영향이 큰 항목부터 먼저 정리해 주세요.")}</p>
        <div class="action-detail-row">
          <div class="action-detail">
            <span class="action-detail-label">먼저 할 일</span>
            <strong>${escapeHtml(getActionStep(finding))}</strong>
          </div>
          <div class="action-detail subtle">
            <span class="action-detail-label">근거</span>
            <strong>${escapeHtml(finding.evidence || "세부 진단에서 확인 가능")}</strong>
          </div>
        </div>
      </div>
    </article>
  `).join("");
}

function renderStrengths(strengths) {
  if (!elements.strengthsList) return;

  if (!strengths.length) {
    elements.strengthsList.innerHTML = `<div class="empty-state-inline">이번 점검에서는 바로 강조할 강점이 많지 않습니다. 보안 헤더와 전송 보안부터 먼저 다듬어 보세요.</div>`;
    return;
  }

  elements.strengthsList.innerHTML = strengths.slice(0, 5).map((check) => `
    <article class="strength-card">
      <div class="strength-icon">✓</div>
      <div class="strength-content">
        <h3>${escapeHtml(check.label || "통과")}</h3>
        <p>${escapeHtml(check.detail || "핵심 항목이 정상적으로 확인되었습니다.")}</p>
      </div>
    </article>
  `).join("");
}

function buildFindingGroups(findings) {
  return [
    {
      id: "urgent",
      title: "지금 막아야 하는 문제",
      description: "치명도 높은 항목입니다. 먼저 손대면 위험을 가장 크게 줄일 수 있습니다.",
      items: findings.filter(finding => finding.severity === "critical" || finding.severity === "high")
    },
    {
      id: "planned",
      title: "이번 배포 전에 확인할 문제",
      description: "서비스는 동작할 수 있지만, 배포 전에 정리해 두는 편이 좋습니다.",
      items: findings.filter(finding => finding.severity === "medium")
    },
    {
      id: "later",
      title: "운영상 개선하면 좋은 항목",
      description: "즉시 위험은 낮지만, 운영 성숙도와 신뢰도를 높이는 데 도움이 됩니다.",
      items: findings.filter(finding => finding.severity === "low" || finding.severity === "info")
    }
  ];
}

function renderFindings(findings) {
  if (!elements.findingsList) return;

  if (!findings || !findings.length) {
    elements.findingsList.innerHTML = `<div class="empty-state-inline">발견된 문제가 없습니다.</div>`;
    return;
  }

  elements.findingsList.innerHTML = buildFindingGroups(findings).map((group) => `
    <section class="finding-group ${group.id}">
      <div class="finding-group-head">
        <div>
          <h3>${group.title}</h3>
          <p>${group.description}</p>
        </div>
        <span class="finding-group-count">${group.items.length}건</span>
      </div>
      ${group.items.length ? `
        <div class="finding-group-list">
          ${group.items.map((finding) => `
            <article class="finding-card ${finding.severity}">
              <div class="finding-header">
                <div>
                  <span class="finding-title">${escapeHtml(finding.title || "발견 항목")}</span>
                  <p class="finding-desc">${escapeHtml(finding.summary || "세부 진단에서 내용을 확인해 주세요.")}</p>
                </div>
                <span class="finding-badge ${finding.severity}">${severityLabels[finding.severity] || finding.severity}</span>
              </div>
              <div class="finding-grid">
                <div class="finding-detail">
                  <span class="finding-detail-label">권장 조치</span>
                  <strong>${escapeHtml(getActionStep(finding))}</strong>
                </div>
                <div class="finding-detail subtle">
                  <span class="finding-detail-label">근거</span>
                  <strong>${escapeHtml(finding.evidence || "세부 진단에서 확인 가능")}</strong>
                </div>
              </div>
            </article>
          `).join("")}
        </div>
      ` : `
        <div class="empty-state-inline">이 구간에 해당하는 항목은 없습니다.</div>
      `}
    </section>
  `).join("");
}

function renderChecks(checks) {
  if (!elements.checksGrid || !checks || !checks.length) return;

  const statusOrder = {
    fail: 0,
    warn: 1,
    pass: 2,
    na: 3
  };

  elements.checksGrid.innerHTML = [...checks].sort((left, right) => {
    const delta = (statusOrder[left.status] ?? 9) - (statusOrder[right.status] ?? 9);
    if (delta !== 0) {
      return delta;
    }
    return String(left.label || "").localeCompare(String(right.label || ""), "ko");
  }).map(check => {
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
      <div class="header-name">${escapeHtml(name)}</div>
      <div class="header-value">${escapeHtml(Array.isArray(value) ? value.join(", ") : value)}</div>
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
        <div class="cookie-name">${escapeHtml(cookie.name)}</div>
        <div class="cookie-flags">
          ${flags.map(f => `<span class="cookie-flag ${f.ok ? "ok" : "bad"}">${escapeHtml(f.text)}</span>`).join("")}
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

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
