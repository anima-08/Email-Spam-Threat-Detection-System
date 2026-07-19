/**
 * popup.js — SpamShield v2 popup controller.
 *
 * Features:
 *  - On open: immediately load last result from storage (instant display)
 *  - Tab switching: Results ↔ History
 *  - Collapsible sections (sender, keywords, URLs)
 *  - User feedback (agree/wrong)
 *  - Copy report to clipboard
 *  - Backend health dot
 *  - Auto-scan badge from settings
 */

"use strict";

// ── DOM refs ──────────────────────────────────────────────────────
const $idle    = document.getElementById("state-idle");
const $loading = document.getElementById("state-loading");
const $error   = document.getElementById("state-error");
const $results = document.getElementById("state-results");

const $errorMsg   = document.getElementById("error-message");
const $backendDot = document.getElementById("backend-dot");
const $autoScanBadge = document.getElementById("auto-scan-badge");

const $verdictBanner = document.getElementById("verdict-banner");
const $verdictIcon   = document.getElementById("verdict-icon");
const $verdictLabel  = document.getElementById("verdict-label");
const $riskBadge     = document.getElementById("risk-badge");
const $senderDisplay = document.getElementById("sender-display");

const $spamProb    = document.getElementById("spam-prob");
const $confidence  = document.getElementById("confidence");
const $threatScore = document.getElementById("threat-score");
const $meterFill   = document.getElementById("meter-fill");

const $senderSection     = document.getElementById("sender-section");
const $senderFlagCount   = document.getElementById("sender-flag-count");
const $senderEmailDisplay = document.getElementById("sender-email-display");
const $senderFlagsList   = document.getElementById("sender-flags-list");

const $keywordsSection = document.getElementById("keywords-section");
const $kwCount         = document.getElementById("kw-count");
const $keywordsChips   = document.getElementById("keywords-chips");
const $emailPreview    = document.getElementById("email-preview");

const $urlsSection = document.getElementById("urls-section");
const $urlCount    = document.getElementById("url-count");
const $urlsList    = document.getElementById("urls-list");

const $cleanCard     = document.getElementById("clean-card");
const $feedbackRow   = document.getElementById("feedback-row");
const $feedbackThanks = document.getElementById("feedback-thanks");
const $btnAgree      = document.getElementById("btn-agree");
const $btnWrong      = document.getElementById("btn-wrong");

const $phishingSection = document.getElementById("phishing-section");
const $phishingCount   = document.getElementById("phishing-count");
const $phishingList    = document.getElementById("phishing-list");

const $explainSection  = document.getElementById("explain-section");
const $explainList     = document.getElementById("explain-list");

const $btnScanIdle = document.getElementById("btn-scan-idle");
const $btnRetry    = document.getElementById("btn-retry");
const $btnRescan   = document.getElementById("btn-rescan");
const $btnCopy     = document.getElementById("btn-copy");
const $btnSettings = document.getElementById("btn-settings");

const $historyEmpty  = document.getElementById("history-empty");
const $historyList   = document.getElementById("history-list");
const $historyFooter = document.getElementById("history-footer");
const $btnClearHistory = document.getElementById("btn-clear-history");
const $historyCount  = document.getElementById("history-count");

// ── State ────────────────────────────────────────────────────────
let currentResult = null;
let currentHistoryId = null;

// ── State machine ─────────────────────────────────────────────────
function showResultsState(name) {
  [$idle, $loading, $error, $results].forEach(el => el.classList.add("hidden"));
  if (name === "idle")    $idle.classList.remove("hidden");
  if (name === "loading") $loading.classList.remove("hidden");
  if (name === "error")   $error.classList.remove("hidden");
  if (name === "results") $results.classList.remove("hidden");
}

// ── Tab switching ─────────────────────────────────────────────────
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => {
      b.classList.remove("active");
      b.setAttribute("aria-selected", "false");
    });
    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");

    const target = btn.dataset.tab;
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
    document.getElementById("tab-" + target).classList.remove("hidden");

    if (target === "history") loadHistory();
  });
});

// ── Collapsibles ──────────────────────────────────────────────────
document.querySelectorAll(".collapsible-header").forEach(header => {
  header.addEventListener("click", () => {
    const targetId = header.dataset.target;
    const body = document.getElementById(targetId);
    const isOpen = header.getAttribute("aria-expanded") === "true";
    header.setAttribute("aria-expanded", String(!isOpen));
    body.classList.toggle("hidden", isOpen);
  });
});

// ── Backend health ────────────────────────────────────────────────
async function checkBackend() {
  try {
    const settings = await getSettings();
    const url = (settings.backendUrl || CONFIG.BACKEND_URL) + "/health";
    const r = await fetch(url, { signal: AbortSignal.timeout(2500) });
    const json = await r.json();
    $backendDot.classList.add("online");
    $backendDot.title = json.models_loaded
      ? "Backend online — models loaded ✓"
      : "Backend online but models NOT loaded (drop .pkl files into models/)";
  } catch (_) {
    $backendDot.classList.add("offline");
    $backendDot.title = "Backend offline — start the Flask server";
  }
}

async function getSettings() {
  return new Promise(resolve => {
    chrome.storage.sync.get(CONFIG.DEFAULTS, resolve);
  });
}

// ── Rendering ─────────────────────────────────────────────────────
const RISK_CLASS = { Low: "risk-low", Moderate: "risk-moderate", Medium: "risk-medium", High: "risk-high", Critical: "risk-critical" };

function renderResults(data, subject, body, sender, historyId) {
  currentResult  = { data, subject, body, sender };
  currentHistoryId = historyId || null;

  const isSpam = data.prediction === "Spam";
  const risk   = data.risk_level || "Low";

  // Verdict
  $verdictBanner.className = "verdict-banner " + (isSpam ? "spam" : "not-spam");
  $verdictIcon.textContent  = isSpam ? "🚨" : "✅";
  $verdictLabel.textContent = isSpam ? "Spam" : "Not Spam";

  // Risk badge
  $riskBadge.textContent = risk;
  $riskBadge.className   = "risk-badge " + (RISK_CLASS[risk] || "risk-low");

  // Sender display in banner
  $senderDisplay.textContent = data.sender_email
    ? "From: " + truncate(data.sender_email, 35)
    : "";

  // Metrics
  $spamProb.textContent   = pct(data.spam_probability);
  $confidence.textContent = pct(data.confidence);
  $threatScore.textContent = data.threat_score + " / 100";
  $meterFill.style.width  = Math.min(data.threat_score, 100) + "%";
  $meterFill.setAttribute("data-level", risk.toLowerCase());

  // Sender analysis
  const senderFlags = data.sender_flags || [];
  if (senderFlags.length > 0 || data.sender_score > 0) {
    $senderSection.classList.remove("hidden");
    $senderFlagCount.textContent = senderFlags.length + " flag" + (senderFlags.length !== 1 ? "s" : "");
    $senderEmailDisplay.textContent = data.sender_email || "(sender unknown)";
    $senderFlagsList.innerHTML = senderFlags.length
      ? senderFlags.map(f => `<li>${escHtml(f)}</li>`).join("")
      : "<li style='color:var(--text-muted)'>No reputation flags detected.</li>";
    if (senderFlags.length > 0) {
      // Auto-expand sender section if there are flags
      const header = $senderSection.querySelector(".collapsible-header");
      const body2  = document.getElementById("sender-body");
      header.setAttribute("aria-expanded", "true");
      body2.classList.remove("hidden");
    }
  } else {
    $senderSection.classList.add("hidden");
  }

  // Keywords
  const keywords = data.suspicious_keywords || [];
  if (keywords.length > 0) {
    $keywordsSection.classList.remove("hidden");
    $kwCount.textContent = keywords.length;
    $keywordsChips.innerHTML = keywords.map(kw => `<span class="kw-chip">${escHtml(kw)}</span>`).join("");
    const rawText = ((subject ? subject + " " : "") + (body || "")).slice(0, 280);
    $emailPreview.innerHTML = highlightKeywords(rawText, keywords);
  } else {
    $keywordsSection.classList.add("hidden");
  }

  // URLs
  const urls = data.urls || [];
  if (urls.length > 0) {
    $urlsSection.classList.remove("hidden");
    $urlCount.textContent = urls.length;
    $urlsList.innerHTML = urls.map(renderUrlItem).join("");
  } else {
    $urlsSection.classList.add("hidden");
  }

  // Phishing patterns
  const phishingPatterns = data.phishing_patterns || [];
  if (phishingPatterns.length > 0) {
    $phishingSection.classList.remove("hidden");
    $phishingCount.textContent = phishingPatterns.length;
    $phishingList.innerHTML = phishingPatterns.map(renderPhishingPattern).join("");
    // Auto-expand for High/Critical
    const topSeverity = phishingPatterns[0]?.severity;
    if (topSeverity === "High" || topSeverity === "Critical") {
      const hdr = $phishingSection.querySelector(".collapsible-header");
      hdr.setAttribute("aria-expanded", "true");
      document.getElementById("phishing-body").classList.remove("hidden");
    }
  } else {
    $phishingSection.classList.add("hidden");
  }

  // Explanation
  const explanation = data.explanation || [];
  if (explanation.length > 0) {
    $explainSection.classList.remove("hidden");
    $explainList.innerHTML = explanation
      .map(e => `<li class="explain-item">${escHtml(e)}</li>`)
      .join("");
  } else {
    $explainSection.classList.add("hidden");
  }

  // Clean card
  const hasSignals = senderFlags.length > 0 || keywords.length > 0
    || urls.length > 0 || phishingPatterns.length > 0;
  $cleanCard.classList.toggle("hidden", hasSignals);

  // Feedback
  $feedbackRow.classList.remove("hidden");
  $feedbackThanks.classList.add("hidden");
  $btnAgree.disabled = false;
  $btnWrong.disabled = false;

  showResultsState("results");
}

function renderPhishingPattern(p) {
  const sevClass = {
    "Critical": "phish-critical",
    "High":     "phish-high",
    "Medium":   "phish-medium",
    "Low":      "phish-low",
  }[p.severity] || "phish-low";
  const kws = (p.matched_keywords || []).map(k => `<span class="kw-chip">${escHtml(k)}</span>`).join("");
  return `
    <div class="phishing-pattern ${sevClass}">
      <div class="phishing-header">
        <span class="phishing-label">${escHtml(p.label)}</span>
        <span class="phishing-severity ${sevClass}-badge">${escHtml(p.severity)}</span>
      </div>
      <p class="phishing-explanation">${escHtml(p.explanation)}</p>
      ${kws ? `<div class="phishing-keywords">${kws}</div>` : ""}
    </div>`;
}

function renderUrlItem(u) {
  const cls = u.verdict === "Suspicious" ? "suspicious" : "safe";
  const reasons = (u.reasons && u.reasons.length > 0)
    ? u.reasons.map(r => "• " + escHtml(r)).join("<br>")
    : "";
  return `
    <li class="url-item ${cls}">
      <span class="url-text">${escHtml(u.url)}</span>
      <span class="url-verdict">${escHtml(u.verdict)}</span>
      ${reasons ? `<span class="url-reasons">${reasons}</span>` : ""}
    </li>`;
}

// ── History ───────────────────────────────────────────────────────
async function loadHistory() {
  const { history = [] } = await chrome.storage.local.get("history");

  if (history.length === 0) {
    $historyEmpty.classList.remove("hidden");
    $historyList.classList.add("hidden");
    $historyFooter.classList.add("hidden");
    return;
  }

  $historyEmpty.classList.add("hidden");
  $historyList.classList.remove("hidden");
  $historyFooter.classList.remove("hidden");
  $historyCount.textContent = history.length;
  $historyCount.classList.remove("hidden");

  $historyList.innerHTML = history.map(renderHistoryItem).join("");
}

function renderHistoryItem(item) {
  const isSpam = item.prediction === "Spam";
  const riskClass = RISK_CLASS[item.risk_level] || "risk-low";
  const timeAgo = formatTimeAgo(item.ts);
  const senderShort = item.sender ? truncate(item.sender, 30) : "";
  const feedbackHtml = item.feedback === "correct"
    ? '<span class="feedback-dot-correct">✓ Correct</span>'
    : item.feedback === "wrong"
    ? '<span class="feedback-dot-wrong">✗ Wrong</span>'
    : "";

  return `
    <div class="history-item">
      <span class="history-verdict-icon">${isSpam ? "🚨" : "✅"}</span>
      <div class="history-info">
        <div class="history-subject">${escHtml(item.subject || "(No subject)")}</div>
        <div class="history-meta">
          <span class="risk-badge ${riskClass}">${item.risk_level}</span>
          ${senderShort ? `<span class="history-sender">${escHtml(senderShort)}</span>` : ""}
          <span class="history-time">${timeAgo}</span>
        </div>
      </div>
      <div class="history-right">
        <span class="history-score">${item.threat_score}/100</span>
        ${feedbackHtml}
      </div>
    </div>`;
}

// ── Analysis flow ─────────────────────────────────────────────────
function runAnalysis() {
  showResultsState("loading");

  chrome.runtime.sendMessage({ type: "ANALYZE" }, function (response) {
    if (chrome.runtime.lastError) {
      showError("Communication error: " + chrome.runtime.lastError.message);
      return;
    }
    if (!response || !response.ok) {
      showError(response?.error || "Unknown error occurred.");
      return;
    }
    // Store history id (the most recent entry)
    chrome.storage.local.get("history", ({ history = [] }) => {
      const id = history.length > 0 ? history[0].id : null;
      renderResults(response.data, response.subject, response.body, response.sender, id);
    });
  });
}

function showError(msg) {
  $errorMsg.textContent = msg;
  showResultsState("error");
}

// ── Feedback ──────────────────────────────────────────────────────
function submitFeedback(type) {
  $btnAgree.disabled = true;
  $btnWrong.disabled = true;
  $feedbackThanks.classList.remove("hidden");

  if (currentHistoryId != null) {
    chrome.runtime.sendMessage({ type: "SAVE_FEEDBACK", id: currentHistoryId, feedback: type });
  }
}

$btnAgree.addEventListener("click", () => submitFeedback("correct"));
$btnWrong.addEventListener("click", () => submitFeedback("wrong"));

// ── Copy report ───────────────────────────────────────────────────
$btnCopy.addEventListener("click", () => {
  if (!currentResult) return;
  const { data, subject, sender } = currentResult;
  const lines = [
    "=== SpamShield Report ===",
    `Subject:     ${subject || "(none)"}`,
    `Sender:      ${sender || "(none)"}`,
    `Prediction:  ${data.prediction === "Spam" ? "SPAM" : "NOT SPAM"}`,
    `Spam Prob:   ${pct(data.spam_probability)}`,
    `Confidence:  ${pct(data.confidence)}`,
    `Threat Score:${data.threat_score}/100`,
    `Risk Level:  ${data.risk_level}`,
  ];
  if (data.phishing_patterns?.length) {
    lines.push("Phishing:    " + data.phishing_patterns.map(p => p.label).join("; "));
  }
  if (data.sender_flags?.length) {
    lines.push("Sender Flags:" + data.sender_flags.join("; "));
  }
  if (data.spam_signals?.length) {
    const topSigs = data.spam_signals.slice(0, 6).map(s => s.phrase);
    lines.push("Spam Signals:" + topSigs.join(", ") + (data.spam_signals.length > 6 ? "…" : ""));
  } else if (data.suspicious_keywords?.length) {
    lines.push("Keywords:    " + data.suspicious_keywords.join(", "));
  }
  if (data.urls?.length) {
    lines.push("URLs:        " + data.urls.map(u => `${u.url} [${u.verdict}]`).join(" | "));
  }
  if (data.explanation?.length) {
    lines.push("");
    lines.push("Why Flagged:");
    data.explanation.forEach(e => lines.push("  • " + e));
  }
  lines.push("");
  lines.push("Generated:   " + new Date().toLocaleString());
  navigator.clipboard.writeText(lines.join("\n")).then(() => {
    $btnCopy.textContent = "✅ Copied!";
    setTimeout(() => { $btnCopy.textContent = "📋 Copy Report"; }, 2000);
  });
});

// ── Clear history ─────────────────────────────────────────────────
$btnClearHistory.addEventListener("click", async () => {
  await chrome.storage.local.set({ history: [] });
  $historyCount.classList.add("hidden");
  loadHistory();
});

// ── Settings ──────────────────────────────────────────────────────
$btnSettings.addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

// ── Utilities ─────────────────────────────────────────────────────
function pct(val) {
  return val != null ? Math.round(val * 100) + "%" : "—";
}
function truncate(s, n) {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function formatTimeAgo(ts) {
  const diff = Date.now() - ts;
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return m + "m ago";
  const h = Math.floor(m / 60);
  if (h < 24) return h + "h ago";
  return Math.floor(h / 24) + "d ago";
}
function highlightKeywords(text, keywords) {
  if (!keywords || keywords.length === 0) return escHtml(text);
  const sorted = [...keywords].sort((a, b) => b.length - a.length);
  const pattern = new RegExp(
    "(" + sorted.map(kw => kw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")",
    "gi"
  );
  return text.split(pattern).map((part, i) =>
    i % 2 === 1 ? `<mark>${escHtml(part)}</mark>` : escHtml(part)
  ).join("");
}

// ── Init ──────────────────────────────────────────────────────────
async function init() {
  // Check auto-scan badge
  const settings = await getSettings();
  if (settings.autoScan) $autoScanBadge.classList.remove("hidden");

  // Backend health
  checkBackend();

  // Load last result instantly from storage (if auto-scan ran)
  const { lastResult } = await chrome.storage.local.get("lastResult");
  if (lastResult && lastResult.result) {
    const { result, subject, body, sender } = lastResult;
    const { history = [] } = await chrome.storage.local.get("history");
    const id = history.length > 0 ? history[0].id : null;
    renderResults(result, subject, body, sender, id);

    // Update history badge
    if (history.length > 0) {
      $historyCount.textContent = history.length;
      $historyCount.classList.remove("hidden");
    }
  } else {
    showResultsState("idle");
  }
}

// ── Event bindings ────────────────────────────────────────────────
$btnScanIdle.addEventListener("click", runAnalysis);
$btnRetry.addEventListener("click", runAnalysis);
$btnRescan.addEventListener("click", runAnalysis);

init();
