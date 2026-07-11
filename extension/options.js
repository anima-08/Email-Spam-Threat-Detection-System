/**
 * options.js — Settings page logic.
 * Reads/writes from chrome.storage.sync so settings survive browser restarts.
 */

"use strict";

const $backendUrl    = document.getElementById("backend-url");
const $thresholdSlider = document.getElementById("threshold-slider");
const $thresholdLabel  = document.getElementById("threshold-label");
const $autoScanToggle  = document.getElementById("auto-scan-toggle");
const $notifToggle     = document.getElementById("notifications-toggle");
const $btnTest         = document.getElementById("btn-test");
const $backendStatus   = document.getElementById("backend-status-msg");
const $btnSave         = document.getElementById("btn-save");
const $btnClearHistory = document.getElementById("btn-clear-history");
const $clearConfirm    = document.getElementById("clear-confirm");
const $toast           = document.getElementById("toast");

// ── Load saved settings ───────────────────────────────────────────
chrome.storage.sync.get(CONFIG.DEFAULTS, (stored) => {
  $backendUrl.value        = stored.backendUrl || CONFIG.BACKEND_URL;
  $autoScanToggle.checked  = stored.autoScan  ?? CONFIG.DEFAULTS.autoScan;
  $notifToggle.checked     = stored.notifications ?? CONFIG.DEFAULTS.notifications;

  const threshold = stored.spamThreshold ?? CONFIG.DEFAULTS.spamThreshold;
  const pct = Math.round(threshold * 100);
  $thresholdSlider.value = pct;
  $thresholdLabel.textContent = pct + "%";
});

// ── Slider live preview ───────────────────────────────────────────
$thresholdSlider.addEventListener("input", () => {
  $thresholdLabel.textContent = $thresholdSlider.value + "%";
});

// ── Test connection ───────────────────────────────────────────────
$btnTest.addEventListener("click", async () => {
  const url = $backendUrl.value.trim().replace(/\/$/, "");
  $backendStatus.textContent = "Testing…";
  $backendStatus.className   = "status-msg";
  try {
    const r    = await fetch(url + "/health", { signal: AbortSignal.timeout(3000) });
    const json = await r.json();
    if (json.models_loaded) {
      $backendStatus.textContent = "✓ Connected — models loaded and ready";
      $backendStatus.className   = "status-msg ok";
    } else {
      $backendStatus.textContent = "⚠ Connected but models not loaded — place .pkl files in models/";
      $backendStatus.className   = "status-msg err";
    }
  } catch (e) {
    $backendStatus.textContent = "✗ Cannot connect — is the Flask server running?";
    $backendStatus.className   = "status-msg err";
  }
});

// ── Save settings ─────────────────────────────────────────────────
$btnSave.addEventListener("click", () => {
  const settings = {
    backendUrl:       $backendUrl.value.trim().replace(/\/$/, "") || CONFIG.BACKEND_URL,
    autoScan:         $autoScanToggle.checked,
    notifications:    $notifToggle.checked,
    spamThreshold:    parseInt($thresholdSlider.value, 10) / 100,
  };

  chrome.storage.sync.set(settings, () => {
    showToast();
  });
});

// ── Clear history ─────────────────────────────────────────────────
$btnClearHistory.addEventListener("click", () => {
  chrome.storage.local.set({ history: [], lastResult: null }, () => {
    $clearConfirm.classList.remove("hidden");
    setTimeout(() => $clearConfirm.classList.add("hidden"), 2500);
  });
});

// ── Toast ─────────────────────────────────────────────────────────
function showToast() {
  $toast.classList.remove("hidden");
  setTimeout(() => $toast.classList.add("hidden"), 2200);
}
