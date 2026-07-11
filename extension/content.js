/**
 * content.js — Injected into Gmail AND Outlook Web tabs.
 *
 * Responsibilities:
 *  1. Detect which email client is active (Gmail / Outlook)
 *  2. Respond to EXTRACT_EMAIL messages from the background service worker
 *  3. Watch the DOM for new email opens (MutationObserver) and notify
 *     background so it can auto-scan
 *
 * Both Gmail and Outlook use dynamic SPAs, so multiple fallback selectors
 * are tried for each field. On failure a structured error is returned.
 */

(function () {
  "use strict";

  // ── Platform detection ───────────────────────────────────────────
  const HOST = location.hostname;
  const IS_GMAIL   = HOST === "mail.google.com";
  const IS_OUTLOOK = HOST === "outlook.live.com"
                  || HOST === "outlook.office.com"
                  || HOST === "outlook.office365.com";

  // ── Gmail selectors ───────────────────────────────────────────────
  const GMAIL_SUBJECT = [
    "h2.hP",
    ".hP",
    "[data-legacy-thread-id] h2",
    ".ha h2",
    ".nH .g3",
  ];
  const GMAIL_BODY = [
    ".a3s.aiL",
    ".a3s",
    ".ii.gt .a3s",
    ".ii.gt div[dir]",
    ".nH .gs .ii.gt",
  ];
  const GMAIL_SENDER_EMAIL = [".gD", "[data-hovercard-id]"];
  const GMAIL_SENDER_NAME  = [".go", ".gD"];

  // ── Outlook Web selectors ─────────────────────────────────────────
  // Outlook Web is a React SPA — aria-label / role attributes are the
  // most stable hooks across Outlook's frequent UI updates.
  const OUTLOOK_SUBJECT = [
    // New Outlook (2023+)
    "[data-testid='ConversationCard-subject']",
    "div[role='heading'][aria-level='1']",
    "span[role='heading']",
    // OWA / Outlook 365
    "div.allowTextSelection[aria-label]",
    "[aria-label='Message subject']",
    // Fallback: first heading in reading pane
    "[aria-label='Reading Pane'] h1",
    "[aria-label='Reading Pane'] h2",
    // Generic: look for subject-like role headings
    "h1[tabindex]",
    "h2[tabindex]",
  ];
  const OUTLOOK_BODY = [
    // Reading pane document body
    "[role='document']",
    "div[aria-label='Message body']",
    // OWA
    ".ReadingPaneContent div[role='document']",
    ".customScrollBar [role='document']",
    // Broader fallback
    "[aria-label='Reading Pane'] [role='document']",
    "[aria-label='Reading Pane'] div[dir]",
  ];
  const OUTLOOK_SENDER = [
    "[aria-label^='From']",
    "[data-testid='SenderCard']",
    "[aria-label*='sender']",
    "button[aria-label*='@']",
    "span[title*='@']",
  ];

  // ── Helpers ───────────────────────────────────────────────────────
  function trySelectors(selectors) {
    for (const sel of selectors) {
      try {
        const el = document.querySelector(sel);
        if (el) {
          const text = (el.innerText || el.textContent || "").trim();
          if (text.length > 0) return text;
        }
      } catch (_) {}
    }
    return null;
  }

  // ── Gmail extractors ──────────────────────────────────────────────
  function gmailSubject() {
    const fromDOM = trySelectors(GMAIL_SUBJECT);
    if (fromDOM) return fromDOM;
    return document.title.replace(/\s*[-–]\s*Gmail\s*$/i, "").trim() || null;
  }

  function gmailBody() {
    return trySelectors(GMAIL_BODY);
  }

  function gmailSender() {
    for (const sel of GMAIL_SENDER_EMAIL) {
      try {
        const el = document.querySelector(sel);
        if (el) {
          const email = el.getAttribute("email")
                     || el.getAttribute("data-hovercard-id") || "";
          const name  = el.getAttribute("name")
                     || trySelectors(GMAIL_SENDER_NAME) || "";
          if (email) return name ? `${name} <${email}>` : email;
        }
      } catch (_) {}
    }
    return trySelectors(GMAIL_SENDER_NAME) || "";
  }

  // ── Outlook extractors ────────────────────────────────────────────
  function outlookSubject() {
    const fromDOM = trySelectors(OUTLOOK_SUBJECT);
    if (fromDOM) return fromDOM;
    // Fallback: strip "- Outlook" or "| Outlook" from page title
    return document.title
      .replace(/\s*[-–|]\s*Outlook\s*$/i, "")
      .replace(/\s*[-–|]\s*Microsoft Outlook\s*$/i, "")
      .trim() || null;
  }

  function outlookBody() {
    return trySelectors(OUTLOOK_BODY);
  }

  function outlookSender() {
    // Try aria-label based sender buttons (most reliable)
    for (const sel of OUTLOOK_SENDER) {
      try {
        const el = document.querySelector(sel);
        if (el) {
          const label = el.getAttribute("aria-label")
                     || el.getAttribute("title")
                     || el.innerText || "";
          if (label.includes("@") || label.toLowerCase().startsWith("from")) {
            // Strip "From: " prefix if present
            return label.replace(/^from[:\s]*/i, "").trim();
          }
        }
      } catch (_) {}
    }
    return "";
  }

  // ── Dispatch to correct platform ──────────────────────────────────
  function extractEmail() {
    if (IS_GMAIL) {
      return {
        subject: gmailSubject(),
        body:    gmailBody(),
        sender:  gmailSender(),
      };
    }
    if (IS_OUTLOOK) {
      return {
        subject: outlookSubject(),
        body:    outlookBody(),
        sender:  outlookSender(),
      };
    }
    return { subject: null, body: null, sender: "" };
  }

  // ── Message listener (from background.js) ───────────────────────
  chrome.runtime.onMessage.addListener(function (message, _sender, sendResponse) {
    if (message.type !== "EXTRACT_EMAIL") return;

    try {
      const { subject, body, sender } = extractEmail();

      if (!subject && !body) {
        const platform = IS_OUTLOOK ? "Outlook" : "Gmail";
        sendResponse({
          ok: false,
          error:
            `Couldn't read this email. Make sure an email is open in the reading pane. ` +
            `If ${platform} recently updated its UI, the DOM selectors may need updating.`,
        });
        return;
      }

      sendResponse({ ok: true, subject: subject || "", body: body || "", sender });
    } catch (err) {
      sendResponse({
        ok: false,
        error: "Unexpected error reading email: " + (err.message || String(err)),
      });
    }

    return true;
  });

  // ── MutationObserver — detect when a new email opens ─────────────
  // Both Gmail and Outlook use pushState navigation.
  // We detect email changes by watching for subject changes.

  let lastSubject = "";
  let debounceTimer = null;

  function onPossibleEmailChange() {
    const { subject } = extractEmail();
    if (subject && subject !== lastSubject) {
      lastSubject = subject;
      chrome.runtime.sendMessage({ type: "EMAIL_OPENED" }).catch(() => {});
    }
  }

  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(onPossibleEmailChange, 600);
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Also poll URL changes (both Gmail and Outlook use pushState/replaceState)
  let lastHref = location.href;
  setInterval(() => {
    if (location.href !== lastHref) {
      lastHref = location.href;
      setTimeout(onPossibleEmailChange, 800);
    }
  }, 500);
})();
