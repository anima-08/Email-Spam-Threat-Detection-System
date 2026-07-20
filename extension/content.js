(function () {
  "use strict";

  const HOST = location.hostname;
  const IS_GMAIL   = HOST === "mail.google.com";
  const IS_OUTLOOK = HOST === "outlook.live.com"
                  || HOST === "outlook.office.com"
                  || HOST === "outlook.office365.com";

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

  const OUTLOOK_SUBJECT = [

    "[data-testid='ConversationCard-subject']",
    "div[role='heading'][aria-level='1']",
    "span[role='heading']",

    "div.allowTextSelection[aria-label]",
    "[aria-label='Message subject']",

    "[aria-label='Reading Pane'] h1",
    "[aria-label='Reading Pane'] h2",

    "h1[tabindex]",
    "h2[tabindex]",
  ];
  const OUTLOOK_BODY = [

    "[role='document']",
    "div[aria-label='Message body']",

    ".ReadingPaneContent div[role='document']",
    ".customScrollBar [role='document']",

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

  function outlookSubject() {
    const fromDOM = trySelectors(OUTLOOK_SUBJECT);
    if (fromDOM) return fromDOM;

    return document.title
      .replace(/\s*[-–|]\s*Outlook\s*$/i, "")
      .replace(/\s*[-–|]\s*Microsoft Outlook\s*$/i, "")
      .trim() || null;
  }

  function outlookBody() {
    return trySelectors(OUTLOOK_BODY);
  }

  function outlookSender() {

    for (const sel of OUTLOOK_SENDER) {
      try {
        const el = document.querySelector(sel);
        if (el) {
          const label = el.getAttribute("aria-label")
                     || el.getAttribute("title")
                     || el.innerText || "";
          if (label.includes("@") || label.toLowerCase().startsWith("from")) {

            return label.replace(/^from[:\s]*/i, "").trim();
          }
        }
      } catch (_) {}
    }
    return "";
  }

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

  let lastHref = location.href;
  setInterval(() => {
    if (location.href !== lastHref) {
      lastHref = location.href;
      setTimeout(onPossibleEmailChange, 800);
    }
  }, 500);
})();
