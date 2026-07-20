const CONFIG = {
  BACKEND_URL: "http://localhost:5000",
  DEFAULTS: {
    autoScan: true,
    notifications: true,
    spamThreshold: 0.50,
  },
  MAX_HISTORY: 20,
};

async function getSettings() {
  const stored = await chrome.storage.sync.get(CONFIG.DEFAULTS);
  return { ...CONFIG.DEFAULTS, ...stored };
}

const EMAIL_HOSTS = [
  "https://mail.google.com",
  "https://outlook.live.com",
  "https://outlook.office.com",
  "https://outlook.office365.com",
];

async function getActiveEmailTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab) throw new Error("No active tab found.");
  const isEmailTab = EMAIL_HOSTS.some(h => tab.url && tab.url.startsWith(h));
  if (!isEmailTab) {
    throw new Error(
      "Active tab is not Gmail or Outlook. Please open your email and try again."
    );
  }
  return tab;
}

function askContentScriptToExtract(tabId) {

  function trySend() {
    return new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(tabId, { type: "EXTRACT_EMAIL" }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(response);
        }
      });
    });
  }

  return trySend().catch(async (err) => {

    if (err.message && err.message.includes("Receiving end does not exist")) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId },
          files: ["content.js"],
        });

        await new Promise((r) => setTimeout(r, 300));
        return trySend();
      } catch (injectErr) {
        throw new Error(
          "Could not inject content script: " + injectErr.message +
          ". Try reloading the Gmail tab."
        );
      }
    }
    throw new Error(
      "Content script not ready. Reload the Gmail tab and try again. (" +
        err.message + ")"
    );
  });
}

async function callBackend(subject, body, sender) {
  const settings = await getSettings();
  const url = (settings.backendUrl || CONFIG.BACKEND_URL) + "/predict";

  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject, body, sender }),
    });
  } catch (_) {
    throw new Error(
      "Cannot reach the backend at " +
        (settings.backendUrl || CONFIG.BACKEND_URL) +
        ". Make sure the Flask server is running (python app.py)."
    );
  }

  if (!response.ok) {
    let errText = "";
    try { errText = (await response.json()).error || ""; }
    catch (_) { errText = await response.text(); }
    throw new Error("Backend returned " + response.status + ": " + errText);
  }

  return response.json();
}

async function appendToHistory(entry) {
  const { history = [] } = await chrome.storage.local.get("history");
  history.unshift(entry);               // newest first
  if (history.length > CONFIG.MAX_HISTORY) history.length = CONFIG.MAX_HISTORY;
  await chrome.storage.local.set({ history });
}

function maybeNotify(settings, prediction, riskLevel, subject) {
  if (!settings.notifications) return;
  if (riskLevel !== "High" && riskLevel !== "Critical") return;

  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: `⚠️ SpamShield — ${riskLevel} Risk Detected`,
    message:
      prediction === "Spam"
        ? `Spam detected: "${(subject || "").slice(0, 60)}"`
        : `Suspicious email: "${(subject || "").slice(0, 60)}"`,
    priority: 2,
  });
}

async function analyzeEmail(tabId) {
  const extraction = await askContentScriptToExtract(tabId);

  if (!extraction || !extraction.ok) {
    throw new Error(extraction?.error || "Failed to extract email.");
  }

  const { subject, body, sender } = extraction;
  if (!subject && !body) throw new Error("The email appears to be empty.");

  const data = await callBackend(subject, body, sender);
  return { data, subject, body, sender };
}

chrome.runtime.onMessage.addListener(function (message, _sender, sendResponse) {

  if (message.type === "ANALYZE") {
    (async () => {
      try {
        const tab = await getActiveEmailTab();
        const { data, subject, body, sender } = await analyzeEmail(tab.id);

        const settings = await getSettings();
        const threshold = settings.spamThreshold ?? CONFIG.DEFAULTS.spamThreshold;

        const adjustedPrediction =
          data.spam_probability >= threshold ? "Spam" : "Ham";

        const result = { ...data, prediction: adjustedPrediction };

        await chrome.storage.local.set({ lastResult: { result, subject, body, sender, ts: Date.now() } });

        await appendToHistory({
          id: Date.now(),
          subject: subject || "(No subject)",
          sender: sender || "",
          prediction: adjustedPrediction,
          risk_level: data.risk_level,
          threat_score: data.threat_score,
          spam_probability: data.spam_probability,
          ts: Date.now(),
          feedback: null,
        });

        maybeNotify(settings, adjustedPrediction, data.risk_level, subject);

        sendResponse({ ok: true, data: result, subject, body, sender });
      } catch (err) {
        sendResponse({ ok: false, error: err.message || String(err) });
      }
    })();
    return true;
  }

  if (message.type === "EMAIL_OPENED") {
    (async () => {
      try {
        const settings = await getSettings();
        if (!settings.autoScan) return;

        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const tab = tabs[0];
        const isEmailTab = EMAIL_HOSTS.some(h => tab?.url?.startsWith(h));
        if (!tab || !isEmailTab) return;

        await new Promise(r => setTimeout(r, 1000));

        const { data, subject, body, sender } = await analyzeEmail(tab.id);

        const threshold = settings.spamThreshold ?? CONFIG.DEFAULTS.spamThreshold;
        const adjustedPrediction = data.spam_probability >= threshold ? "Spam" : "Ham";
        const result = { ...data, prediction: adjustedPrediction };

        await chrome.storage.local.set({ lastResult: { result, subject, body, sender, ts: Date.now() } });

        await appendToHistory({
          id: Date.now(),
          subject: subject || "(No subject)",
          sender: sender || "",
          prediction: adjustedPrediction,
          risk_level: data.risk_level,
          threat_score: data.threat_score,
          spam_probability: data.spam_probability,
          ts: Date.now(),
          feedback: null,
        });

        maybeNotify(settings, adjustedPrediction, data.risk_level, subject);

        const badgeColors = { Low: "#22c55e", Medium: "#eab308", High: "#f97316", Critical: "#ef4444" };
        chrome.action.setBadgeText({ text: adjustedPrediction === "Spam" ? "!" : "" });
        chrome.action.setBadgeBackgroundColor({ color: badgeColors[data.risk_level] || "#6366f1" });

      } catch (_) {

      }
    })();
    return false;
  }

  if (message.type === "SAVE_FEEDBACK") {
    (async () => {
      const { id, feedback } = message;

      const { history = [] } = await chrome.storage.local.get("history");
      const idx = history.findIndex(h => h.id === id);
      if (idx !== -1) history[idx].feedback = feedback;
      await chrome.storage.local.set({ history });

      try {
        const { lastResult } = await chrome.storage.local.get("lastResult");
        if (lastResult) {
          const { subject, body, sender, result } = lastResult;

          const modelPrediction = result?.prediction ?? "Ham";
          let correctLabel;
          if (feedback === "correct") {
            correctLabel = modelPrediction;
          } else {
            correctLabel = modelPrediction === "Spam" ? "Ham" : "Spam";
          }

          const settings = await getSettings();
          const backendUrl = (settings.backendUrl || CONFIG.BACKEND_URL) + "/feedback";

          fetch(backendUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ subject, body, sender, correct_label: correctLabel }),
          })
            .then(r => r.json())
            .then(res => {
              if (res.retrain_triggered && res.retrain?.success) {
                console.info(
                  "[SpamShield] Model retrained! " + res.retrain.message
                );
              }
            })
            .catch(err => console.warn("[SpamShield] Feedback send failed:", err));
        }
      } catch (e) {
        console.warn("[SpamShield] Could not send feedback to backend:", e);
      }

      sendResponse({ ok: true });
    })();
    return true;
  }
});
