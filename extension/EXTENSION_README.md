# SpamShield — Chrome Extension

A Manifest V3 Chrome extension that detects spam and phishing threats in Gmail emails in real time, powered by a trained Random Forest ML model served by a Flask backend.

---

## 1. Prerequisites

The Flask backend must be running before you use the extension.

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
python app.py
# → Server starts at http://localhost:5000
```

> **Important:** Place the 5 `.pkl` model files from your Colab notebook into `backend/models/` before starting the server:
> `spam_detector_model.pkl`, `feature_scaler.pkl`, `tfidf_vectorizer.pkl`,
> `feature_selector.pkl`, `pca_transformer.pkl`

---

## 2. Load the extension unpacked

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer mode** (toggle, top-right)
3. Click **Load unpacked**
4. Select the `extension/` folder (this folder)
5. The **SpamShield** extension should appear in your toolbar

---

## 3. How to use it

1. Go to [Gmail](https://mail.google.com) and open any email
2. Click the SpamShield icon in the Chrome toolbar
3. Click **Scan Email** — the extension extracts the subject & body, sends them to the backend, and displays the results:
   - **Spam / Ham** verdict with color coding
   - **Spam probability** and **confidence** percentages
   - **Threat score** (0–100) visual meter
   - **Risk level** badge: Low / Medium / High / Critical
   - **Suspicious keywords** highlighted inline in an email preview
   - **URLs detected** with heuristic reputation verdicts and reasons
4. Click **↺ Re-scan** to re-run analysis on the same email
5. The small colored dot in the popup header shows the **backend status**: green = online, red = offline

---

## 4. Changing the backend URL

When you deploy the Flask backend to a real server (Render, Railway, VPS, etc.):

Open `extension/config.js` and change the one line:

```js
// Before
BACKEND_URL: "http://localhost:5000",

// After
BACKEND_URL: "https://your-app.onrender.com",
```

Also update `manifest.json` → `host_permissions` to include your deployed URL:

```json
"host_permissions": [
  "https://mail.google.com/*",
  "https://your-app.onrender.com/*"
]
```

Then reload the extension on `chrome://extensions` (click the refresh icon).

---

## 5. Known limitations & things to double-check

### Gmail DOM selectors (most likely to break)

The content script (`content.js`) reads Gmail's DOM to extract the email subject and body. Google updates Gmail's HTML structure occasionally, which can break extraction silently. The script uses multiple fallback selectors to be resilient, but **you should verify** the following if extraction stops working:

| What | Selectors currently used | Where to check |
|---|---|---|
| Subject | `h2.hP`, `.hP` | Inspect the email subject heading in Gmail DevTools |
| Body | `.a3s.aiL`, `.a3s`, `.ii.gt div[dir]` | Inspect the email body container in Gmail DevTools |

To find the correct selector: open Gmail, open an email, right-click on the subject/body → Inspect, and look for a stable class or attribute.

### URL reputation is heuristic-only

The backend's URL checker (`utils/threat_analysis.py → check_url_reputation`) uses offline heuristics (HTTPS check, shortener detection, suspicious TLD, hyphen count, domain length). It does **not** call Google Safe Browsing or VirusTotal. For production use, swap in a real API call.

### No persistent background page

The extension uses a **Manifest V3 service worker**, which Chrome can terminate when idle. This is correct MV3 behavior. If the popup opens and immediately shows an error, click "Try Again" — the service worker will wake up.

### Google Workspace accounts

Some Google Workspace configurations render Gmail with slightly different markup. If extraction fails on a Workspace account, inspect the DOM and add fallback selectors to `content.js`.

### HTTP backend (localhost only)

Chrome extensions can make `fetch()` calls to `http://localhost` from background service workers (it's allowed by the `host_permissions`). If you change the backend URL to an `http://` (non-HTTPS) deployed URL, Chrome may block the request due to mixed-content restrictions. **Always use HTTPS for deployed backends.**

---

## 6. File structure

```
extension/
├── manifest.json       # MV3 manifest
├── config.js           # Backend URL (single place to change)
├── content.js          # Injected into Gmail — extracts email
├── background.js       # Service worker — relay + backend call
├── popup.html          # Extension popup UI
├── popup.css           # Dark-theme styles
├── popup.js            # Popup logic / state machine
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── EXTENSION_README.md # This file
```
