# SpamShield — Email Spam & Threat Detection

> Real-time spam and phishing detection for Gmail and Outlook via Chrome Extension + Python ML backend.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5%2B-orange?logo=scikit-learn)](https://scikit-learn.org)
[![Manifest](https://img.shields.io/badge/MV3-Chrome%20Extension-green?logo=googlechrome)](https://developer.chrome.com/docs/extensions/mv3/)

---

## What It Does

SpamShield combines a **trained ML model (98%+ accuracy)** with a **multi-layer heuristic threat engine** to give you real-time analysis of any email open in Gmail or Outlook:

| Layer | What it detects |
|-------|----------------|
| 🤖 **ML Model** | RandomForestClassifier trained on 5,000+ emails |
| 🔤 **Spam Language** | 170+ weighted phrases across 8 categories |
| 🎣 **Phishing Patterns** | 10 combination-based attack families |
| 🔗 **URL Analysis** | Shorteners, IP URLs, suspicious TLDs, brand impersonation |
| 👤 **Sender Analysis** | Domain spoofing, bulk-sender infra, display-name mismatch |
| 🏗️ **Structural Signals** | ALL CAPS abuse, exclamation overuse, short body + URL |
| 📎 **Attachment Risk** | Executable mentions, macro-enable instructions |
| 💡 **Explainability** | "Why was this flagged?" bullet list in every scan |

---

## Project Structure

```
IBM/
├── extension/                     Chrome Extension (Manifest V3)
│   ├── manifest.json              Permissions — Gmail + Outlook
│   ├── background.js              Service worker, analysis orchestration
│   ├── content.js                 DOM extraction (Gmail + Outlook selectors)
│   ├── popup.html / popup.js / popup.css   Main UI
│   └── options.html / options.js  Settings page
│
└── antigravity_upload/backend/    Python Flask API
    ├── app.py                     Main Flask app, /predict endpoint
    ├── requirements.txt
    ├── models/                    5 trained .pkl artifacts
    │   ├── spam_detector_model.pkl
    │   ├── feature_scaler.pkl
    │   ├── tfidf_vectorizer.pkl
    │   ├── feature_selector.pkl
    │   └── pca_transformer.pkl
    ├── config/
    │   └── spam_signals.json      170+ structured spam-signal definitions
    └── utils/
        ├── preprocessing.py        ML feature pipeline
        ├── threat_analysis.py      URL analysis + unified threat scoring
        ├── sender_analysis.py      Domain/sender reputation heuristics
        ├── spam_language_analyzer.py  Weighted spam-word detection
        ├── phishing_analyzer.py    Combination phishing pattern detection
        ├── structural_analyzer.py  Formatting anomaly detection
        ├── attachment_analyzer.py  Risky attachment mention detection
        └── learner.py              Continual learning from user feedback
    └── tests/
        └── test_backend.py         35-test suite (unit + integration)
```

---

## Quick Start

### 1. Start the Backend

```bash
cd antigravity_upload/backend

# Create & activate virtual environment (first time only)
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Start the server
python app.py
# Server starts at http://localhost:5000
```

Alternatively, use the provided batch file from the project root:
```bash
start_backend.bat
```

### 2. Load the Chrome Extension

1. Open Chrome → `chrome://extensions`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Click **Allow** when prompted for Gmail and Outlook permissions

### 3. Scan an Email

1. Open **Gmail** (`mail.google.com`) or **Outlook** (`outlook.live.com`)
2. Open any email
3. Click the **SpamShield** icon in your browser toolbar
4. Click **Scan Email**

---

## API Reference

### `POST /predict`

Analyzes an email. All fields are optional but at least one of `text` or `subject`/`body` is required.

```json
// Request
{
  "subject": "You have won a free gift!",
  "body": "Claim your prize now...",
  "sender": "Prize Team <noreply@prizes.xyz>"
}

// Response
{
  "prediction": "Spam",
  "spam_probability": 0.8623,
  "confidence": 0.8623,
  "threat_score": 67,
  "risk_level": "High",

  "spam_signals": [
    {"phrase": "free gift", "category": "free_offers", "severity": 2, "explanation": "..."}
  ],
  "spam_signal_count": 7,
  "spam_category_summary": {"prize_reward_scams": 3, "urgency_pressure": 2},

  "phishing_patterns": [
    {"pattern_name": "prize_reward_scam", "label": "Prize or Reward Scam", "severity": "High"}
  ],

  "urls": [{"url": "...", "risk_score": 55, "verdict": "Suspicious", "reasons": [...]}],
  "sender_flags": ["Sender domain uses a suspicious TLD (.xyz)"],
  "structural_flags": [],
  "attachment_warnings": [],

  "explanation": [
    "ML model classified this message as Spam with 86.2% confidence.",
    "Phishing pattern detected: Prize or Reward Scam",
    "7 spam-language signal(s) matched..."
  ]
}
```

### `GET /health`
```json
{"status": "ok", "models_loaded": true}
```

### `POST /feedback`
```json
// Request
{"subject": "...", "body": "...", "correct_label": "Ham"}
// Response
{"ok": true, "samples_collected": 5, "retrain_triggered": false}
```

### `GET /learning-status`
Returns continual-learning status: sample count, last retrain timestamp, next retrain ETA.

---

## Running Tests

```bash
cd antigravity_upload/backend
python tests/test_backend.py
# 35 tests: spam language, phishing, structural, attachment, URL, scoring, integration
```

---

## Threat Score Interpretation

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| 0–24  | **Low** | No significant signals |
| 25–49 | **Moderate** | Some signals present; use caution |
| 50–74 | **High** | Multiple risk factors detected |
| 75–100| **Critical** | Strong evidence of spam or phishing |

The threat score is **separate** from the ML classification. An email can be:
- Classified as **Spam** by ML with a lower threat score (e.g., aggressive marketing)
- Classified as **Ham** with a moderate threat score (e.g., legitimate invoice with a suspicious link)

---

## Supported Email Clients

| Client | Status |
|--------|--------|
| Gmail (`mail.google.com`) | ✅ Full support |
| Outlook Web (`outlook.live.com`) | ✅ Full support |
| Outlook 365 (`outlook.office.com`) | ✅ Full support |

---

## Security Notes

- **No API keys in extension code.** All analysis is performed by the backend.
- **No email content is sent to third parties.** Analysis runs entirely locally.
- **Content scripts are isolated** and sanitize extracted text before processing.
- To add Google Safe Browsing URL scanning, set `SAFE_BROWSING_API_KEY=<key>` as an environment variable on the backend. The architecture supports this without any code changes.

---

## Continual Learning

SpamShield learns from your corrections:
1. After scanning an email, click **"Was this correct?" → ✗ No** if the result is wrong
2. The backend stores the corrected label
3. Every 10 corrections, the model automatically retrains on the accumulated feedback
4. The next scan uses the improved model

---

## Limitations

- Outlook Web selectors target `aria-label` and `role` attributes which may shift if Microsoft updates their UI significantly
- URL analysis is heuristic-only (no external API by default); add `SAFE_BROWSING_API_KEY` for real-time URL reputation
- The extension analyzes extracted text only — binary attachment scanning requires a dedicated file scanning service
- Continual learning uses a lightweight RandomForest fine-tune, not a full retrain from scratch

---

## Recommended Next Improvements

1. **Google Safe Browsing integration** — set env var, one function swap in `threat_analysis.py`
2. **VirusTotal URL scanning** — same architecture, add alternative provider
3. **Brand impersonation logos** — detect spoofed sender logos in HTML emails
4. **Domain age checking** — newly registered domains are higher risk
5. **DMARC/SPF header analysis** — when available from email headers
6. **Notification on auto-scan** — Chrome notification API for background scans
