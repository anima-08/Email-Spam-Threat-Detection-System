# PROJECT_CONTEXT.md
## Email Spam & Threat Detection — Chrome Extension

This file is background context for the coding agent. The main task list is
in `ANTIGRAVITY_PROMPT.md` — read that first, use this for technical details.

---

### 1. Where the ML model came from

Trained in Google Colab (`Email_Spam_And_Threat_Detection_Using_Machine_Learning_.ipynb`):

- Dataset: `emails.csv` (text + `spam` binary label)
- Preprocessing: lowercase → strip non-alpha chars → remove NLTK English stopwords
- Structural features (4): `text_length`, `num_words`, `num_digits`, `num_punctuation`
  - `text_length`/`num_words` computed from the **cleaned** text
  - `num_digits`/`num_punctuation` computed from the **original raw** text
- Structural features scaled with `MinMaxScaler`
- Text vectorized with `TfidfVectorizer(max_features=1000)`
- Combined vector → `SelectKBest(f_classif, k=150)` → `TruncatedSVD(n_components=100)`
- Three models trained: Logistic Regression, Naive Bayes, Random Forest
- **Random Forest won**: ~97% accuracy, saved as the production model
- Artifacts saved via `joblib`: `spam_detector_model.pkl`, `feature_scaler.pkl`,
  `tfidf_vectorizer.pkl`, `feature_selector.pkl`, `pca_transformer.pkl`

### 2. Backend (already built — in `backend/`)

A Flask app already implements this pipeline exactly and exposes it as an API.
**Do not rebuild this from scratch — extend it if needed.**

- `backend/app.py` — Flask server, CORS-enabled
- `backend/utils/preprocessing.py` — reproduces the exact training pipeline
- `backend/utils/threat_analysis.py` — URL extraction + offline reputation
  heuristics, phishing keyword matching, combined threat score (0–100) and
  risk level (Low/Medium/High/Critical)
- `backend/models/` — **empty**, user must drop in the 5 `.pkl` files from Colab
- `backend/requirements.txt`, `backend/README.md` — setup instructions

#### API contract (already implemented, treat as fixed unless told otherwise)

`GET /health` →
```json
{ "status": "ok", "models_loaded": true }
```

`POST /predict` — body:
```json
{ "subject": "string", "body": "string" }
```
or
```json
{ "text": "string" }
```

Response:
```json
{
  "prediction": "Spam" | "Ham",
  "spam_probability": 0.94,
  "confidence": 0.94,
  "threat_score": 82,
  "risk_level": "Low" | "Medium" | "High" | "Critical",
  "suspicious_keywords": ["congratulations", "click here"],
  "keyword_count": 2,
  "url_count": 1,
  "urls": [
    {
      "url": "http://bit.ly/xyz",
      "risk_score": 55,
      "verdict": "Suspicious" | "Likely Safe",
      "reasons": ["Not using HTTPS", "Uses a URL shortener (destination is hidden)"]
    }
  ]
}
```

Default local URL: `http://localhost:5000`. This should be a configurable
constant in the extension (not hardcoded in multiple places), since it will
change when deployed.

### 3. What still needs to be built

A Chrome Extension, **Manifest V3**, that:

1. Reads the currently-open email in Gmail's web UI (subject + body) via a
   content script
2. Sends it to the backend's `/predict` endpoint
3. Displays results in a popup: prediction label, spam probability, threat
   score with a visual meter, risk level badge, highlighted suspicious
   keywords (highlight them inline in a preview of the email text), and a
   list of detected URLs with their reputation verdicts
4. Works via a background service worker (Manifest V3 requirement — no
   persistent background pages)
5. Gracefully handles: backend unreachable, no email open/selected, empty
   email body

### 4. Constraints

- Manifest V3 only (no V2 APIs)
- No API keys hardcoded in the extension — the backend URL should be the only
  configurable value, and it should be easy to change (e.g. a constant at the
  top of one config file)
- Extension must not break if Gmail's DOM structure has minor variations —
  fail gracefully with a clear "couldn't read this email" message rather than
  crashing
- Keep the UI simple and readable — this is a student capstone/demo project,
  not a commercial product. Clarity over polish.
