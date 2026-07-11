# Email Spam & Threat Detection — Flask Backend

Serves your trained Random Forest model (from `Email_Spam_And_Threat_Detection_Using_Machine_Learning_.ipynb`)
behind a REST API so the Chrome extension can call it in real time.

## 1. Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Add your trained model files

From Colab, download the 5 files saved in **Step 14: Model Persistence**:

- `spam_detector_model.pkl`
- `feature_scaler.pkl`
- `tfidf_vectorizer.pkl`
- `feature_selector.pkl`
- `pca_transformer.pkl`

Place all 5 into `backend/models/`.

## 3. Run the server

```bash
python app.py
```

Server starts at `http://localhost:5000`.

## 4. API

### `GET /health`
Quick liveness + "are the model files in place" check.

### `POST /predict`
Request body (either form works):
```json
{ "subject": "Congratulations!", "body": "You have won a prize, click here: http://bit.ly/xyz" }
```
or
```json
{ "text": "full email text including subject and body" }
```

Response:
```json
{
  "prediction": "Spam",
  "spam_probability": 0.94,
  "confidence": 0.94,
  "threat_score": 82,
  "risk_level": "Critical",
  "suspicious_keywords": ["congratulations", "click here"],
  "keyword_count": 2,
  "url_count": 1,
  "urls": [
    {
      "url": "http://bit.ly/xyz",
      "risk_score": 55,
      "verdict": "Suspicious",
      "reasons": ["Not using HTTPS", "Uses a URL shortener (destination is hidden)"]
    }
  ]
}
```

## How it stays faithful to the notebook

`utils/preprocessing.py` reproduces the **exact** feature pipeline the model was
trained on (stopword removal → structural features → MinMaxScaler → TF-IDF →
SelectKBest → TruncatedSVD/"PCA"), mirroring `predict_single_email()` from
Step 20 of the notebook. If you retrain with a different pipeline, update this
file to match.

`utils/threat_analysis.py` adds the extra signals for the extension UI that
aren't in the notebook: URL extraction + a lightweight offline reputation
heuristic, phishing/urgency keyword matching, and a combined 0–100 threat
score. The URL reputation check is heuristic-only (no external API key
required) — swap `check_url_reputation()` for a real call to Google Safe
Browsing or VirusTotal when you're ready for production-grade checks.

## Deploying

For anything beyond local testing, run behind gunicorn instead of the Flask
dev server:
```bash
gunicorn -w 2 -b 0.0.0.0:5000 app:app
```
And update the extension's fetch URL from `http://localhost:5000` to wherever
you deploy this (Render, Railway, a VPS, etc.). Also enable HTTPS — the
extension's `manifest.json` `host_permissions` will need the real URL.
