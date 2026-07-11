"""
Flask backend for the Email Spam & Threat Detection Chrome Extension.

Loads the artifacts saved from the notebook (Step 14: Model Persistence):
    spam_detector_model.pkl   - trained RandomForestClassifier
    feature_scaler.pkl        - MinMaxScaler for structural features
    tfidf_vectorizer.pkl      - TfidfVectorizer (max_features=1000)
    feature_selector.pkl      - SelectKBest (k=150)
    pca_transformer.pkl       - TruncatedSVD (n_components=100)

Place all 5 .pkl files in the `models/` folder next to this file before running.

Run locally:
    pip install -r requirements.txt
    python app.py
    # server starts on http://localhost:5000

Endpoints:
    GET  /health              -> basic liveness check
    POST /predict             -> body: {"subject": "...", "body": "..."} or {"text": "..."}
    POST /feedback            -> body: {"subject", "body", "sender", "correct_label"}
                                 Stores a labelled sample; retrains model every 10 samples.
    GET  /learning-status     -> returns sample count, last retrain time, next retrain ETA
"""
import logging
import os

import joblib
from flask import Flask, jsonify, request
from flask_cors import CORS

from utils.preprocessing import build_feature_vector
from utils.threat_analysis import (
    check_url_reputation,
    compute_threat_score,
    extract_urls,
    find_phishing_keywords,
    risk_level_from_score,
)
from utils.sender_analysis import analyze_sender
from utils.learner import (
    RETRAIN_THRESHOLD,
    get_status,
    retrain,
    save_feedback_sample,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

MODELS_DIR   = os.path.join(os.path.dirname(__file__), "models")
BACKEND_DIR  = os.path.dirname(__file__)
FEEDBACK_STORE = os.path.join(BACKEND_DIR, "feedback_store.jsonl")
RETRAIN_LOG    = os.path.join(BACKEND_DIR, "retrain_log.jsonl")
MODEL_PATH     = os.path.join(MODELS_DIR, "spam_detector_model.pkl")

# Track how many feedback samples have been added since the last retrain.
_samples_since_retrain = 0

app = Flask(__name__)
# Allow requests from the Chrome extension (extension origins look like chrome-extension://<id>)
CORS(app, resources={
    r"/predict":         {"origins": "*"},
    r"/health":          {"origins": "*"},
    r"/feedback":        {"origins": "*"},
    r"/learning-status": {"origins": "*"},
})

_artifacts = None  # lazy-loaded so /health works even before models are placed


def load_artifacts():
    global _artifacts
    if _artifacts is not None:
        return _artifacts

    required = {
        "model": "spam_detector_model.pkl",
        "scaler": "feature_scaler.pkl",
        "tfidf": "tfidf_vectorizer.pkl",
        "selector": "feature_selector.pkl",
        "pca": "pca_transformer.pkl",
    }

    missing = [f for f in required.values() if not os.path.exists(os.path.join(MODELS_DIR, f))]
    if missing:
        raise FileNotFoundError(
            f"Missing model artifact(s) in {MODELS_DIR}: {missing}. "
            "Copy the .pkl files saved in Step 14 of the notebook into the models/ folder."
        )

    _artifacts = {key: joblib.load(os.path.join(MODELS_DIR, fname)) for key, fname in required.items()}
    return _artifacts


@app.route("/health", methods=["GET"])
def health():
    models_ready = all(
        os.path.exists(os.path.join(MODELS_DIR, f))
        for f in [
            "spam_detector_model.pkl",
            "feature_scaler.pkl",
            "tfidf_vectorizer.pkl",
            "feature_selector.pkl",
            "pca_transformer.pkl",
        ]
    )
    return jsonify({"status": "ok", "models_loaded": models_ready})


@app.route("/predict", methods=["POST"])
def predict():
    try:
        artifacts = load_artifacts()
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 503

    data = request.get_json(silent=True) or {}

    subject = data.get("subject", "")
    body = data.get("body", "")
    text = data.get("text")  # allow a single combined field too
    sender = data.get("sender", "")  # optional sender string e.g. "Name <email@domain>"

    if text is None:
        text = f"{subject}\n{body}".strip()

    if not text:
        return jsonify({"error": "Request must include 'text', or 'subject'/'body'."}), 400

    # --- ML prediction ---
    feature_vector, clean_text = build_feature_vector(text, artifacts)
    model = artifacts["model"]

    prediction = model.predict(feature_vector)[0]
    proba = model.predict_proba(feature_vector)[0]
    spam_probability = float(proba[1])
    confidence = float(max(proba))

    label = "Spam" if prediction == 1 else "Ham"

    # --- Sender reputation ---
    sender_analysis = analyze_sender(sender)
    sender_score = sender_analysis["sender_score"]

    # --- Threat analysis (URLs, keywords, combined score) ---
    urls = extract_urls(text)
    url_reports = [check_url_reputation(u) for u in urls]
    matched_keywords = find_phishing_keywords(text)

    threat_score = compute_threat_score(spam_probability, url_reports, matched_keywords, sender_score)
    risk_level = risk_level_from_score(threat_score)

    return jsonify({
        "prediction": label,
        "spam_probability": round(spam_probability, 4),
        "confidence": round(confidence, 4),
        "threat_score": threat_score,
        "risk_level": risk_level,
        "suspicious_keywords": matched_keywords,
        "urls": url_reports,
        "keyword_count": len(matched_keywords),
        "url_count": len(urls),
        "sender_score": sender_score,
        "sender_flags": sender_analysis["sender_flags"],
        "sender_email": sender_analysis["sender_email"],
        "sender_domain": sender_analysis["sender_domain"],
    })


@app.route("/feedback", methods=["POST"])
def feedback():
    """
    Receive a user correction and store it as a training sample.
    Body: { subject, body, sender, correct_label }  (correct_label: "Spam" or "Ham")
    Automatically retrains the model every RETRAIN_THRESHOLD new samples.
    """
    global _artifacts, _samples_since_retrain

    try:
        artifacts = load_artifacts()
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 503

    data = request.get_json(silent=True) or {}
    subject       = data.get("subject", "")
    body          = data.get("body", "")
    sender        = data.get("sender", "")         # noqa: F841 (reserved for future use)
    correct_label = data.get("correct_label", "")  # "Spam" or "Ham"

    if correct_label not in ("Spam", "Ham"):
        return jsonify({"error": "correct_label must be 'Spam' or 'Ham'."}), 400

    text = f"{subject}\n{body}".strip()
    if not text:
        return jsonify({"error": "subject and/or body required."}), 400

    # Build the same feature vector the model uses for prediction
    feature_vector, _ = build_feature_vector(text, artifacts)
    label = 1 if correct_label == "Spam" else 0

    total = save_feedback_sample(feature_vector, label, FEEDBACK_STORE)
    _samples_since_retrain += 1

    retrain_result = None
    if _samples_since_retrain >= RETRAIN_THRESHOLD:
        retrain_result = retrain(MODEL_PATH, FEEDBACK_STORE, RETRAIN_LOG)
        if retrain_result["success"]:
            _artifacts = None          # clear cache → next predict loads improved model
            _samples_since_retrain = 0

    response = {
        "ok": True,
        "samples_collected": total,
        "retrain_triggered": retrain_result is not None,
    }
    if retrain_result:
        response["retrain"] = retrain_result

    return jsonify(response)


@app.route("/learning-status", methods=["GET"])
def learning_status():
    """Return current learning progress: sample count, last retrain, next retrain ETA."""
    return jsonify(get_status(FEEDBACK_STORE, RETRAIN_LOG))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
