"""
Flask backend for the SpamShield Email Threat Detection Chrome Extension.

Multi-layer detection pipeline:
  1. ML spam prediction (RandomForestClassifier, 98%+ accuracy)
  2. Spam-language analysis (170+ weighted signals, 8 categories)
  3. Phishing pattern detection (10 combination-based patterns)
  4. URL extraction and heuristic reputation scoring
  5. Sender/domain reputation analysis
  6. Structural anomaly detection (ALL CAPS, exclamation abuse, etc.)
  7. Attachment risk detection from email text mentions
  8. Explainability ("Why flagged?") bullet list

Model artifacts (place in models/ folder):
  spam_detector_model.pkl   - trained RandomForestClassifier
  feature_scaler.pkl        - MinMaxScaler for structural features
  tfidf_vectorizer.pkl      - TfidfVectorizer (max_features=1000)
  feature_selector.pkl      - SelectKBest (k=150)
  pca_transformer.pkl       - TruncatedSVD (n_components=100)

Run locally:
  cd antigravity_upload/backend
  python app.py          # http://localhost:5000

Endpoints:
  GET  /health              → liveness check + model status
  POST /predict             → full multi-layer analysis
  POST /feedback            → store labelled sample, trigger retrain
  GET  /learning-status     → sample count, last retrain, next retrain ETA
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
from utils.spam_language_analyzer import analyze_spam_language
from utils.phishing_analyzer import analyze_phishing
from utils.structural_analyzer import analyze_structure
from utils.attachment_analyzer import analyze_attachments
from utils.learner import (
    RETRAIN_THRESHOLD,
    get_status,
    retrain,
    save_feedback_sample,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)

MODELS_DIR     = os.path.join(os.path.dirname(__file__), "models")
BACKEND_DIR    = os.path.dirname(__file__)
FEEDBACK_STORE = os.path.join(BACKEND_DIR, "feedback_store.jsonl")
RETRAIN_LOG    = os.path.join(BACKEND_DIR, "retrain_log.jsonl")
MODEL_PATH     = os.path.join(MODELS_DIR, "spam_detector_model.pkl")

_samples_since_retrain = 0

app = Flask(__name__)
CORS(app, resources={
    r"/predict":         {"origins": "*"},
    r"/health":          {"origins": "*"},
    r"/feedback":        {"origins": "*"},
    r"/learning-status": {"origins": "*"},
})

_artifacts = None  # lazy-loaded


def load_artifacts():
    global _artifacts
    if _artifacts is not None:
        return _artifacts

    required = {
        "model":    "spam_detector_model.pkl",
        "scaler":   "feature_scaler.pkl",
        "tfidf":    "tfidf_vectorizer.pkl",
        "selector": "feature_selector.pkl",
        "pca":      "pca_transformer.pkl",
    }

    missing = [f for f in required.values() if not os.path.exists(os.path.join(MODELS_DIR, f))]
    if missing:
        raise FileNotFoundError(
            f"Missing model artifact(s) in {MODELS_DIR}: {missing}. "
            "Copy the .pkl files saved from the training notebook into the models/ folder."
        )

    _artifacts = {key: joblib.load(os.path.join(MODELS_DIR, fname)) for key, fname in required.items()}
    log.info("ML model artifacts loaded successfully.")
    return _artifacts


# ── Explainability ────────────────────────────────────────────────────────────

def generate_explanation(
    label: str,
    spam_probability: float,
    confidence: float,
    spam_lang: dict,
    phishing: dict,
    url_reports: list,
    structural: dict,
    attachment: dict,
    sender_analysis: dict,
) -> list:
    """
    Generate a human-readable list of reasons why an email was flagged.

    Every item in the returned list corresponds to an actual detected signal.
    Nothing is fabricated.
    """
    reasons = []

    # ML classification
    conf_pct = round(confidence * 100, 1)
    prob_pct = round(spam_probability * 100, 1)
    if label == "Spam":
        reasons.append(f"ML model classified this message as Spam with {conf_pct}% confidence (spam probability: {prob_pct}%).")
    else:
        reasons.append(f"ML model classified this message as Not Spam with {conf_pct}% confidence.")

    # Phishing patterns
    for p in phishing.get("phishing_patterns", []):
        reasons.append(f"Phishing pattern detected: {p['label']} — {p['explanation']}")

    # Spam language
    if spam_lang.get("signal_count", 0) > 0:
        top = spam_lang.get("top_categories", [])
        cat_str = ", ".join(f"{c} ({n})" for c, n in top[:3])
        reasons.append(
            f"{spam_lang['signal_count']} spam-language signal(s) matched across categories: {cat_str}."
        )

    # URLs
    suspicious_urls = [u for u in url_reports if u.get("verdict") == "Suspicious"]
    if url_reports:
        if suspicious_urls:
            reasons.append(
                f"{len(url_reports)} URL(s) detected; {len(suspicious_urls)} flagged as suspicious."
            )
            for u in suspicious_urls[:2]:
                if u.get("reasons"):
                    reasons.append(f"  • URL issue: {u['reasons'][0]}")
        else:
            reasons.append(f"{len(url_reports)} URL(s) detected; none flagged as suspicious.")

    # Sender
    sender_flags = sender_analysis.get("sender_flags", [])
    if sender_flags:
        for flag in sender_flags[:2]:
            reasons.append(f"Sender flag: {flag}")

    # Structural
    for flag in structural.get("flags", []):
        reasons.append(f"Structural signal: {flag['explanation']}")

    # Attachment
    for w in attachment.get("warnings", []):
        reasons.append(f"Attachment risk: {w['description']}")

    return reasons


# ── Endpoints ─────────────────────────────────────────────────────────────────

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

    subject = data.get("subject", "") or ""
    body    = data.get("body", "")    or ""
    text    = data.get("text")
    sender  = data.get("sender", "")  or ""

    if text is None:
        text = f"{subject}\n{body}".strip()

    if not text:
        return jsonify({"error": "Request must include 'text', or 'subject'/'body'."}), 400

    # ── 1. ML prediction ──────────────────────────────────────────────────────
    feature_vector, clean_text = build_feature_vector(text, artifacts)
    model = artifacts["model"]
    prediction = model.predict(feature_vector)[0]
    proba       = model.predict_proba(feature_vector)[0]
    spam_probability = float(proba[1])
    confidence       = float(max(proba))
    label = "Spam" if prediction == 1 else "Ham"

    # ── 2. Sender analysis ────────────────────────────────────────────────────
    sender_analysis_result = analyze_sender(sender)
    sender_score = sender_analysis_result["sender_score"]

    # ── 3. URL extraction ─────────────────────────────────────────────────────
    urls        = extract_urls(text)
    url_reports = [check_url_reputation(u) for u in urls]

    # ── 4. Spam language analysis ─────────────────────────────────────────────
    spam_lang = analyze_spam_language(text)

    # ── 5. Phishing pattern analysis ──────────────────────────────────────────
    phishing = analyze_phishing(text, urls)

    # ── 6. Structural analysis ────────────────────────────────────────────────
    structural = analyze_structure(subject, body, len(urls))

    # ── 7. Attachment analysis ────────────────────────────────────────────────
    attachment = analyze_attachments(text)

    # ── 8. Unified threat score ───────────────────────────────────────────────
    threat_score = compute_threat_score(
        spam_probability   = spam_probability,
        confidence         = confidence,
        url_reports        = url_reports,
        spam_language_score= spam_lang["score_contribution"],
        phishing_score     = phishing["score_contribution"],
        structural_score   = structural["score_contribution"],
        attachment_score   = attachment["score_contribution"],
        sender_score       = sender_score,
    )
    risk_level = risk_level_from_score(threat_score)

    # ── 9. Explainability ─────────────────────────────────────────────────────
    explanation = generate_explanation(
        label            = label,
        spam_probability = spam_probability,
        confidence       = confidence,
        spam_lang        = spam_lang,
        phishing         = phishing,
        url_reports      = url_reports,
        structural       = structural,
        attachment       = attachment,
        sender_analysis  = sender_analysis_result,
    )

    # ── 10. Legacy keyword list (backward compatibility) ──────────────────────
    matched_keywords = find_phishing_keywords(text)
    # Supplement with matched spam signals for the legacy field
    legacy_keywords = list({
        sig["phrase"] for sig in spam_lang.get("matched_signals", [])
    } | set(matched_keywords))

    return jsonify({
        # ── ML classification ──────────────────────────────────────────────
        "prediction":       label,
        "spam_probability": round(spam_probability, 4),
        "confidence":       round(confidence, 4),

        # ── Threat score ───────────────────────────────────────────────────
        "threat_score": threat_score,
        "risk_level":   risk_level,

        # ── Spam language ──────────────────────────────────────────────────
        "spam_signals":         spam_lang["matched_signals"],
        "spam_signal_count":    spam_lang["signal_count"],
        "spam_category_summary":spam_lang["category_summary"],

        # ── Phishing patterns ──────────────────────────────────────────────
        "phishing_patterns": phishing["phishing_patterns"],
        "phishing_count":    phishing["pattern_count"],

        # ── URLs ───────────────────────────────────────────────────────────
        "urls":      url_reports,
        "url_count": len(urls),

        # ── Sender ─────────────────────────────────────────────────────────
        "sender_score":  sender_score,
        "sender_flags":  sender_analysis_result["sender_flags"],
        "sender_email":  sender_analysis_result["sender_email"],
        "sender_domain": sender_analysis_result["sender_domain"],

        # ── Structural ─────────────────────────────────────────────────────
        "structural_flags": structural["flags"],

        # ── Attachments ────────────────────────────────────────────────────
        "attachment_warnings": attachment["warnings"],

        # ── Explainability ─────────────────────────────────────────────────
        "explanation": explanation,

        # ── Legacy fields (backward compat) ───────────────────────────────
        "suspicious_keywords": legacy_keywords,
        "keyword_count":       len(legacy_keywords),
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

    data          = request.get_json(silent=True) or {}
    subject       = data.get("subject", "")
    body          = data.get("body", "")
    correct_label = data.get("correct_label", "")

    if correct_label not in ("Spam", "Ham"):
        return jsonify({"error": "correct_label must be 'Spam' or 'Ham'."}), 400

    text = f"{subject}\n{body}".strip()
    if not text:
        return jsonify({"error": "subject and/or body required."}), 400

    feature_vector, _ = build_feature_vector(text, artifacts)
    label = 1 if correct_label == "Spam" else 0

    total = save_feedback_sample(feature_vector, label, FEEDBACK_STORE)
    _samples_since_retrain += 1

    retrain_result = None
    if _samples_since_retrain >= RETRAIN_THRESHOLD:
        retrain_result = retrain(MODEL_PATH, FEEDBACK_STORE, RETRAIN_LOG)
        if retrain_result["success"]:
            _artifacts = None
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
