import logging
import os
import joblib
import hashlib
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from utils.preprocessing import build_feature_vector
from utils.threat_analysis import check_url_reputation, compute_threat_score, extract_urls, find_phishing_keywords, risk_level_from_score
from utils.sender_analysis import analyze_sender
from utils.spam_language_analyzer import analyze_spam_language
from utils.phishing_analyzer import analyze_phishing
from utils.structural_analyzer import analyze_structure
from utils.attachment_analyzer import analyze_attachments
from utils.learner import RETRAIN_THRESHOLD, get_status, retrain, save_feedback_sample
logging.basicConfig(level=logging.INFO, format='%(levelname)s %(name)s: %(message)s')
log = logging.getLogger(__name__)
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
BACKEND_DIR = os.path.dirname(__file__)
FEEDBACK_STORE = os.path.join(BACKEND_DIR, 'feedback_store.jsonl')
RETRAIN_LOG = os.path.join(BACKEND_DIR, 'retrain_log.jsonl')
MODEL_PATH = os.path.join(MODELS_DIR, 'spam_detector_model.pkl')
_samples_since_retrain = 0
app = Flask(__name__)
CORS(app, resources={'/predict': {'origins': '*'}, '/health': {'origins': '*'}, '/feedback': {'origins': '*'}, '/learning-status': {'origins': '*'}})
_artifacts = None

MANUAL_OVERRIDES = os.path.join(BACKEND_DIR, 'manual_overrides.json')

def load_overrides():
    if os.path.exists(MANUAL_OVERRIDES):
        try:
            with open(MANUAL_OVERRIDES, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_override(text_hash, label):
    overrides = load_overrides()
    overrides[text_hash] = label
    with open(MANUAL_OVERRIDES, 'w') as f:
        json.dump(overrides, f)

def load_artifacts():
    global _artifacts
    if _artifacts is not None:
        return _artifacts
    required = {'model': 'spam_detector_model.pkl', 'scaler': 'feature_scaler.pkl', 'tfidf': 'tfidf_vectorizer.pkl', 'selector': 'feature_selector.pkl', 'pca': 'pca_transformer.pkl'}
    missing = [f for f in required.values() if not os.path.exists(os.path.join(MODELS_DIR, f))]
    if missing:
        raise FileNotFoundError(f'Missing model artifact(s) in {MODELS_DIR}: {missing}. Copy the .pkl files saved from the training notebook into the models/ folder.')
    _artifacts = {key: joblib.load(os.path.join(MODELS_DIR, fname)) for (key, fname) in required.items()}
    log.info('ML model artifacts loaded successfully.')
    return _artifacts

def generate_explanation(ml_label: str, final_label: str, threat_score: int, spam_probability: float, confidence: float, spam_lang: dict, phishing: dict, url_reports: list, structural: dict, attachment: dict, sender_analysis: dict) -> list:
    reasons = []
    conf_pct = round(confidence * 100, 1)
    prob_pct = round(spam_probability * 100, 1)
    if ml_label == 'Spam':
        reasons.append(f'ML model classified this message as Spam with {conf_pct}% confidence (spam probability: {prob_pct}%).')
    else:
        reasons.append(f'ML model classified this message as Not Spam with {conf_pct}% confidence.')
    if final_label == 'Spam' and ml_label == 'Ham':
        reasons.append(f'Message flagged as Spam by heuristic analysis (Threat Score: {threat_score}/100) despite ML prediction.')
    for p in phishing.get('phishing_patterns', []):
        reasons.append(f"Phishing pattern detected: {p['label']} — {p['explanation']}")
    if spam_lang.get('signal_count', 0) > 0:
        top = spam_lang.get('top_categories', [])
        cat_str = ', '.join((f'{c} ({n})' for (c, n) in top[:3]))
        reasons.append(f"{spam_lang['signal_count']} spam-language signal(s) matched across categories: {cat_str}.")
    suspicious_urls = [u for u in url_reports if u.get('verdict') == 'Suspicious']
    if url_reports:
        if suspicious_urls:
            reasons.append(f'{len(url_reports)} URL(s) detected; {len(suspicious_urls)} flagged as suspicious.')
            for u in suspicious_urls[:2]:
                if u.get('reasons'):
                    reasons.append(f"  • URL issue: {u['reasons'][0]}")
        else:
            reasons.append(f'{len(url_reports)} URL(s) detected; none flagged as suspicious.')
    sender_flags = sender_analysis.get('sender_flags', [])
    if sender_flags:
        for flag in sender_flags[:2]:
            reasons.append(f'Sender flag: {flag}')
    for flag in structural.get('flags', []):
        reasons.append(f"Structural signal: {flag['explanation']}")
    for w in attachment.get('warnings', []):
        reasons.append(f"Attachment risk: {w['description']}")
    return reasons

@app.route('/health', methods=['GET'])
def health():
    models_ready = all((os.path.exists(os.path.join(MODELS_DIR, f)) for f in ['spam_detector_model.pkl', 'feature_scaler.pkl', 'tfidf_vectorizer.pkl', 'feature_selector.pkl', 'pca_transformer.pkl']))
    return jsonify({'status': 'ok', 'models_loaded': models_ready})

@app.route('/predict', methods=['POST'])
def predict():
    try:
        artifacts = load_artifacts()
    except FileNotFoundError as e:
        return (jsonify({'error': str(e)}), 503)
    data = request.get_json(silent=True) or {}
    subject = data.get('subject', '') or ''
    body = data.get('body', '') or ''
    text = data.get('text')
    sender = data.get('sender', '') or ''
    if text is None:
        text = f'{subject}\n{body}'.strip()
    if not text:
        return (jsonify({'error': "Request must include 'text', or 'subject'/'body'."}), 400)
    
    import re
    # Strip forwarding wrappers so we only scan the original scam payload
    # Gmail: "---------- Forwarded message ---------"
    fwd_match = re.search(r'(?:-{3,}\s*Forwarded message\s*-{3,}|Begin forwarded message:)(.*)', text, re.IGNORECASE | re.DOTALL)
    if fwd_match:
        fwd_text = fwd_match.group(1)
        # Try to extract original sender
        from_match = re.search(r'From:\s*.*?[<]([^>]+)[>]', fwd_text, re.IGNORECASE)
        if not from_match:
            from_match = re.search(r'From:\s*([^\n\r]+)', fwd_text, re.IGNORECASE)
        if from_match:
            sender = from_match.group(1).strip()
        text = fwd_text.strip()
        
    text_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
    overrides = load_overrides()
    manual_override_label = overrides.get(text_hash)
    
    (feature_vector, clean_text) = build_feature_vector(text, artifacts)
    model = artifacts['model']
    prediction = model.predict(feature_vector)[0]
    proba = model.predict_proba(feature_vector)[0]
    raw_spam_probability = float(proba[1])
    raw_confidence = float(max(proba))
    
    sender_analysis_result = analyze_sender(sender)
    sender_score = sender_analysis_result['sender_score']
    urls = extract_urls(text)
    url_reports = [check_url_reputation(u) for u in urls]
    spam_lang = analyze_spam_language(text)
    phishing = analyze_phishing(text, urls)
    structural = analyze_structure(subject, body, len(urls))
    attachment = analyze_attachments(text)
    
    threat_score = compute_threat_score(spam_probability=raw_spam_probability, confidence=raw_confidence, url_reports=url_reports, spam_language_score=spam_lang['score_contribution'], phishing_score=phishing['score_contribution'], structural_score=structural['score_contribution'], attachment_score=attachment['score_contribution'], sender_score=sender_score)
    risk_level = risk_level_from_score(threat_score)
    
    # Unified Risk (Safety Net Approach)
    # We take the MAXIMUM of the ML probability and the Heuristic Threat Score.
    # This ensures that a strong Spam signal from ONE system isn't diluted by a low score from the OTHER system.
    # Weighted combination
    spam_probability = (
    0.7 * raw_spam_probability +
    0.3 * (threat_score / 100.0)
)

    confidence = max(spam_probability, 1.0 - spam_probability)
    
    ml_label = "Spam" if raw_spam_probability >= 0.50 else "Ham"

    if spam_probability >= 0.80:
       final_label = "Spam"
       risk_level = "High"

    elif spam_probability >= 0.60:
         final_label = "Spam"
         risk_level = "Moderate"

    elif spam_probability >= 0.36:
         final_label = "Ham"
         risk_level = "Low"

    else:
         final_label = "Ham"
         risk_level = "Safe"
    
    if manual_override_label:
        final_label = manual_override_label
        if final_label == 'Ham':
            threat_score = 0
            risk_level = 'Low'
            spam_probability = 0.0
            explanation = ['You manually marked this exact email as Not Spam.']
        else:
            threat_score = 100
            risk_level = 'Critical'
            spam_probability = 1.0
            explanation = ['You manually marked this exact email as Spam.']
    else:
        explanation = generate_explanation(ml_label=ml_label, final_label=final_label, threat_score=threat_score, spam_probability=spam_probability, confidence=confidence, spam_lang=spam_lang, phishing=phishing, url_reports=url_reports, structural=structural, attachment=attachment, sender_analysis=sender_analysis_result)
        
    matched_keywords = find_phishing_keywords(text)
    legacy_keywords = list({sig['phrase'] for sig in spam_lang.get('matched_signals', [])} | set(matched_keywords))
    return jsonify({'prediction': final_label, 'spam_probability': round(spam_probability, 4), 'confidence': round(confidence, 4), 'threat_score': threat_score, 'risk_level': risk_level, 'spam_signals': spam_lang['matched_signals'], 'spam_signal_count': spam_lang['signal_count'], 'spam_category_summary': spam_lang['category_summary'], 'phishing_patterns': phishing['phishing_patterns'], 'phishing_count': phishing['pattern_count'], 'urls': url_reports, 'url_count': len(urls), 'sender_score': sender_score, 'sender_flags': sender_analysis_result['sender_flags'], 'sender_email': sender_analysis_result['sender_email'], 'sender_domain': sender_analysis_result['sender_domain'], 'structural_flags': structural['flags'], 'attachment_warnings': attachment['warnings'], 'explanation': explanation, 'suspicious_keywords': legacy_keywords, 'keyword_count': len(legacy_keywords)})

@app.route('/feedback', methods=['POST'])
def feedback():
    global _artifacts, _samples_since_retrain
    try:
        artifacts = load_artifacts()
    except FileNotFoundError as e:
        return (jsonify({'error': str(e)}), 503)
    data = request.get_json(silent=True) or {}
    subject = data.get('subject', '') or ''
    body = data.get('body', '') or ''
    correct_label = data.get('correct_label', '')
    if correct_label not in ('Spam', 'Ham'):
        return (jsonify({'error': "correct_label must be 'Spam' or 'Ham'."}), 400)
    text = f'{subject}\n{body}'.strip()
    if not text:
        return (jsonify({'error': 'subject and/or body required.'}), 400)
        
    import re
    # Strip forwarding wrappers so we hash the same payload as predict
    fwd_match = re.search(r'(?:-{3,}\s*Forwarded message\s*-{3,}|Begin forwarded message:)(.*)', text, re.IGNORECASE | re.DOTALL)
    if fwd_match:
        fwd_text = fwd_match.group(1)
        text = fwd_text.strip()
        
    text_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
    save_override(text_hash, correct_label)
    
    (feature_vector, _) = build_feature_vector(text, artifacts)
    label = 1 if correct_label == 'Spam' else 0
    total = save_feedback_sample(feature_vector, label, FEEDBACK_STORE)
    _samples_since_retrain += 1
    retrain_result = None
    if _samples_since_retrain >= RETRAIN_THRESHOLD:
        retrain_result = retrain(MODEL_PATH, FEEDBACK_STORE, RETRAIN_LOG)
        if retrain_result['success']:
            _artifacts = None
            _samples_since_retrain = 0
    response = {'ok': True, 'samples_collected': total, 'retrain_triggered': retrain_result is not None}
    if retrain_result:
        response['retrain'] = retrain_result
    return jsonify(response)

@app.route('/learning-status', methods=['GET'])
def learning_status():
    return jsonify(get_status(FEEDBACK_STORE, RETRAIN_LOG))
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
