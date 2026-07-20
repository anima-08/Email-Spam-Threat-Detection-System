import json
import logging
import os
import time
from datetime import datetime, timezone
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
logger = logging.getLogger(__name__)
RETRAIN_THRESHOLD = 10
MIN_SAMPLES_TO_RETRAIN = 5

def save_feedback_sample(feature_vector: np.ndarray, label: int, store_path: str) -> int:
    vec = np.array(feature_vector).flatten().tolist()
    record = {'features': vec, 'label': int(label), 'ts': datetime.now(timezone.utc).isoformat()}
    with open(store_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record) + '\n')
    with open(store_path, 'r', encoding='utf-8') as f:
        total = sum((1 for _ in f))
    logger.info('Feedback sample saved (label=%d). Total samples: %d', label, total)
    return total

def load_feedback_samples(store_path: str):
    if not os.path.exists(store_path):
        return (None, None)
    (X, y) = ([], [])
    with open(store_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                X.append(rec['features'])
                y.append(int(rec['label']))
            except (json.JSONDecodeError, KeyError):
                continue
    if not X:
        return (None, None)
    return (np.array(X, dtype=float), np.array(y, dtype=int))

def retrain(model_path: str, store_path: str, log_path: str) -> dict:
    (X, y) = load_feedback_samples(store_path)
    if X is None or len(X) < MIN_SAMPLES_TO_RETRAIN:
        msg = f'Not enough samples to retrain (need ≥ {MIN_SAMPLES_TO_RETRAIN}).'
        logger.warning(msg)
        return {'success': False, 'n_samples': 0, 'message': msg}
    n_samples = len(X)
    n_spam = int(np.sum(y == 1))
    n_ham = int(np.sum(y == 0))
    logger.info('Retraining on %d samples (%d spam, %d ham)…', n_samples, n_spam, n_ham)
    t0 = time.time()
    try:
        existing = joblib.load(model_path)
        n_estimators = getattr(existing, 'n_estimators', 100)
        random_state = getattr(existing, 'random_state', 42)
    except Exception:
        (n_estimators, random_state) = (100, 42)
    new_model = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state, class_weight='balanced', n_jobs=-1)
    new_model.fit(X, y)
    elapsed = round(time.time() - t0, 2)
    logger.info('Retrain complete in %.2fs.', elapsed)
    joblib.dump(new_model, model_path)
    logger.info('Model saved to %s', model_path)
    log_entry = {'ts': datetime.now(timezone.utc).isoformat(), 'n_samples': n_samples, 'n_spam': n_spam, 'n_ham': n_ham, 'elapsed_s': elapsed}
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry) + '\n')
    return {'success': True, 'n_samples': n_samples, 'message': f'Model retrained on {n_samples} samples ({n_spam} spam, {n_ham} ham) in {elapsed}s.'}

def get_status(store_path: str, log_path: str) -> dict:
    n_samples = 0
    if os.path.exists(store_path):
        with open(store_path, 'r', encoding='utf-8') as f:
            n_samples = sum((1 for line in f if line.strip()))
    last_retrained = None
    last_retrain_samples = None
    if os.path.exists(log_path):
        with open(log_path, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip()]
        if lines:
            try:
                last = json.loads(lines[-1])
                last_retrained = last.get('ts')
                last_retrain_samples = last.get('n_samples')
            except (json.JSONDecodeError, KeyError):
                pass
    samples_since_retrain = n_samples - (last_retrain_samples or 0) if last_retrain_samples is not None else n_samples
    return {'samples_collected': n_samples, 'samples_since_last_retrain': samples_since_retrain, 'next_retrain_in': max(0, RETRAIN_THRESHOLD - samples_since_retrain), 'last_retrained': last_retrained, 'retrain_threshold': RETRAIN_THRESHOLD}
