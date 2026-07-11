"""
learner.py — Continual learning utilities for SpamShield.

Stores user-feedback samples (feature vectors + correct labels) and
periodically retrains the RandomForestClassifier on the accumulated data.

Flow:
    1. User clicks Agree/Wrong in the popup.
    2. background.js POSTs to /feedback with {subject, body, sender, correct_label}.
    3. app.py calls save_feedback_sample() → appended to feedback_store.jsonl.
    4. When sample count reaches RETRAIN_THRESHOLD, app.py calls retrain().
    5. retrain() fits a new RF on all stored samples and overwrites the .pkl.
    6. The _artifacts cache in app.py is cleared so the next /predict loads the
       improved model automatically.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)

# How many new feedback samples to accumulate before triggering a retrain.
RETRAIN_THRESHOLD = 10

# Minimum samples needed before any retraining attempt (guards against
# retraining on a tiny, unrepresentative dataset).
MIN_SAMPLES_TO_RETRAIN = 5


# ── Persistence helpers ───────────────────────────────────────────────────────

def save_feedback_sample(feature_vector: np.ndarray, label: int, store_path: str) -> int:
    """
    Append one labelled sample to the JSONL store.

    Args:
        feature_vector: 1-D or 2-D numpy array (the PCA output from the pipeline).
        label:          0 = Ham, 1 = Spam.
        store_path:     Absolute path to feedback_store.jsonl.

    Returns:
        Total number of samples now stored.
    """
    vec = np.array(feature_vector).flatten().tolist()
    record = {
        "features": vec,
        "label": int(label),
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    with open(store_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    # Count total lines = total samples
    with open(store_path, "r", encoding="utf-8") as f:
        total = sum(1 for _ in f)

    logger.info("Feedback sample saved (label=%d). Total samples: %d", label, total)
    return total


def load_feedback_samples(store_path: str):
    """
    Load all feedback samples from the JSONL store.

    Returns:
        X: np.ndarray of shape (n_samples, n_features)
        y: np.ndarray of shape (n_samples,)  — integer labels
        Returns (None, None) if the file doesn't exist or is empty.
    """
    if not os.path.exists(store_path):
        return None, None

    X, y = [], []
    with open(store_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                X.append(rec["features"])
                y.append(int(rec["label"]))
            except (json.JSONDecodeError, KeyError):
                continue  # skip malformed lines

    if not X:
        return None, None

    return np.array(X, dtype=float), np.array(y, dtype=int)


# ── Retraining ────────────────────────────────────────────────────────────────

def retrain(model_path: str, store_path: str, log_path: str) -> dict:
    """
    Retrain the RandomForestClassifier on all accumulated feedback samples
    and overwrite the saved model .pkl.

    Args:
        model_path:  Path to spam_detector_model.pkl (will be overwritten).
        store_path:  Path to feedback_store.jsonl.
        log_path:    Path to retrain_log.jsonl (audit trail).

    Returns:
        dict with keys: success (bool), n_samples (int), message (str).
    """
    X, y = load_feedback_samples(store_path)

    if X is None or len(X) < MIN_SAMPLES_TO_RETRAIN:
        msg = f"Not enough samples to retrain (need ≥ {MIN_SAMPLES_TO_RETRAIN})."
        logger.warning(msg)
        return {"success": False, "n_samples": 0, "message": msg}

    n_samples = len(X)
    n_spam = int(np.sum(y == 1))
    n_ham = int(np.sum(y == 0))

    logger.info("Retraining on %d samples (%d spam, %d ham)…", n_samples, n_spam, n_ham)
    t0 = time.time()

    # Load the existing model to inherit its hyperparameters where possible
    try:
        existing = joblib.load(model_path)
        n_estimators = getattr(existing, "n_estimators", 100)
        random_state = getattr(existing, "random_state", 42)
    except Exception:
        n_estimators, random_state = 100, 42

    new_model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        class_weight="balanced",   # handles class imbalance in small feedback sets
        n_jobs=-1,
    )
    new_model.fit(X, y)

    elapsed = round(time.time() - t0, 2)
    logger.info("Retrain complete in %.2fs.", elapsed)

    # Overwrite the model file
    joblib.dump(new_model, model_path)
    logger.info("Model saved to %s", model_path)

    # Append to audit log
    log_entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "n_samples": n_samples,
        "n_spam": n_spam,
        "n_ham": n_ham,
        "elapsed_s": elapsed,
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

    return {
        "success": True,
        "n_samples": n_samples,
        "message": f"Model retrained on {n_samples} samples ({n_spam} spam, {n_ham} ham) in {elapsed}s.",
    }


# ── Status ────────────────────────────────────────────────────────────────────

def get_status(store_path: str, log_path: str) -> dict:
    """
    Return learning status information for the /learning-status endpoint.
    """
    # Count stored samples
    n_samples = 0
    if os.path.exists(store_path):
        with open(store_path, "r", encoding="utf-8") as f:
            n_samples = sum(1 for line in f if line.strip())

    # Find last retrain timestamp
    last_retrained = None
    last_retrain_samples = None
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        if lines:
            try:
                last = json.loads(lines[-1])
                last_retrained = last.get("ts")
                last_retrain_samples = last.get("n_samples")
            except (json.JSONDecodeError, KeyError):
                pass

    # Samples since last retrain
    samples_since_retrain = (
        n_samples - (last_retrain_samples or 0)
        if last_retrain_samples is not None
        else n_samples
    )

    return {
        "samples_collected": n_samples,
        "samples_since_last_retrain": samples_since_retrain,
        "next_retrain_in": max(0, RETRAIN_THRESHOLD - samples_since_retrain),
        "last_retrained": last_retrained,
        "retrain_threshold": RETRAIN_THRESHOLD,
    }
