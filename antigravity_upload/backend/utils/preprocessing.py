"""
Preprocessing pipeline — mirrors the training pipeline from the notebook
(Email_Spam_And_Threat_Detection_Using_Machine_Learning_.ipynb) EXACTLY,
so live predictions stay consistent with the trained artifacts.

Pipeline recap (see notebook cells 17, 19, 31, 34, 64):
  1. lowercase + strip non-alpha chars -> remove stopwords            -> "clean" text
  2. structural features computed from the ORIGINAL raw text:
       text_length      = len(clean)
       num_words        = len(clean.split())
       num_digits       = count of digits in RAW text
       num_punctuation  = count of punctuation chars in RAW text
  3. MinMaxScaler on the 4 structural features
  4. TF-IDF (max_features=1000) on the clean text
  5. hstack(struct, tfidf) -> SelectKBest(k=150) -> TruncatedSVD(n_components=100)
"""
import re
import string

import nltk
from nltk.corpus import stopwords
from scipy.sparse import csr_matrix, hstack
import numpy as np

# Ensure stopwords are available (downloads once, then cached)
try:
    STOP_WORDS = set(stopwords.words("english"))
except LookupError:
    nltk.download("stopwords", quiet=True)
    STOP_WORDS = set(stopwords.words("english"))


def clean_text(raw_text: str) -> str:
    """Lowercase, strip non-alpha chars, remove stopwords."""
    text = str(raw_text).lower()
    text = re.sub(r"subject:\s*", "", text)
    text = re.sub(r"[^a-zA-Z\s]", "", text)
    words = [w for w in text.split() if w not in STOP_WORDS]
    return " ".join(words)


def structural_features(raw_text: str, clean: str) -> np.ndarray:
    """4 structural features, matching predict_single_email() in the notebook."""
    return np.array(
        [[
            len(clean),
            len(clean.split()),
            sum(1 for c in str(raw_text) if c.isdigit()),
            sum(1 for c in str(raw_text) if c in string.punctuation),
        ]],
        dtype=float,
    )


def build_feature_vector(raw_text: str, artifacts: dict):
    """
    Runs the full preprocessing pipeline and returns the final
    PCA-reduced feature vector ready for model.predict().
    """
    clean = clean_text(raw_text)

    feats = structural_features(raw_text, clean)
    feats_scaled = artifacts["scaler"].transform(feats)

    x_tfidf = artifacts["tfidf"].transform([clean])
    x_struct = csr_matrix(feats_scaled)
    x_combined = hstack([x_struct, x_tfidf])

    x_kbest = artifacts["selector"].transform(x_combined)
    x_pca = artifacts["pca"].transform(x_kbest)

    return x_pca, clean
