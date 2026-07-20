import re
import string
import nltk
from nltk.corpus import stopwords
from scipy.sparse import csr_matrix, hstack
import numpy as np
try:
    STOP_WORDS = set(stopwords.words('english'))
except LookupError:
    nltk.download('stopwords', quiet=True)
    STOP_WORDS = set(stopwords.words('english'))

def clean_text(raw_text: str) -> str:
    text = str(raw_text).lower()
    text = re.sub('subject:\\s*', '', text)
    text = re.sub('[^a-zA-Z\\s]', '', text)
    words = [w for w in text.split() if w not in STOP_WORDS]
    return ' '.join(words)

def structural_features(raw_text: str, clean: str) -> np.ndarray:
    return np.array([[len(clean), len(clean.split()), sum((1 for c in str(raw_text) if c.isdigit())), sum((1 for c in str(raw_text) if c in string.punctuation))]], dtype=float)

def build_feature_vector(raw_text: str, artifacts: dict):
    clean = clean_text(raw_text)
    feats = structural_features(raw_text, clean)
    feats_scaled = artifacts['scaler'].transform(feats)
    x_tfidf = artifacts['tfidf'].transform([clean])
    x_struct = csr_matrix(feats_scaled)
    x_combined = hstack([x_struct, x_tfidf])
    x_kbest = artifacts['selector'].transform(x_combined)
    x_pca = artifacts['pca'].transform(x_kbest)
    return (x_pca, clean)
