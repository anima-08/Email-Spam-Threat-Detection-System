import os
import sys
import numpy as np
import pandas as pd
import joblib
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from scipy.sparse import hstack, csr_matrix

sys.path.insert(0, os.path.dirname(__file__))

from utils.preprocessing import clean_text, structural_features
from utils.threat_analysis import extract_urls
from utils.phishing_analyzer import analyze_phishing
from utils.spam_language_analyzer import analyze_spam_language
from utils.structural_analyzer import analyze_structure
from utils.attachment_analyzer import analyze_attachments

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

print("1. Loading dataset...")
ds = load_dataset('SetFit/enron_spam', split='train')

# Take a balanced subset to speed up training
df = ds.to_pandas()
df_spam = df[df['label'] == 1].sample(n=2500, random_state=42)
df_ham = df[df['label'] == 0].sample(n=2500, random_state=42)
df_sub = pd.concat([df_spam, df_ham]).sample(frac=1, random_state=42).reset_index(drop=True)

raw_texts = df_sub['text'].fillna('').tolist()
subjects = df_sub['subject'].fillna('').tolist()
messages = df_sub['message'].fillna('').tolist()
y = df_sub['label'].values

print("2. Extracting basic text features (TF-IDF, PCA)...")
cleaned_texts = [clean_text(t) for t in raw_texts]

# Fit Scaler for basic structural features
basic_structs = np.vstack([structural_features(r, c) for r, c in zip(raw_texts, cleaned_texts)])
scaler = MinMaxScaler()
basic_structs_scaled = scaler.fit_transform(basic_structs)

# Fit TF-IDF
tfidf = TfidfVectorizer(max_features=5000)
X_tfidf = tfidf.fit_transform(cleaned_texts)

# Combine for Selection
X_combined = hstack([csr_matrix(basic_structs_scaled), X_tfidf])
selector = SelectKBest(f_classif, k=min(1000, X_combined.shape[1]))
X_kbest = selector.fit_transform(X_combined, y)

# PCA
pca = PCA(n_components=min(100, X_kbest.shape[1]), random_state=42)
X_pca = pca.fit_transform(X_kbest.toarray())

print("3. Computing heuristic features for Super-Model fusion (this may take a minute)...")
heuristic_features = []
for i in range(len(raw_texts)):
    text = raw_texts[i]
    subj = subjects[i]
    body = messages[i]
    
    urls = extract_urls(text)
    url_count = len(urls)
    
    phishing_score = analyze_phishing(text, urls)['score_contribution']
    spam_lang_score = analyze_spam_language(text)['score_contribution']
    struct_score = analyze_structure(subj, body, url_count)['score_contribution']
    attach_score = analyze_attachments(text)['score_contribution']
    
    # We'll use 0 for sender score as Enron doesn't have sender reputation context
    heuristic_features.append([phishing_score, spam_lang_score, struct_score, attach_score])

heuristic_features = np.array(heuristic_features)

print("4. Fusing features and training Super-Model...")
X_fused = np.hstack([X_pca, heuristic_features])

model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight='balanced', n_jobs=-1)
model.fit(X_fused, y)

print("5. Saving all artifacts...")
joblib.dump(scaler, os.path.join(MODELS_DIR, 'feature_scaler.pkl'))
joblib.dump(tfidf, os.path.join(MODELS_DIR, 'tfidf_vectorizer.pkl'))
joblib.dump(selector, os.path.join(MODELS_DIR, 'feature_selector.pkl'))
joblib.dump(pca, os.path.join(MODELS_DIR, 'pca_transformer.pkl'))
joblib.dump(model, os.path.join(MODELS_DIR, 'spam_detector_model.pkl'))

print("Super-Model training complete and artifacts saved!")
