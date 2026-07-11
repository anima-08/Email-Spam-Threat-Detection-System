# 🛡️ SpamShield — ML-Powered Email Threat Detection

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/WAYMAKER1802/Spam-Email/ci.yml?branch=main)
![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-Backend-black?logo=flask)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-green?logo=googlechrome)
![Machine Learning](https://img.shields.io/badge/ML-Random_Forest-orange)

**SpamShield** is a real-time, Machine Learning-powered Chrome Extension and Flask Backend designed to protect you from email spam, phishing attacks, and malicious URLs directly inside Gmail.

By extracting email text and subject from the Gmail DOM, the extension queries a backend REST API that uses a trained Random Forest model. It immediately returns actionable insights: a **Spam or Ham** verdict, a comprehensive **Threat Score**, and heuristics-based URL reputation checks.

---

## 🌟 Key Features

- **Real-Time Gmail Integration:** Click the SpamShield icon on any open Gmail email to run an instant analysis.
- **ML Verdict & Confidence:** Returns a Spam/Ham classification along with exact confidence percentages.
- **Threat Score & Risk Level:** Visual 0–100 threat meter and categorical risk badging (Low, Medium, High, Critical).
- **Suspicious Keyword Highlighting:** Identifies and highlights phishing/urgency triggers in your email text.
- **URL Reputation Heuristics:** Scans all URLs in the email body for suspicious TLDs, missing HTTPS, URL shorteners, and structural anomalies.
- **Continuous Integration (CI/CD):** Automated Python testing and Bandit security scanning on every push via GitHub Actions.

---

## 🏗️ Architecture

1. **The Extension (`/extension`)**: A Manifest V3 Chrome Extension that reads the active Gmail tab, extracts text, and presents the UI pop-up to the user.
2. **The Backend (`/antigravity_upload/backend`)**: A Flask REST API that applies structural text preprocessing, TF-IDF vectorization, PCA, and a Random Forest Classifier to detect threats.

---

## 🚀 Getting Started

To get the full SpamShield experience running locally, you need to start the backend and load the unpacked extension into Chrome.

### 1. Start the Backend

Make sure you have your 5 trained model `.pkl` files placed inside `antigravity_upload/backend/models/`.

```bash
cd antigravity_upload/backend
python -m venv venv

# Activate the virtual environment
venv\Scripts\activate        # On Windows
# source venv/bin/activate   # On macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Start the Flask API
python app.py
```
*The server will start locally at `http://localhost:5000`.*

### 2. Load the Chrome Extension

1. Open Chrome and navigate to `chrome://extensions`.
2. Toggle **Developer mode** on (top-right corner).
3. Click **Load unpacked** in the top-left menu.
4. Select the `extension/` folder in this repository.
5. The SpamShield icon will appear in your browser toolbar!

### 3. Usage

1. Go to [Gmail](https://mail.google.com) and open an email.
2. Click the SpamShield extension icon.
3. Click **Scan Email**.
4. Review the ML verdict, threat score, flagged keywords, and suspicious URLs!

---

## 📁 Repository Structure

```text
├── .github/workflows/          # GitHub Actions CI/CD Pipeline
├── antigravity_upload/
│   └── backend/                # Flask API and ML pipeline scripts
│       ├── models/             # Directory for .pkl ML models
│       ├── utils/              # Preprocessing & Threat Analysis logic
│       ├── app.py              # Main Flask application
│       └── requirements.txt    # Python dependencies
├── extension/                  # Chrome Extension Source Code
│   ├── background.js           # MV3 Service Worker
│   ├── content.js              # Injected Gmail DOM scraper
│   ├── manifest.json           # Extension config
│   └── popup.html/.js/.css     # Extension UI
└── README.md                   # You are here!
```

---

## 🛡️ CI/CD Pipeline

This project uses **GitHub Actions** to automatically test the code and scan for security vulnerabilities using **Bandit**. Any push or pull request to the `main` branch will trigger the pipeline (`.github/workflows/ci.yml`).

---

## 🤝 Contributing

Feel free to fork the repository and submit pull requests. Ensure that the GitHub Actions pipeline passes successfully before requesting a review.
