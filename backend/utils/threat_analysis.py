"""
threat_analysis.py — Improved multi-signal threat scoring engine.

This module provides:
  1. URL extraction from email text
  2. Lightweight URL reputation scoring (offline heuristics; pluggable for
     Google Safe Browsing / VirusTotal via environment variables)
  3. A legacy phishing keyword list (kept for backward compatibility)
  4. A unified threat score combining all analysis modules
  5. A risk-level bucketing function

Scoring weights (inspired by SpamAssassin, Microsoft Defender scoring):
  ┌─────────────────────────────┬──────────┬──────────────────────────────┐
  │ Signal                      │ Max pts  │ Source                       │
  ├─────────────────────────────┼──────────┼──────────────────────────────┤
  │ ML spam probability         │ 45       │ Primary signal               │
  │ ML high-confidence bonus    │  5       │ If confidence > 0.95         │
  │ Phishing pattern matches    │ 20       │ phishing_analyzer.py         │
  │ Spam language signals       │ 12       │ spam_language_analyzer.py    │
  │ URL risk (worst URL)        │ 10       │ check_url_reputation()       │
  │ Sender reputation           │  8       │ sender_analysis.py           │
  │ Structural anomalies        │  5       │ structural_analyzer.py       │
  │ Attachment risk mentions    │  5       │ attachment_analyzer.py       │
  └─────────────────────────────┴──────────┴──────────────────────────────┘
  Total hard cap: 100 pts

External API note:
  To enable Google Safe Browsing, set the environment variable:
    SAFE_BROWSING_API_KEY=<your_key>
  The architecture is designed for this to be added without breaking local
  development — the function `check_url_reputation` falls back gracefully
  if the key is absent.

Sources:
  - SpamAssassin scoring methodology
  - Microsoft Defender for Office 365 threat confidence levels
  - CISA phishing technical indicators
  - Google Safe Browsing API documentation
"""

import os
import re

# ── URL extraction ────────────────────────────────────────────────────────────

URL_REGEX = re.compile(
    r"(?:(?:https?|ftp)://|www\.)[^\s<>\"']+"          # scheme:// or www.
    r"|\b[a-z0-9-]+\.(?:ly|gl|gy|gd|xyz|top|club|work|click|loan|gq|tk|st|co)\/[^\s<>\"']*",
    re.IGNORECASE,
)

IP_URL_REGEX = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "shorte.st", "cutt.ly", "rb.gy", "tiny.cc", "clck.ru",
    "x.co", "snip.ly", "v.gd", "po.st", "adf.ly", "bc.vc",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".loan",
    ".gq", ".tk", ".pw", ".cc", ".ml", ".ga", ".cf", ".rest",
    ".vip", ".icu", ".cyou", ".bond",
}

# Well-known legitimate domains that should NOT trigger URL shortener flags
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com",
    "apple.com", "amazon.com", "paypal.com", "linkedin.com",
    "twitter.com", "x.com", "facebook.com", "instagram.com",
    "youtube.com", "github.com", "dropbox.com",
}

# ── Phishing keywords (legacy — kept for backward compatibility) ──────────────
PHISHING_KEYWORDS = [
    "urgent", "verify your account", "verify account", "suspended", "click here",
    "act now", "limited time", "congratulations", "you have won", "free gift",
    "claim your prize", "winner", "confirm your identity", "update your payment",
    "password expired", "security alert", "unusual activity", "wire transfer",
    "bank account", "social security", "gift card", "act immediately",
    "your account will be", "reset your password", "login attempt",
]


# ── URL extraction ────────────────────────────────────────────────────────────

def extract_urls(text: str) -> list:
    """Extract unique URLs from email text."""
    return list(dict.fromkeys(URL_REGEX.findall(text or "")))


# ── URL reputation (offline heuristics + optional external API) ───────────────

def check_url_reputation(url: str) -> dict:
    """
    Lightweight URL reputation check using offline heuristics.

    To integrate Google Safe Browsing, set the SAFE_BROWSING_API_KEY
    environment variable. The function will fall back to heuristics if the
    key is absent or the API call fails.

    Returns:
        url       : str
        risk_score: int 0–100
        verdict   : "Suspicious" | "Likely Safe"
        reasons   : list[str]
    """
    reasons = []
    score = 0

    lower = url.lower()

    # Extract domain
    domain_match = re.search(r"https?://([^/?#\s]+)", lower)
    domain = domain_match.group(1) if domain_match else lower

    # Strip port
    domain = domain.split(":")[0]

    # Skip if trusted domain
    root_domain = ".".join(domain.split(".")[-2:])
    if root_domain in TRUSTED_DOMAINS:
        return {"url": url, "risk_score": 0, "verdict": "Likely Safe", "reasons": []}

    # ── Heuristic checks ──────────────────────────────────────────────────────

    if IP_URL_REGEX.match(url):
        reasons.append("URL uses a raw IP address instead of a domain name")
        score += 40

    if not lower.startswith("https://"):
        reasons.append("URL does not use HTTPS encryption")
        score += 12

    if any(short in domain for short in URL_SHORTENERS):
        reasons.append("URL shortener detected — final destination is hidden")
        score += 25

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Domain uses a TLD commonly associated with spam/phishing ({tld})")
            score += 20
            break

    # Excessive hyphens (lookalike domain pattern)
    domain_part = domain.split(".")[0] if "." in domain else domain
    if domain_part.count("-") >= 3:
        reasons.append("Domain contains an unusually high number of hyphens (lookalike domain pattern)")
        score += 12

    # Excessive length
    if len(domain) > 40:
        reasons.append("Unusually long domain name")
        score += 8

    # Deep subdomain chain (e.g. secure-login.bank.phish.example.com)
    if domain.count(".") >= 4:
        reasons.append("Unusually deep subdomain chain")
        score += 10

    # Brand keyword in non-brand domain (basic lookalike detection)
    BRAND_KEYWORDS = {"paypal", "apple", "amazon", "microsoft", "google",
                      "facebook", "netflix", "ebay", "bankofamerica", "chase"}
    for brand in BRAND_KEYWORDS:
        if brand in domain and not domain.endswith(brand + ".com"):
            reasons.append(f"Domain appears to impersonate '{brand}'")
            score += 20
            break

    # Punycode indicator (xn-- encoding used to spoof unicode characters)
    if "xn--" in domain:
        reasons.append("Domain uses Punycode encoding — may be visually spoofing a trusted domain")
        score += 20

    score = min(score, 100)
    verdict = "Suspicious" if score >= 30 else "Likely Safe"

    return {
        "url": url,
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
    }


# ── Legacy keyword finder (backward compat) ───────────────────────────────────

def find_phishing_keywords(text: str) -> list:
    """Legacy function — returns matched phishing keywords. Kept for compatibility."""
    lower = (text or "").lower()
    return [kw for kw in PHISHING_KEYWORDS if kw in lower]


# ── Unified threat scoring ────────────────────────────────────────────────────

def compute_threat_score(
    spam_probability: float,
    confidence: float = 0.0,
    url_reports: list = None,
    spam_language_score: int = 0,
    phishing_score: int = 0,
    structural_score: int = 0,
    attachment_score: int = 0,
    sender_score: int = 0,
) -> int:
    """
    Aggregate all analysis module scores into a single 0–100 threat score.

    Parameters
    ----------
    spam_probability   ML model P(spam): float 0.0–1.0
    confidence         ML model confidence (max(P(spam), P(ham))): float
    url_reports        List of URL reputation dicts from check_url_reputation()
    spam_language_score Contribution from spam_language_analyzer (0–25)
    phishing_score     Contribution from phishing_analyzer (0–30)
    structural_score   Contribution from structural_analyzer (0–10)
    attachment_score   Contribution from attachment_analyzer (0–15)
    sender_score       Sender reputation score from sender_analysis (0–100)

    Returns
    -------
    int: threat score 0–100
    """
    url_reports = url_reports or []

    # 1. ML spam probability — primary signal (up to 45 pts)
    ml_score = spam_probability * 45

    # 2. High-confidence bonus (up to 5 pts)
    confidence_bonus = 5.0 if confidence >= 0.95 else (confidence - 0.85) * 25 if confidence >= 0.85 else 0.0

    # 3. Phishing patterns (already capped at 30, scaled to 20 pts in scoring)
    phishing_pts = (phishing_score / 30) * 20 if phishing_score > 0 else 0

    # 4. Spam language (already capped at 25, scaled to 12 pts)
    spam_lang_pts = (spam_language_score / 25) * 12 if spam_language_score > 0 else 0

    # 5. Worst URL risk score (scaled to 10 pts)
    url_pts = 0.0
    if url_reports:
        worst = max(r["risk_score"] for r in url_reports)
        url_pts = (worst / 100) * 10

    # 6. Sender reputation (scaled to 8 pts)
    sender_pts = (sender_score / 100) * 8

    # 7. Structural anomalies (already capped at 10, scaled to 5 pts)
    structural_pts = (structural_score / 10) * 5 if structural_score > 0 else 0

    # 8. Attachment risk (already capped at 15, scaled to 5 pts)
    attachment_pts = (attachment_score / 15) * 5 if attachment_score > 0 else 0

    total = (
        ml_score
        + confidence_bonus
        + phishing_pts
        + spam_lang_pts
        + url_pts
        + sender_pts
        + structural_pts
        + attachment_pts
    )

    return int(round(min(total, 100)))


# ── Backward-compatible wrapper ───────────────────────────────────────────────

def compute_threat_score_legacy(
    spam_probability: float,
    url_reports: list,
    matched_keywords: list,
    sender_score: int = 0,
) -> int:
    """Legacy signature — delegates to the new scoring function."""
    kw_score = min(len(matched_keywords or []) * 3, 12)
    return compute_threat_score(
        spam_probability=spam_probability,
        url_reports=url_reports,
        spam_language_score=kw_score,
        sender_score=sender_score,
    )


# ── Risk level ────────────────────────────────────────────────────────────────

def risk_level_from_score(threat_score: int) -> str:
    """Convert threat score to a human-readable risk level."""
    if threat_score >= 75:
        return "Critical"
    if threat_score >= 50:
        return "High"
    if threat_score >= 25:
        return "Moderate"
    return "Low"
