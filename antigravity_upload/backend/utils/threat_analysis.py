"""
Heuristic threat-analysis helpers that sit ALONGSIDE the ML model prediction:
- URL extraction + lightweight reputation scoring (no external API required,
  but structured so a real reputation API — Google Safe Browsing, VirusTotal,
  etc. — can be dropped in later, see `check_url_reputation`)
- Phishing / urgency keyword detection + highlighting
- Combined threat score (0-100) and risk level bucket
"""
import re

URL_REGEX = re.compile(
    r"(?:(?:https?|ftp)://|www\.)[^\s<>\"']+"          # scheme:// or www.
    r"|\b[a-z0-9-]+\.(?:ly|gl|gy|gd|xyz|top|club|work|click|loan|gq|tk|st|co)\/[^\s<>\"']*",
    re.IGNORECASE,
)

IP_URL_REGEX = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "shorte.st", "cutt.ly", "rb.gy",
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".work", ".click", ".loan", ".gq", ".tk"}

# Phishing / social-engineering trigger words (kept at pattern level —
# grouped loosely, not meant to be exhaustive)
PHISHING_KEYWORDS = [
    "urgent", "verify your account", "verify account", "suspended", "click here",
    "act now", "limited time", "congratulations", "you have won", "free gift",
    "claim your prize", "winner", "confirm your identity", "update your payment",
    "password expired", "security alert", "unusual activity", "wire transfer",
    "bank account", "social security", "gift card", "act immediately",
    "your account will be", "reset your password", "login attempt",
]


def extract_urls(text: str):
    return list(dict.fromkeys(URL_REGEX.findall(text or "")))


def check_url_reputation(url: str) -> dict:
    """
    Lightweight, offline heuristic reputation check.
    Swap in a real API call here (e.g. Google Safe Browsing) for production use.
    """
    reasons = []
    score = 0  # 0 = looks fine, higher = more suspicious

    lower = url.lower()

    if IP_URL_REGEX.match(url):
        reasons.append("Uses a raw IP address instead of a domain name")
        score += 40

    if not lower.startswith("https://"):
        reasons.append("Not using HTTPS")
        score += 15

    domain_match = re.search(r"https?://([^/]+)", lower)
    domain = domain_match.group(1) if domain_match else lower

    if any(short in domain for short in URL_SHORTENERS):
        reasons.append("Uses a URL shortener (destination is hidden)")
        score += 25

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("Uses a TLD commonly associated with spam/phishing")
        score += 20

    if domain.count("-") >= 3:
        reasons.append("Domain contains an unusually high number of hyphens")
        score += 10

    if len(domain) > 40:
        reasons.append("Unusually long domain name")
        score += 10

    score = min(score, 100)
    verdict = "Suspicious" if score >= 30 else "Likely Safe"

    return {"url": url, "risk_score": score, "verdict": verdict, "reasons": reasons}


def find_phishing_keywords(text: str):
    lower = (text or "").lower()
    return [kw for kw in PHISHING_KEYWORDS if kw in lower]


def compute_threat_score(
    spam_probability: float,
    url_reports: list,
    matched_keywords: list,
    sender_score: int = 0,
) -> int:
    """
    Combines the ML model's spam probability with URL, keyword, and sender
    reputation signals into a single 0-100 threat score.

    Weights:
      ML model spam probability  → up to 50 pts
      Sender reputation          → up to 20 pts
      Worst URL risk score       → up to 18 pts
      Keyword matches            → up to 12 pts
    """
    score = spam_probability * 50

    score += (sender_score / 100) * 20

    if url_reports:
        worst_url_score = max(r["risk_score"] for r in url_reports)
        score += (worst_url_score / 100) * 18

    score += min(len(matched_keywords), 4) * 3  # up to +12

    return int(round(min(score, 100)))


def risk_level_from_score(threat_score: int) -> str:
    if threat_score >= 75:
        return "Critical"
    if threat_score >= 50:
        return "High"
    if threat_score >= 25:
        return "Medium"
    return "Low"
