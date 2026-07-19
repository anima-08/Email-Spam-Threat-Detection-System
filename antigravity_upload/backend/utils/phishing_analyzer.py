"""
phishing_analyzer.py — Combination-based phishing pattern detection.

Detects phishing by looking for *combinations* of signals rather than
isolated keywords. A single word like "urgent" is a weak signal; but
"urgent" + "verify your account" + a URL present is a strong phishing
indicator.

Approach based on:
  - NIST Phish Scale (NIST TN 2276): rates phishing difficulty by combining
    cues across urgency, authority, context, and visual presentation.
  - CISA phishing guidance: emphasizes sender mismatch + urgency + link as
    the classic phishing trifecta.
  - Microsoft Anti-Phishing documentation: identifies pattern families like
    credential theft, business email compromise, prize fraud.

Each pattern has:
  - name          : machine-readable pattern identifier
  - label         : human-readable name
  - severity      : "Low", "Medium", "High", "Critical"
  - score         : points contributed to threat score (0–30 total cap)
  - required_any  : list of keyword groups — at least one keyword from each
                    group must be present for the pattern to fire
  - url_required  : bool — a URL must be present in the email
  - explanation   : human-readable description for the UI

Design note: patterns are checked as AND-conditions across groups, making
false positives rare and specificity high.
"""

import re

# ── Phishing pattern definitions ──────────────────────────────────────────────
# Each pattern fires when ALL required_any groups have ≥1 match.

PHISHING_PATTERNS = [
    {
        "name": "credential_theft",
        "label": "Credential Theft Attempt",
        "severity": "Critical",
        "score": 28,
        "required_any": [
            ["urgent", "immediately", "right away", "act now", "right now"],
            ["verify", "confirm", "validate", "authenticate"],
            ["account", "password", "login", "credentials", "sign in"],
        ],
        "url_required": True,
        "explanation": "Urgency + account/credential language + a link — classic phishing trifecta for credential theft.",
    },
    {
        "name": "account_suspension_threat",
        "label": "Account Suspension Threat",
        "severity": "High",
        "score": 22,
        "required_any": [
            ["suspended", "locked", "disabled", "closed", "deactivated", "restricted", "blocked"],
            ["account", "profile", "access", "service"],
        ],
        "url_required": False,
        "explanation": "Account suspension or lockout threat — used to create panic and force rapid action.",
    },
    {
        "name": "payment_fraud",
        "label": "Payment or Billing Fraud",
        "severity": "High",
        "score": 22,
        "required_any": [
            ["payment", "billing", "invoice", "transaction", "charge", "fee"],
            ["update", "confirm", "verify", "failed", "declined", "overdue", "past due"],
        ],
        "url_required": True,
        "explanation": "Payment/billing language combined with an update request and a link — typical payment fraud phishing.",
    },
    {
        "name": "prize_reward_scam",
        "label": "Prize or Reward Scam",
        "severity": "High",
        "score": 20,
        "required_any": [
            ["won", "winner", "prize", "reward", "selected", "chosen", "lucky"],
            ["claim", "collect", "redeem", "receive"],
        ],
        "url_required": False,
        "explanation": "Prize/reward notification combined with a claim action — advance-fee fraud or phishing for personal data.",
    },
    {
        "name": "security_alert_impersonation",
        "label": "Security Alert Impersonation",
        "severity": "High",
        "score": 20,
        "required_any": [
            ["security alert", "security notice", "unusual activity", "suspicious activity",
             "unauthorized access", "unusual sign-in", "login attempt", "suspicious login"],
            ["verify", "confirm", "review", "check", "click", "link"],
        ],
        "url_required": False,
        "explanation": "Security alert language combined with a verification request — impersonation of security services.",
    },
    {
        "name": "fake_delivery_notification",
        "label": "Fake Delivery Notification",
        "severity": "Medium",
        "score": 14,
        "required_any": [
            ["package", "parcel", "delivery", "shipment", "tracking", "courier",
             "fedex", "ups", "dhl", "usps", "royal mail"],
            ["failed", "held", "pending", "undeliverable", "reschedule", "confirm address",
             "update address", "pay fee", "customs fee"],
        ],
        "url_required": True,
        "explanation": "Fake delivery failure combined with a link — used to redirect victims to phishing pages or charge fake fees.",
    },
    {
        "name": "financial_information_request",
        "label": "Financial Information Request",
        "severity": "Critical",
        "score": 28,
        "required_any": [
            ["bank account", "routing number", "sort code", "wire transfer", "western union",
             "moneygram", "bitcoin", "crypto", "gift card", "prepaid card"],
            ["send", "transfer", "provide", "share", "pay"],
        ],
        "url_required": False,
        "explanation": "Direct request for financial information or untraceable payment — hallmark of advance-fee and BEC fraud.",
    },
    {
        "name": "personal_info_harvest",
        "label": "Personal Information Harvesting",
        "severity": "High",
        "score": 18,
        "required_any": [
            ["social security", "ssn", "national insurance", "date of birth", "mother's maiden",
             "passport", "driver's license", "id number"],
            ["provide", "send", "enter", "submit", "confirm", "give us"],
        ],
        "url_required": False,
        "explanation": "Request for government-issued ID or sensitive personal data — identity theft pattern.",
    },
    {
        "name": "tax_scam",
        "label": "Tax Refund or Authority Scam",
        "severity": "High",
        "score": 18,
        "required_any": [
            ["tax refund", "irs", "hmrc", "tax authority", "tax return", "tax rebate",
             "overdue tax", "tax penalty"],
            ["claim", "collect", "verify", "confirm", "pay", "submit"],
        ],
        "url_required": False,
        "explanation": "Tax authority impersonation — used to steal financial data or payments.",
    },
    {
        "name": "job_offer_scam",
        "label": "Fake Job or Work-from-Home Offer",
        "severity": "Medium",
        "score": 12,
        "required_any": [
            ["job offer", "work from home", "remote position", "earn from home",
             "no experience required", "hiring immediately", "start today"],
            ["apply now", "click here", "register", "sign up", "fill out"],
        ],
        "url_required": True,
        "explanation": "Unsolicited job offer with an application link — often leads to data harvesting or advance-fee fraud.",
    },
]

# Maximum total score contribution from phishing patterns
MAX_PHISHING_SCORE = 30


def analyze_phishing(text: str, urls: list) -> dict:
    """
    Detect phishing pattern combinations in email text.

    Args:
        text: Raw email text (subject + body).
        urls: List of URL strings extracted from the email.

    Returns a dict with:
        phishing_patterns  : list of fired pattern dicts
        score_contribution : int 0–MAX_PHISHING_SCORE
        highest_severity   : str ("Low"/"Medium"/"High"/"Critical" or None)
    """
    if not text:
        return _empty_result()

    lower = text.lower()
    has_urls = bool(urls)

    fired_patterns = []

    for pattern in PHISHING_PATTERNS:
        # Check URL requirement
        if pattern["url_required"] and not has_urls:
            continue

        # Check all required_any groups — all must have at least one match
        all_groups_match = True
        matched_keywords = []

        for keyword_group in pattern["required_any"]:
            group_matched = False
            for kw in keyword_group:
                if kw.lower() in lower:
                    matched_keywords.append(kw)
                    group_matched = True
                    break
            if not group_matched:
                all_groups_match = False
                break

        if all_groups_match:
            fired_patterns.append({
                "pattern_name": pattern["name"],
                "label": pattern["label"],
                "severity": pattern["severity"],
                "score": pattern["score"],
                "matched_keywords": matched_keywords,
                "explanation": pattern["explanation"],
                "url_required": pattern["url_required"],
            })

    # Deduplicate: if multiple patterns fire, take the top-N by score
    # but cap the total contribution to avoid runaway scoring.
    # Sort by score descending, then take the highest + partial credit for others.
    fired_patterns.sort(key=lambda p: p["score"], reverse=True)

    total_score = 0
    for i, p in enumerate(fired_patterns):
        if i == 0:
            total_score += p["score"]
        else:
            # Diminishing returns for additional patterns (50% credit)
            total_score += p["score"] // 2

    score_contribution = min(total_score, MAX_PHISHING_SCORE)

    severity_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    highest_severity = None
    if fired_patterns:
        highest_severity = max(
            fired_patterns, key=lambda p: severity_order.get(p["severity"], 0)
        )["severity"]

    return {
        "phishing_patterns": fired_patterns,
        "score_contribution": score_contribution,
        "highest_severity": highest_severity,
        "pattern_count": len(fired_patterns),
    }


def _empty_result() -> dict:
    return {
        "phishing_patterns": [],
        "score_contribution": 0,
        "highest_severity": None,
        "pattern_count": 0,
    }
