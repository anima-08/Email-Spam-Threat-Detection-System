"""
structural_analyzer.py — Email structural anomaly detection.

Analyzes formatting and structural patterns in email text that are
associated with spam and phishing, independent of keyword content.

Signals based on:
  - SpamAssassin scoring rules (BAYES_00, CAPS_EXCESSIVE, etc.)
  - Google Gmail spam filter documentation (formatting signals)
  - Microsoft Outlook junk filter criteria (HTML/text anomalies)

Signals detected:
  - Excessive ALL CAPS word ratio
  - Excessive exclamation marks
  - Subject line ALL CAPS
  - Very short body with a URL (typical for one-liner phishing)
  - URL density (ratio of URLs to total text words)
  - Suspicious character stuffing (!!!, $$$, ...)

All scores are capped at MAX_STRUCTURAL_SCORE.
"""

import re

MAX_STRUCTURAL_SCORE = 10


def analyze_structure(subject: str, body: str, url_count: int) -> dict:
    """
    Analyze structural features of an email.

    Args:
        subject  : Email subject line text.
        body     : Email body text.
        url_count: Number of URLs found in the email.

    Returns a dict with:
        flags              : list of {signal, explanation, contribution}
        score_contribution : int 0–MAX_STRUCTURAL_SCORE
    """
    flags = []
    total_score = 0
    text = ((subject or "") + " " + (body or "")).strip()

    if not text:
        return {"flags": [], "score_contribution": 0}

    words = text.split()
    word_count = len(words)

    # ── 1. ALL CAPS word ratio ────────────────────────────────────────────────
    if word_count >= 5:
        caps_words = [w for w in words if w.isupper() and len(w) > 2 and w.isalpha()]
        caps_ratio = len(caps_words) / word_count
        if caps_ratio >= 0.40:
            pts = 4
            flags.append({
                "signal": "excessive_caps",
                "explanation": f"{int(caps_ratio * 100)}% of words are in ALL CAPS — strong spam formatting signal.",
                "contribution": pts,
            })
            total_score += pts
        elif caps_ratio >= 0.25:
            pts = 2
            flags.append({
                "signal": "high_caps",
                "explanation": f"{int(caps_ratio * 100)}% of words are in ALL CAPS.",
                "contribution": pts,
            })
            total_score += pts

    # ── 2. Subject ALL CAPS ───────────────────────────────────────────────────
    if subject:
        subj_words = subject.split()
        subj_caps = [w for w in subj_words if w.isupper() and len(w) > 2 and w.isalpha()]
        if len(subj_words) >= 2 and len(subj_caps) / len(subj_words) >= 0.60:
            pts = 3
            flags.append({
                "signal": "subject_caps",
                "explanation": "Subject line is predominantly in ALL CAPS — a strong spam formatting signal.",
                "contribution": pts,
            })
            total_score += pts

    # ── 3. Exclamation mark overuse ───────────────────────────────────────────
    exclamation_count = text.count("!")
    if exclamation_count >= 5:
        pts = 3
        flags.append({
            "signal": "excessive_exclamations",
            "explanation": f"{exclamation_count} exclamation marks detected — spam emails frequently use excessive punctuation.",
            "contribution": pts,
        })
        total_score += pts
    elif exclamation_count >= 3:
        pts = 1
        flags.append({
            "signal": "multiple_exclamations",
            "explanation": f"{exclamation_count} exclamation marks detected.",
            "contribution": pts,
        })
        total_score += pts

    # ── 4. Very short body with URL ───────────────────────────────────────────
    body_words = (body or "").split()
    if url_count >= 1 and len(body_words) < 20:
        pts = 3
        flags.append({
            "signal": "short_body_with_url",
            "explanation": f"Very short email body ({len(body_words)} words) containing a URL — typical of one-liner phishing.",
            "contribution": pts,
        })
        total_score += pts

    # ── 5. URL density ────────────────────────────────────────────────────────
    if word_count > 0 and url_count >= 3:
        url_density = url_count / word_count
        if url_density > 0.05:
            pts = 2
            flags.append({
                "signal": "high_url_density",
                "explanation": f"{url_count} URLs in {word_count} words — unusually high link density.",
                "contribution": pts,
            })
            total_score += pts

    # ── 6. Currency symbol stuffing ───────────────────────────────────────────
    dollar_count = text.count("$")
    if dollar_count >= 4:
        pts = 2
        flags.append({
            "signal": "currency_stuffing",
            "explanation": f"{dollar_count} dollar signs detected — heavy financial emphasis typical of spam.",
            "contribution": pts,
        })
        total_score += pts

    score_contribution = min(total_score, MAX_STRUCTURAL_SCORE)
    return {
        "flags": flags,
        "score_contribution": score_contribution,
    }
