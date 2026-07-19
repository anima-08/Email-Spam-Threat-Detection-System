"""
spam_language_analyzer.py — Weighted spam-signal detection engine.

Loads structured signal definitions from config/spam_signals.json and
analyzes email text for matching phrases. Returns matched signals with
categories, severity, per-category counts, and a capped score contribution.

Design principles (from NIST Phish Scale and SpamAssassin):
  - Context matters: severity weights prevent a single low-risk word from
    causing a false positive.
  - Category caps: a single category contributes at most MAX_PER_CATEGORY
    points, preventing keyword-stuffing from dominating the score.
  - Deduplication: overlapping phrase matches at the same text position
    count only once.
  - Total cap: keyword contribution is bounded at MAX_TOTAL_CONTRIBUTION
    regardless of how many signals match.

Sources:
  - ActiveCampaign "188 Spam Words to Avoid" (2024)
  - SpamAssassin scoring rules
  - NIST Phish Scale (NIST TN 2276)
"""

import json
import os
import re

# ── Config ────────────────────────────────────────────────────────────────────

_SIGNALS_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "spam_signals.json")

# Severity → raw point value for a single match
SEVERITY_POINTS = {1: 1, 2: 2, 3: 4}

# Maximum points any single category can contribute
MAX_PER_CATEGORY = 8

# Maximum total points from all spam-language signals
MAX_TOTAL_CONTRIBUTION = 25


def _load_signals():
    """Load signal definitions from JSON config. Cached after first load."""
    with open(_SIGNALS_PATH, encoding="utf-8") as f:
        data = json.load(f)
    # Sort by phrase length descending so longer phrases match first
    signals = sorted(data["signals"], key=lambda s: len(s["phrase"]), reverse=True)
    return signals


_SIGNALS = None


def _get_signals():
    global _SIGNALS
    if _SIGNALS is None:
        _SIGNALS = _load_signals()
    return _SIGNALS


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze_spam_language(text: str) -> dict:
    """
    Scan email text for spam-signal phrases.

    Args:
        text: Raw email text (subject + body combined).

    Returns a dict with:
        matched_signals   : list of matched signal dicts (phrase, category,
                            severity, explanation)
        category_summary  : {category: count_of_matches}
        score_contribution: int 0–MAX_TOTAL_CONTRIBUTION
        top_categories    : list of (category, count) sorted by count desc
    """
    if not text:
        return _empty_result()

    lower = text.lower()
    signals = _get_signals()

    matched = []
    seen_positions = set()  # (start, end) spans already claimed by a match

    for signal in signals:
        phrase = signal["phrase"].lower()
        # Use word-boundary aware search when possible
        try:
            pattern = re.compile(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)")
        except re.error:
            pattern = re.compile(re.escape(phrase))

        for m in pattern.finditer(lower):
            span = (m.start(), m.end())
            # Skip if this span overlaps a previously matched span
            if any(span[0] < e and span[1] > s for s, e in seen_positions):
                continue
            seen_positions.add(span)
            matched.append(signal)
            break  # count each phrase only once per text, regardless of occurrences

    # Aggregate by category
    category_counts: dict = {}
    category_scores: dict = {}

    for sig in matched:
        cat = sig["category"]
        sev = sig.get("severity", 1)
        pts = SEVERITY_POINTS.get(sev, 1)
        category_counts[cat] = category_counts.get(cat, 0) + 1
        category_scores[cat] = category_scores.get(cat, 0) + pts

    # Apply per-category cap
    total = 0
    for cat, raw in category_scores.items():
        total += min(raw, MAX_PER_CATEGORY)

    # Apply global cap
    score_contribution = min(total, MAX_TOTAL_CONTRIBUTION)

    top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)

    return {
        "matched_signals": matched,
        "category_summary": category_counts,
        "score_contribution": score_contribution,
        "top_categories": top_categories,
        "signal_count": len(matched),
    }


def _empty_result() -> dict:
    return {
        "matched_signals": [],
        "category_summary": {},
        "score_contribution": 0,
        "top_categories": [],
        "signal_count": 0,
    }
