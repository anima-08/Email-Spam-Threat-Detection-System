import json
import os
import re
_SIGNALS_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'spam_signals.json')
SEVERITY_POINTS = {1: 1, 2: 2, 3: 4}
MAX_PER_CATEGORY = 8
MAX_TOTAL_CONTRIBUTION = 25

def _load_signals():
    with open(_SIGNALS_PATH, encoding='utf-8') as f:
        data = json.load(f)
    signals = sorted(data['signals'], key=lambda s: len(s['phrase']), reverse=True)
    return signals
_SIGNALS = None

def _get_signals():
    global _SIGNALS
    if _SIGNALS is None:
        _SIGNALS = _load_signals()
    return _SIGNALS

def analyze_spam_language(text: str) -> dict:
    if not text:
        return _empty_result()
    lower = text.lower()
    signals = _get_signals()
    matched = []
    seen_positions = set()
    for signal in signals:
        phrase = signal['phrase'].lower()
        try:
            pattern = re.compile('(?<!\\w)' + re.escape(phrase) + '(?!\\w)')
        except re.error:
            pattern = re.compile(re.escape(phrase))
        for m in pattern.finditer(lower):
            span = (m.start(), m.end())
            if any((span[0] < e and span[1] > s for (s, e) in seen_positions)):
                continue
            seen_positions.add(span)
            matched.append(signal)
            break
    category_counts: dict = {}
    category_scores: dict = {}
    for sig in matched:
        cat = sig['category']
        sev = sig.get('severity', 1)
        pts = SEVERITY_POINTS.get(sev, 1)
        category_counts[cat] = category_counts.get(cat, 0) + 1
        category_scores[cat] = category_scores.get(cat, 0) + pts
    total = 0
    for (cat, raw) in category_scores.items():
        total += min(raw, MAX_PER_CATEGORY)
    score_contribution = min(total, MAX_TOTAL_CONTRIBUTION)
    top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
    return {'matched_signals': matched, 'category_summary': category_counts, 'score_contribution': score_contribution, 'top_categories': top_categories, 'signal_count': len(matched)}

def _empty_result() -> dict:
    return {'matched_signals': [], 'category_summary': {}, 'score_contribution': 0, 'top_categories': [], 'signal_count': 0}
