import re
MAX_STRUCTURAL_SCORE = 10

def analyze_structure(subject: str, body: str, url_count: int) -> dict:
    flags = []
    total_score = 0
    text = ((subject or '') + ' ' + (body or '')).strip()
    if not text:
        return {'flags': [], 'score_contribution': 0}
    words = text.split()
    word_count = len(words)
    if word_count >= 5:
        caps_words = [w for w in words if w.isupper() and len(w) > 2 and w.isalpha()]
        caps_ratio = len(caps_words) / word_count
        if caps_ratio >= 0.4:
            pts = 4
            flags.append({'signal': 'excessive_caps', 'explanation': f'{int(caps_ratio * 100)}% of words are in ALL CAPS — strong spam formatting signal.', 'contribution': pts})
            total_score += pts
        elif caps_ratio >= 0.25:
            pts = 2
            flags.append({'signal': 'high_caps', 'explanation': f'{int(caps_ratio * 100)}% of words are in ALL CAPS.', 'contribution': pts})
            total_score += pts
    if subject:
        subj_words = subject.split()
        subj_caps = [w for w in subj_words if w.isupper() and len(w) > 2 and w.isalpha()]
        if len(subj_words) >= 2 and len(subj_caps) / len(subj_words) >= 0.6:
            pts = 3
            flags.append({'signal': 'subject_caps', 'explanation': 'Subject line is predominantly in ALL CAPS — a strong spam formatting signal.', 'contribution': pts})
            total_score += pts
    exclamation_count = text.count('!')
    if exclamation_count >= 5:
        pts = 3
        flags.append({'signal': 'excessive_exclamations', 'explanation': f'{exclamation_count} exclamation marks detected — spam emails frequently use excessive punctuation.', 'contribution': pts})
        total_score += pts
    elif exclamation_count >= 3:
        pts = 1
        flags.append({'signal': 'multiple_exclamations', 'explanation': f'{exclamation_count} exclamation marks detected.', 'contribution': pts})
        total_score += pts
    body_words = (body or '').split()
    if url_count >= 1 and len(body_words) < 20:
        pts = 3
        flags.append({'signal': 'short_body_with_url', 'explanation': f'Very short email body ({len(body_words)} words) containing a URL — typical of one-liner phishing.', 'contribution': pts})
        total_score += pts
    if word_count > 0 and url_count >= 3:
        url_density = url_count / word_count
        if url_density > 0.05:
            pts = 2
            flags.append({'signal': 'high_url_density', 'explanation': f'{url_count} URLs in {word_count} words — unusually high link density.', 'contribution': pts})
            total_score += pts
    dollar_count = text.count('$')
    if dollar_count >= 4:
        pts = 2
        flags.append({'signal': 'currency_stuffing', 'explanation': f'{dollar_count} dollar signs detected — heavy financial emphasis typical of spam.', 'contribution': pts})
        total_score += pts
    score_contribution = min(total_score, MAX_STRUCTURAL_SCORE)
    return {'flags': flags, 'score_contribution': score_contribution}
