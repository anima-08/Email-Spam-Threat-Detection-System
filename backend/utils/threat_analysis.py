import os
import re
URL_REGEX = re.compile('(?:(?:https?|ftp)://|www\\.)[^\\s<>\\"\']+|\\b[a-z0-9-]+\\.(?:ly|gl|gy|gd|xyz|top|club|work|click|loan|gq|tk|st|co)\\/[^\\s<>\\"\']*', re.IGNORECASE)
IP_URL_REGEX = re.compile('https?://(\\d{1,3}\\.){3}\\d{1,3}')
URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'shorte.st', 'cutt.ly', 'rb.gy', 'tiny.cc', 'clck.ru', 'x.co', 'snip.ly', 'v.gd', 'po.st', 'adf.ly', 'bc.vc'}
SUSPICIOUS_TLDS = {'.xyz', '.top', '.club', '.work', '.click', '.loan', '.gq', '.tk', '.pw', '.cc', '.ml', '.ga', '.cf', '.rest', '.vip', '.icu', '.cyou', '.bond'}
TRUSTED_DOMAINS = {'google.com', 'gmail.com', 'microsoft.com', 'outlook.com', 'apple.com', 'amazon.com', 'paypal.com', 'linkedin.com', 'twitter.com', 'x.com', 'facebook.com', 'instagram.com', 'youtube.com', 'github.com', 'dropbox.com'}
PHISHING_KEYWORDS = ['urgent', 'verify your account', 'verify account', 'suspended', 'click here', 'act now', 'limited time', 'congratulations', 'you have won', 'free gift', 'claim your prize', 'winner', 'confirm your identity', 'update your payment', 'password expired', 'security alert', 'unusual activity', 'wire transfer', 'bank account', 'social security', 'gift card', 'act immediately', 'your account will be', 'reset your password', 'login attempt']

def extract_urls(text: str) -> list:
    return list(dict.fromkeys(URL_REGEX.findall(text or '')))

def check_url_reputation(url: str) -> dict:
    reasons = []
    score = 0
    lower = url.lower()
    domain_match = re.search('https?://([^/?#\\s]+)', lower)
    domain = domain_match.group(1) if domain_match else lower
    domain = domain.split(':')[0]
    root_domain = '.'.join(domain.split('.')[-2:])
    if root_domain in TRUSTED_DOMAINS:
        return {'url': url, 'risk_score': 0, 'verdict': 'Likely Safe', 'reasons': []}
    if IP_URL_REGEX.match(url):
        reasons.append('URL uses a raw IP address instead of a domain name')
        score += 40
    if not lower.startswith('https://'):
        reasons.append('URL does not use HTTPS encryption')
        score += 12
    if any((short in domain for short in URL_SHORTENERS)):
        reasons.append('URL shortener detected — final destination is hidden')
        score += 25
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f'Domain uses a TLD commonly associated with spam/phishing ({tld})')
            score += 20
            break
    domain_part = domain.split('.')[0] if '.' in domain else domain
    if domain_part.count('-') >= 3:
        reasons.append('Domain contains an unusually high number of hyphens (lookalike domain pattern)')
        score += 12
    if len(domain) > 40:
        reasons.append('Unusually long domain name')
        score += 8
    if domain.count('.') >= 4:
        reasons.append('Unusually deep subdomain chain')
        score += 10
    BRAND_KEYWORDS = {'paypal', 'apple', 'amazon', 'microsoft', 'google', 'facebook', 'netflix', 'ebay', 'bankofamerica', 'chase'}
    for brand in BRAND_KEYWORDS:
        if brand in domain and (not domain.endswith(brand + '.com')):
            reasons.append(f"Domain appears to impersonate '{brand}'")
            score += 20
            break
    if 'xn--' in domain:
        reasons.append('Domain uses Punycode encoding — may be visually spoofing a trusted domain')
        score += 20
    score = min(score, 100)
    verdict = 'Suspicious' if score >= 30 else 'Likely Safe'
    return {'url': url, 'risk_score': score, 'verdict': verdict, 'reasons': reasons}

def find_phishing_keywords(text: str) -> list:
    lower = (text or '').lower()
    return [kw for kw in PHISHING_KEYWORDS if kw in lower]

def compute_threat_score(spam_probability: float, confidence: float=0.0, url_reports: list=None, spam_language_score: int=0, phishing_score: int=0, structural_score: int=0, attachment_score: int=0, sender_score: int=0) -> int:
    url_reports = url_reports or []
    ml_score = spam_probability * 45
    confidence_bonus = 5.0 if confidence >= 0.95 else (confidence - 0.85) * 25 if confidence >= 0.85 else 0.0
    phishing_pts = phishing_score / 30 * 20 if phishing_score > 0 else 0
    spam_lang_pts = spam_language_score / 25 * 12 if spam_language_score > 0 else 0
    url_pts = 0.0
    if url_reports:
        worst = max((r['risk_score'] for r in url_reports))
        url_pts = worst / 100 * 10
    sender_pts = sender_score / 100 * 8
    structural_pts = structural_score / 10 * 5 if structural_score > 0 else 0
    attachment_pts = attachment_score / 15 * 5 if attachment_score > 0 else 0
    total = ml_score + confidence_bonus + phishing_pts + spam_lang_pts + url_pts + sender_pts + structural_pts + attachment_pts
    return int(round(min(total, 100)))

def compute_threat_score_legacy(spam_probability: float, url_reports: list, matched_keywords: list, sender_score: int=0) -> int:
    kw_score = min(len(matched_keywords or []) * 3, 12)
    return compute_threat_score(spam_probability=spam_probability, url_reports=url_reports, spam_language_score=kw_score, sender_score=sender_score)

def risk_level_from_score(threat_score: int) -> str:
    if threat_score >= 75:
        return 'Critical'
    if threat_score >= 50:
        return 'High'
    if threat_score >= 25:
        return 'Moderate'
    return 'Low'
