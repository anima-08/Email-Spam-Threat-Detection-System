import re
BULK_SENDER_DOMAINS = {'mailchimp.com', 'sendgrid.net', 'amazonses.com', 'mailgun.org', 'sparkpostmail.com', 'constantcontact.com', 'klaviyo.com', 'campaign-monitor.com', 'getresponse.com', 'sendinblue.com', 'brevo.com', 'mailjet.com', 'postmarkapp.com', 'mandrillapp.com', 'mcsv.net', 'list-manage.com'}
BULK_SUBDOMAIN_PATTERNS = ['^mail\\d+\\.', '^mailer\\d*\\.', '^em\\d+\\.', '^mg\\.', '^smtp\\d+\\.', '^bulk\\.', '^news\\d*\\.', '^promo\\d*\\.', '^marketing\\.', '^newsletter\\.', '^noreply\\.', '^no-reply\\.', '^bounce\\.', '^reply\\.', '^notification\\.', '^outbound\\.', '^send\\d+\\.', '^e\\.mail\\.', '^e\\d+\\.']
SUSPICIOUS_TLDS = {'.xyz', '.top', '.club', '.work', '.click', '.loan', '.gq', '.tk', '.pw', '.cc'}
FREE_EMAIL_PROVIDERS = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.com', 'ymail.com', 'live.com', 'msn.com', 'icloud.com', 'me.com', 'protonmail.com', 'zoho.com'}

def _extract_email(sender: str):
    match = re.search('<([^>]+)>', sender)
    if match:
        email = match.group(1).strip()
        display_name = sender[:match.start()].strip().strip('"\'')
    else:
        email = sender.strip()
        display_name = ''
    return (email.lower(), display_name)

def analyze_sender(sender: str) -> dict:
    if not sender or not sender.strip():
        return {'sender_score': 0, 'sender_flags': [], 'sender_email': '', 'sender_domain': ''}
    flags = []
    score = 0
    (email, display_name) = _extract_email(sender)
    at_idx = email.rfind('@')
    if at_idx == -1:
        return {'sender_score': 0, 'sender_flags': [], 'sender_email': email, 'sender_domain': ''}
    domain = email[at_idx + 1:]
    if any((bulk in domain for bulk in BULK_SENDER_DOMAINS)):
        flags.append('Sent via a known bulk-email service')
        score += 20
    for pattern in BULK_SUBDOMAIN_PATTERNS:
        if re.match(pattern, domain):
            flags.append('Subdomain pattern typical of mass-mailing infrastructure')
            score += 25
            break
    if display_name:
        display_words = re.findall('[a-zA-Z]{4,}', display_name.lower())
        if display_words and (not any((w in domain for w in display_words))):
            flags.append("Display name doesn't match the actual sending domain")
            score += 15
    if domain in FREE_EMAIL_PROVIDERS and display_name and (len(display_name) > 3):
        flags.append('A brand/company name is sending from a free personal email provider')
        score += 12
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f'Sender domain uses a TLD commonly linked to spam ({tld})')
            score += 20
            break
    if re.search('\\d{3,}', domain):
        flags.append('Sender domain contains a long numeric sequence (common in spam infrastructure)')
        score += 15
    if domain.count('.') >= 3:
        flags.append('Unusually deep subdomain chain in sender domain')
        score += 10
    root = domain.split('.')[0] if domain else ''
    if root.count('-') >= 2:
        flags.append('Sender domain root contains multiple hyphens')
        score += 8
    score = min(score, 100)
    return {'sender_score': score, 'sender_flags': flags, 'sender_email': email, 'sender_domain': domain}
