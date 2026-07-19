"""
attachment_analyzer.py — Risky attachment indicator detection from email text.

Since the Chrome extension extracts email body text (not binary attachments),
this module detects *mentions* of risky attachment types and patterns within
the text itself — such as filenames, extension references, and explicit
attachment-related instructions.

IMPORTANT: This module does NOT claim to detect actual malware. It detects
contextual language suggesting a risky attachment is present or being
referenced. All labels use language like "Potentially risky attachment type
mentioned" rather than "Malware detected".

Risk categories (inspired by Microsoft Defender for Office 365 documentation
and CISA guidance on phishing attachments):

  HIGH-RISK EXTENSIONS  — executable, script, or macro-capable files
  MACRO-ENABLED SIGNALS — Office files with macros, macro-enable instructions
  ARCHIVE TRAP SIGNALS  — password-protected archives (common in malware delivery)
  GENERIC ATTACHMENT SIGNALS — general "open the attachment" urgency language
"""

import re

# ── Extension risk database ───────────────────────────────────────────────────

HIGH_RISK_EXTENSIONS = {
    ".exe":  "Executable file — can run arbitrary code",
    ".bat":  "Windows batch script — can execute system commands",
    ".cmd":  "Windows command script",
    ".com":  "DOS executable",
    ".msi":  "Windows installer package",
    ".ps1":  "PowerShell script — frequently used in malware delivery",
    ".vbs":  "VBScript — common malware delivery vehicle",
    ".vbe":  "Encoded VBScript",
    ".js":   "JavaScript file — can execute locally via Windows Script Host",
    ".jse":  "Encoded JScript",
    ".wsf":  "Windows Script File",
    ".hta":  "HTML Application — runs with elevated privileges",
    ".jar":  "Java executable archive",
    ".scr":  "Windows screensaver — disguises executables",
    ".pif":  "Program Information File — can run executables",
    ".reg":  "Windows registry file — can modify system registry",
    ".dll":  "Dynamic-link library",
    ".lnk":  "Windows shortcut — can point to malicious executables",
}

MACRO_ENABLED_EXTENSIONS = {
    ".xlsm":  "Excel file with macros enabled",
    ".docm":  "Word document with macros enabled",
    ".pptm":  "PowerPoint file with macros enabled",
    ".xlam":  "Excel add-in with macros",
    ".dotm":  "Word template with macros",
}

MACRO_ENABLED_PHRASES = [
    "enable macros",
    "enable editing",
    "enable content",
    "click enable",
    "macros are required",
    "you must enable",
    "allow macros",
]

ARCHIVE_TRAP_PHRASES = [
    "password protected",
    "password is",
    "the password is",
    "password:",
    "zip password",
    "archive password",
    "password to open",
    "open with password",
]

GENERIC_ATTACHMENT_URGENCY = [
    "open the attachment",
    "see the attached",
    "view the attachment",
    "attached file",
    "attached document",
    "attached invoice",
    "please find attached",
    "download the attachment",
    "the document attached",
    "open attached",
]

MAX_ATTACHMENT_SCORE = 15


def analyze_attachments(text: str) -> dict:
    """
    Detect risky attachment references in email text.

    Args:
        text: Raw email text (subject + body).

    Returns a dict with:
        warnings           : list of {type, description, severity, contribution}
        score_contribution : int 0–MAX_ATTACHMENT_SCORE
    """
    if not text:
        return {"warnings": [], "score_contribution": 0}

    lower = text.lower()
    warnings = []
    total_score = 0

    # ── High-risk extension mentions ─────────────────────────────────────────
    found_high_risk = []
    for ext, desc in HIGH_RISK_EXTENSIONS.items():
        pattern = re.compile(re.escape(ext) + r"(?:\b|\"|\s|$)", re.IGNORECASE)
        if pattern.search(text):
            found_high_risk.append((ext, desc))

    if found_high_risk:
        exts_str = ", ".join(e for e, _ in found_high_risk)
        pts = min(len(found_high_risk) * 4, 12)
        warnings.append({
            "type": "high_risk_extension",
            "description": f"Potentially risky file type(s) mentioned: {exts_str}. These file types can execute code.",
            "severity": "High",
            "contribution": pts,
        })
        total_score += pts

    # ── Macro-enabled extension mentions ─────────────────────────────────────
    found_macro_ext = []
    for ext, desc in MACRO_ENABLED_EXTENSIONS.items():
        if re.search(re.escape(ext) + r"(?:\b|\"|\s|$)", text, re.IGNORECASE):
            found_macro_ext.append((ext, desc))

    if found_macro_ext:
        exts_str = ", ".join(e for e, _ in found_macro_ext)
        pts = 6
        warnings.append({
            "type": "macro_enabled_extension",
            "description": f"Macro-enabled Office file(s) mentioned: {exts_str}. Macros can execute malicious code.",
            "severity": "Medium",
            "contribution": pts,
        })
        total_score += pts

    # ── Macro-enable instruction phrases ─────────────────────────────────────
    matched_macro_phrases = [p for p in MACRO_ENABLED_PHRASES if p.lower() in lower]
    if matched_macro_phrases:
        pts = 8
        warnings.append({
            "type": "macro_enable_instruction",
            "description": f"Email instructs recipient to enable macros (\"{matched_macro_phrases[0]}\") — a common malware delivery technique.",
            "severity": "High",
            "contribution": pts,
        })
        total_score += pts

    # ── Password-protected archive ────────────────────────────────────────────
    matched_archive = [p for p in ARCHIVE_TRAP_PHRASES if p.lower() in lower]
    if matched_archive:
        pts = 5
        warnings.append({
            "type": "password_protected_archive",
            "description": "Email mentions a password-protected file — a technique used to bypass email scanning.",
            "severity": "Medium",
            "contribution": pts,
        })
        total_score += pts

    # ── Generic attachment urgency ────────────────────────────────────────────
    matched_generic = [p for p in GENERIC_ATTACHMENT_URGENCY if p.lower() in lower]
    if matched_generic:
        pts = 2
        warnings.append({
            "type": "attachment_mentioned",
            "description": "Email references an attachment — treat with caution if source is unexpected.",
            "severity": "Low",
            "contribution": pts,
        })
        total_score += pts

    score_contribution = min(total_score, MAX_ATTACHMENT_SCORE)
    return {
        "warnings": warnings,
        "score_contribution": score_contribution,
    }
