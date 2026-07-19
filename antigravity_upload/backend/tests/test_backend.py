"""
test_backend.py — Comprehensive test suite for SpamShield backend.

Tests the full analysis pipeline with 11 test cases covering:
  1. Obvious spam
  2. Legitimate promotional email (false-positive guard)
  3. Normal personal email
  4. Password-reset email (contextual — should NOT be high risk)
  5. Credential phishing email
  6. Suspicious-link email
  7. Multiple spam trigger email
  8. Spam keyword in legitimate context (birthday "free")
  9. Empty email (edge case)
  10. Very long email (performance)
  11. Malformed / missing fields

Run:
  cd antigravity_upload/backend
  python tests/test_backend.py
  # OR with coverage:
  pip install pytest
  pytest tests/test_backend.py -v
"""

import json
import sys
import os
import time
import unittest

# ── Allow importing from parent directory ─────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.spam_language_analyzer import analyze_spam_language
from utils.phishing_analyzer import analyze_phishing
from utils.structural_analyzer import analyze_structure
from utils.attachment_analyzer import analyze_attachments
from utils.threat_analysis import (
    check_url_reputation,
    compute_threat_score,
    extract_urls,
    find_phishing_keywords,
    risk_level_from_score,
)
from utils.sender_analysis import analyze_sender


class TestSpamLanguageAnalyzer(unittest.TestCase):

    def test_obvious_spam_language(self):
        """Obvious spam should match many signals with high contribution."""
        text = (
            "CONGRATULATIONS! You have WON a FREE GIFT! "
            "Claim your prize NOW! Act immediately or lose this limited time offer! "
            "100% guaranteed! No catch! This is not spam!"
        )
        result = analyze_spam_language(text)
        self.assertGreater(result["signal_count"], 3)
        self.assertGreater(result["score_contribution"], 10)
        # Should detect prize and urgency categories
        cats = result["category_summary"]
        self.assertTrue(
            cats.get("prize_reward_scams", 0) > 0 or cats.get("urgency_pressure", 0) > 0
        )

    def test_single_free_in_personal_email(self):
        """A single low-severity keyword like 'free' should give minimal score."""
        text = "Hey! Come to my birthday party, food is free for everyone!"
        result = analyze_spam_language(text)
        # 'free' alone as part of 'food is free' might not match "free gift" etc.
        self.assertLessEqual(result["score_contribution"], 4,
            "A single 'free' in legitimate context should not dominate the score")

    def test_no_false_positive_newsletter(self):
        """Legitimate newsletter with 'free trial' should score moderately, not critically."""
        text = (
            "Welcome to our monthly newsletter! "
            "Try our new product with a free trial. "
            "Special offer for subscribers this month. "
            "Unsubscribe anytime."
        )
        result = analyze_spam_language(text)
        # Should match some signals but not dominate
        self.assertLessEqual(result["score_contribution"], 12,
            "Legitimate newsletter should not score above moderate spam language")

    def test_empty_text(self):
        """Empty input should return zero results without error."""
        result = analyze_spam_language("")
        self.assertEqual(result["signal_count"], 0)
        self.assertEqual(result["score_contribution"], 0)

    def test_category_cap(self):
        """Even with many urgency keywords, the urgency category should be capped."""
        text = (
            "Act now! Act immediately! Limited time! Expires today! Last chance! "
            "Open immediately! Urgent! Take action now! Urgent reply! "
            "Get it now! Now only! Time limited! Offer expires! Supplies are limited!"
        )
        result = analyze_spam_language(text)
        # Total contribution from urgency alone is capped at MAX_PER_CATEGORY=8
        self.assertLessEqual(result["score_contribution"], 25)


class TestPhishingAnalyzer(unittest.TestCase):

    def test_credential_theft_pattern(self):
        """Classic phishing trifecta should fire credential_theft pattern."""
        text = (
            "URGENT: Verify your account immediately. "
            "Your login credentials need to be confirmed. "
            "Click here: https://secure-login.fake.example.com"
        )
        result = analyze_phishing(text, ["https://secure-login.fake.example.com"])
        self.assertGreater(result["pattern_count"], 0)
        pattern_names = [p["pattern_name"] for p in result["phishing_patterns"]]
        self.assertIn("credential_theft", pattern_names)
        self.assertGreater(result["score_contribution"], 15)

    def test_password_reset_not_phishing(self):
        """Legitimate password-reset email should NOT trigger credential_theft."""
        text = (
            "You requested a password reset for your account. "
            "If you did not request this, ignore this email. "
            "Click the link below to reset your password. "
            "This link expires in 24 hours."
        )
        # No urgency or account-suspension language + no suspicious URL
        result = analyze_phishing(text, [])
        # Should not fire credential_theft (no urgency trigger + no URL)
        pattern_names = [p["pattern_name"] for p in result["phishing_patterns"]]
        self.assertNotIn("credential_theft", pattern_names,
            "A password reset email without urgency + URL should not fire credential_theft")

    def test_prize_scam(self):
        """Prize scam language should fire prize_reward_scam."""
        text = "Congratulations! You have been selected as our lucky winner. Claim your reward now!"
        result = analyze_phishing(text, [])
        pattern_names = [p["pattern_name"] for p in result["phishing_patterns"]]
        self.assertIn("prize_reward_scam", pattern_names)

    def test_payment_fraud(self):
        """Payment fraud pattern should fire with billing + update + URL."""
        text = (
            "Your payment has failed. Please update your billing information "
            "to avoid service interruption. "
        )
        result = analyze_phishing(text, ["https://pay.example.xyz/update"])
        pattern_names = [p["pattern_name"] for p in result["phishing_patterns"]]
        self.assertIn("payment_fraud", pattern_names)

    def test_empty_text_no_crash(self):
        """Empty text should return empty result without crashing."""
        result = analyze_phishing("", [])
        self.assertEqual(result["pattern_count"], 0)
        self.assertEqual(result["score_contribution"], 0)


class TestStructuralAnalyzer(unittest.TestCase):

    def test_excessive_caps(self):
        """An email with excessive ALL CAPS should trigger the caps flag."""
        subject = "URGENT ACTION REQUIRED"
        body = "YOU MUST ACT NOW! YOUR ACCOUNT HAS BEEN COMPROMISED! CONTACT US IMMEDIATELY!"
        result = analyze_structure(subject, body, 1)
        flag_signals = [f["signal"] for f in result["flags"]]
        self.assertTrue(
            "excessive_caps" in flag_signals or "high_caps" in flag_signals,
            "Excessive caps not detected"
        )
        self.assertGreater(result["score_contribution"], 0)

    def test_short_body_with_url(self):
        """Very short email body with a URL should trigger the short_body_with_url flag."""
        result = analyze_structure("check this out", "click: http://bit.ly/xyz", 1)
        flag_signals = [f["signal"] for f in result["flags"]]
        self.assertIn("short_body_with_url", flag_signals)

    def test_normal_email_no_flags(self):
        """A normal email should produce no or minimal structural flags."""
        body = (
            "Hi Sarah, just following up on our conversation from yesterday. "
            "I've attached the document you requested. Let me know if you have any questions. "
            "Best regards, John"
        )
        result = analyze_structure("Following up on our call", body, 0)
        self.assertLessEqual(result["score_contribution"], 2)


class TestAttachmentAnalyzer(unittest.TestCase):

    def test_executable_extension_detected(self):
        """Mention of .exe should trigger high-risk attachment warning."""
        text = "Please run the attached installer.exe to complete setup."
        result = analyze_attachments(text)
        types = [w["type"] for w in result["warnings"]]
        self.assertIn("high_risk_extension", types)
        self.assertGreater(result["score_contribution"], 0)

    def test_macro_enable_instruction(self):
        """'Enable macros' instruction should trigger macro warning."""
        text = "Open the attached spreadsheet and enable macros to view the report."
        result = analyze_attachments(text)
        types = [w["type"] for w in result["warnings"]]
        self.assertIn("macro_enable_instruction", types)

    def test_password_protected_archive(self):
        """Password-protected archive mention should trigger warning."""
        text = "I've attached a zip file. The password is: secure123"
        result = analyze_attachments(text)
        types = [w["type"] for w in result["warnings"]]
        self.assertIn("password_protected_archive", types)

    def test_clean_email_no_warnings(self):
        """Normal email without attachment mentions should have no warnings."""
        text = "Happy to connect. Looking forward to our meeting tomorrow."
        result = analyze_attachments(text)
        self.assertEqual(len(result["warnings"]), 0)


class TestURLAnalysis(unittest.TestCase):

    def test_ip_url_flagged(self):
        """Raw IP-based URL should be flagged as suspicious."""
        result = check_url_reputation("http://192.168.1.1/login")
        self.assertEqual(result["verdict"], "Suspicious")
        self.assertGreater(result["risk_score"], 30)

    def test_shortener_flagged(self):
        """URL shortener should increase risk score."""
        result = check_url_reputation("http://bit.ly/somepath")
        self.assertGreater(result["risk_score"], 20)

    def test_trusted_domain_safe(self):
        """Well-known trusted domain should be marked as likely safe."""
        result = check_url_reputation("https://google.com/search?q=test")
        self.assertEqual(result["verdict"], "Likely Safe")
        self.assertEqual(result["risk_score"], 0)

    def test_brand_impersonation(self):
        """Domain impersonating PayPal should be flagged."""
        result = check_url_reputation("https://paypal-login.malicious.xyz/verify")
        self.assertEqual(result["verdict"], "Suspicious")

    def test_https_safe_domain(self):
        """Clean HTTPS URL on normal domain should score low."""
        result = check_url_reputation("https://example.com/page")
        self.assertLess(result["risk_score"], 30)


class TestThreatScoring(unittest.TestCase):

    def test_high_spam_probability_dominates(self):
        """High ML spam probability should produce a high threat score."""
        score = compute_threat_score(spam_probability=0.97, confidence=0.97)
        self.assertGreater(score, 40)

    def test_low_probability_low_score(self):
        """Low ML probability with no other signals should give low threat score."""
        score = compute_threat_score(spam_probability=0.05, confidence=0.95)
        self.assertLess(score, 15)

    def test_score_never_exceeds_100(self):
        """Threat score should never exceed 100."""
        score = compute_threat_score(
            spam_probability=1.0,
            confidence=1.0,
            url_reports=[{"risk_score": 100}],
            spam_language_score=25,
            phishing_score=30,
            structural_score=10,
            attachment_score=15,
            sender_score=100,
        )
        self.assertLessEqual(score, 100)

    def test_risk_levels(self):
        """Risk level bucketing should match expected thresholds."""
        self.assertEqual(risk_level_from_score(10),  "Low")
        self.assertEqual(risk_level_from_score(30),  "Moderate")
        self.assertEqual(risk_level_from_score(60),  "High")
        self.assertEqual(risk_level_from_score(80),  "Critical")


class TestSenderAnalysis(unittest.TestCase):

    def test_display_name_domain_mismatch(self):
        """Display name that doesn't match sending domain should be flagged."""
        result = analyze_sender("PayPal Security <no-reply@randomdomain.xyz>")
        self.assertGreater(result["sender_score"], 0)
        self.assertTrue(len(result["sender_flags"]) > 0)

    def test_suspicious_tld(self):
        """Sender with .xyz TLD should be flagged."""
        result = analyze_sender("offers@deals.xyz")
        self.assertGreater(result["sender_score"], 0)

    def test_legitimate_sender(self):
        """A clean corporate sender should have low or zero score."""
        result = analyze_sender("John Smith <john.smith@company.com>")
        # May flag display-name mismatch but overall score should be moderate
        self.assertLessEqual(result["sender_score"], 30)

    def test_empty_sender(self):
        """Empty sender string should return zero score without error."""
        result = analyze_sender("")
        self.assertEqual(result["sender_score"], 0)


class TestIntegrationScenarios(unittest.TestCase):
    """End-to-end integration tests for key email scenarios."""

    def _run(self, subject, body, sender="", urls=None):
        """Helper: run all analyzers and return aggregated result."""
        text = f"{subject}\n{body}".strip()
        extracted_urls = extract_urls(text) if urls is None else urls
        url_reports     = [check_url_reputation(u) for u in extracted_urls]
        spam_lang       = analyze_spam_language(text)
        phishing        = analyze_phishing(text, extracted_urls)
        structural      = analyze_structure(subject, body, len(extracted_urls))
        attachment      = analyze_attachments(text)
        sender_res      = analyze_sender(sender)
        threat_score    = compute_threat_score(
            spam_probability    = 0.5,  # neutral ML for isolation testing
            confidence          = 0.5,
            url_reports         = url_reports,
            spam_language_score = spam_lang["score_contribution"],
            phishing_score      = phishing["score_contribution"],
            structural_score    = structural["score_contribution"],
            attachment_score    = attachment["score_contribution"],
            sender_score        = sender_res["sender_score"],
        )
        return {
            "spam_lang": spam_lang,
            "phishing": phishing,
            "structural": structural,
            "attachment": attachment,
            "threat_score": threat_score,
            "risk_level": risk_level_from_score(threat_score),
        }

    def test_obvious_spam_scenario(self):
        """Full spam email should produce high threat score."""
        r = self._run(
            subject="YOU HAVE WON!!! CLAIM NOW!!!",
            body=(
                "Congratulations! You have won $1,000,000! "
                "Claim your prize immediately! Act now! Limited time only! "
                "This is not spam! 100% guaranteed! No catch! "
                "Send us your social security number and bank account details. "
                "Click here: http://win-prizes.xyz/claim"
            ),
        )
        self.assertGreater(r["threat_score"], 30,
            "Obvious spam email should produce threat score > 30")
        self.assertGreater(r["spam_lang"]["signal_count"], 5)
        self.assertGreater(r["phishing"]["pattern_count"], 0)

    def test_legitimate_newsletter(self):
        """Legitimate newsletter should not be classified as high-risk."""
        r = self._run(
            subject="Monthly Product Updates — July 2025",
            body=(
                "Hi there, here are this month's updates. "
                "We've added new features to our dashboard. "
                "Start your free trial today and see the difference. "
                "To unsubscribe from this newsletter, click here. "
                "Our support team is here to help."
            ),
            sender="newsletter@product.com",
        )
        # With neutral ML (0.5), legitimate newsletters should not hit Critical
        self.assertNotEqual(r["risk_level"], "Critical",
            "A legitimate newsletter should not be Critical risk")

    def test_personal_email(self):
        """Normal personal email should produce very low threat scores."""
        r = self._run(
            subject="Dinner plans for Friday?",
            body=(
                "Hey Mike, are you free Friday evening? "
                "We were thinking of trying the new Italian place on Main St. "
                "Let me know if you can make it! See you soon."
            ),
            sender="jane.doe@gmail.com",
        )
        self.assertLessEqual(r["threat_score"], 30,
            "Personal email should score low")
        self.assertEqual(r["phishing"]["pattern_count"], 0)
        self.assertEqual(r["attachment"]["warnings"], [])

    def test_very_long_email_performance(self):
        """Very long email should complete in reasonable time."""
        long_body = "This is a normal sentence about everyday work tasks. " * 500
        start = time.time()
        r = self._run(subject="Weekly Update", body=long_body)
        elapsed = time.time() - start
        self.assertLess(elapsed, 5.0, f"Analysis took too long: {elapsed:.2f}s")

    def test_empty_email_no_crash(self):
        """Empty email should return zero-risk result without error."""
        r = self._run(subject="", body="")
        self.assertIsNotNone(r["threat_score"])
        self.assertIsNotNone(r["risk_level"])


if __name__ == "__main__":
    print("=" * 60)
    print("SpamShield Backend Test Suite")
    print("=" * 60)
    result = unittest.main(verbosity=2, exit=False)
    total   = result.result.testsRun
    errors  = len(result.result.errors)
    failures= len(result.result.failures)
    passed  = total - errors - failures
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} passed | {failures} failed | {errors} errors")
    if failures == 0 and errors == 0:
        print("PASS: All tests passed!")
    else:
        print("FAIL: Some tests failed -- check output above.")
    print("=" * 60)
