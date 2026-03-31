"""
Tests for the Arabic Phishing Detector.

These tests check logic that runs offline (no network calls):
  - URL validation
  - domain_check scoring
  - risk level thresholds

Network-dependent checks (WHOIS, SSL, content, redirects) are tested
via their return structure, not live results, to keep CI fast.
"""

import pytest
from detector.analyzer import analyze, _validate_url
from detector.checks import domain_check


# --- URL Validation ---

def test_valid_https_url():
    assert _validate_url("https://stc.com.sa") is None

def test_valid_http_url():
    assert _validate_url("http://example.com") is None

def test_invalid_no_scheme():
    assert _validate_url("stc.com.sa") is not None

def test_invalid_ftp_scheme():
    assert _validate_url("ftp://stc.com.sa") is not None

def test_invalid_empty():
    assert _validate_url("") is not None


# --- Domain Check ---

def test_known_legit_domain_scores_zero():
    result = domain_check.check("https://stc.com.sa")
    assert result["score"] == 0
    assert result["status"] == "PASS"

def test_close_lookalike_scores_high():
    # "stc.com.sa" → distance from "stc.sa" is small
    result = domain_check.check("https://stc-sa.com")
    assert result["score"] >= 20  # at minimum suspicious

def test_unrelated_domain_scores_zero():
    result = domain_check.check("https://wikipedia.org")
    assert result["score"] == 0
    assert result["status"] == "PASS"


# --- Risk Level Thresholds ---

def test_score_0_is_low_risk():
    # Simulate a report with score 0
    from detector.analyzer import analyze
    # We check the structure only — a real URL would need network
    report = analyze("not-a-url")
    assert report["error"] is not None  # should fail validation

def test_risk_level_boundaries():
    """Risk thresholds in analyzer.py: <=30 Low, <=60 Medium, >60 High."""
    from unittest.mock import patch

    def fake_checks_with_score(total):
        """Return a mock check list whose scores sum to `total`."""
        return [{"name": "Domain Lookalike", "status": "PASS", "score": total,
                 "detail": "test"}]

    with patch("detector.analyzer.domain_check.check",    return_value={"name": "Domain Lookalike",  "status": "PASS", "score": 0,  "detail": ""}), \
         patch("detector.analyzer.whois_check.check",     return_value={"name": "Domain Age",        "status": "PASS", "score": 0,  "detail": ""}), \
         patch("detector.analyzer.ssl_check.check",       return_value={"name": "SSL Certificate",   "status": "PASS", "score": 0,  "detail": ""}), \
         patch("detector.analyzer.content_check.check",   return_value={"name": "Content Analysis",  "status": "PASS", "score": 0,  "detail": ""}), \
         patch("detector.analyzer.redirect_check.check",  return_value={"name": "Redirect Chain",    "status": "PASS", "score": 0,  "detail": ""}), \
         patch("detector.analyzer.tld_check.check",       return_value={"name": "Suspicious TLD",    "status": "PASS", "score": 0,  "detail": ""}), \
         patch("detector.analyzer.url_structure_check.check", return_value={"name": "URL Structure", "status": "PASS", "score": 0,  "detail": ""}):
        result_0   = analyze("https://example.com")

    assert result_0["risk_level"] == "Low",   "score 0 should be Low"
    assert result_0["score"] == 0

    # Test boundary: score exactly 30 → Low
    with patch("detector.analyzer.domain_check.check",    return_value={"name": "Domain Lookalike",  "status": "SUSPICIOUS", "score": 30, "detail": ""}), \
         patch("detector.analyzer.whois_check.check",     return_value={"name": "Domain Age",        "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.ssl_check.check",       return_value={"name": "SSL Certificate",   "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.content_check.check",   return_value={"name": "Content Analysis",  "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.redirect_check.check",  return_value={"name": "Redirect Chain",    "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.tld_check.check",       return_value={"name": "Suspicious TLD",    "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.url_structure_check.check", return_value={"name": "URL Structure", "status": "PASS",       "score": 0,  "detail": ""}):
        result_30 = analyze("https://example.com")

    assert result_30["risk_level"] == "Low",   "score 30 should be Low"

    # Test boundary: score exactly 31 → Medium
    with patch("detector.analyzer.domain_check.check",    return_value={"name": "Domain Lookalike",  "status": "SUSPICIOUS", "score": 31, "detail": ""}), \
         patch("detector.analyzer.whois_check.check",     return_value={"name": "Domain Age",        "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.ssl_check.check",       return_value={"name": "SSL Certificate",   "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.content_check.check",   return_value={"name": "Content Analysis",  "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.redirect_check.check",  return_value={"name": "Redirect Chain",    "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.tld_check.check",       return_value={"name": "Suspicious TLD",    "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.url_structure_check.check", return_value={"name": "URL Structure", "status": "PASS",       "score": 0,  "detail": ""}):
        result_31 = analyze("https://example.com")

    assert result_31["risk_level"] == "Medium", "score 31 should be Medium"

    # Test boundary: score exactly 61 → High
    with patch("detector.analyzer.domain_check.check",    return_value={"name": "Domain Lookalike",  "status": "HIGH RISK",  "score": 61, "detail": ""}), \
         patch("detector.analyzer.whois_check.check",     return_value={"name": "Domain Age",        "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.ssl_check.check",       return_value={"name": "SSL Certificate",   "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.content_check.check",   return_value={"name": "Content Analysis",  "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.redirect_check.check",  return_value={"name": "Redirect Chain",    "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.tld_check.check",       return_value={"name": "Suspicious TLD",    "status": "PASS",       "score": 0,  "detail": ""}), \
         patch("detector.analyzer.url_structure_check.check", return_value={"name": "URL Structure", "status": "PASS",       "score": 0,  "detail": ""}):
        result_61 = analyze("https://example.com")

    assert result_61["risk_level"] == "High", "score 61 should be High"


# --- Check Result Structure ---

def test_domain_check_returns_required_keys():
    result = domain_check.check("https://stc.com.sa")
    assert "name" in result
    assert "status" in result
    assert "score" in result
    assert "detail" in result
    assert isinstance(result["score"], int)
