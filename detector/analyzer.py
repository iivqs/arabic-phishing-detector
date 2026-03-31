"""
Main analyzer — orchestrates all checks and produces the final report.
"""

import logging
import time
from urllib.parse import urlparse
from detector.checks import (
    domain_check, whois_check, ssl_check,
    content_check, redirect_check,
    tld_check, url_structure_check,
)

logger = logging.getLogger(__name__)
MAX_SCORE = 100


def _validate_url(url: str) -> str | None:
    """Return an error message if the URL is invalid, else None."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "URL must start with http:// or https://"
    if not parsed.netloc:
        return "URL has no hostname."
    return None


def analyze(url: str) -> dict:
    """
    Run all phishing checks against a URL.

    Returns a dict with:
      - url: the analyzed URL
      - score: int 0–100
      - risk_level: "Low" | "Medium" | "High"
      - verdict: human-readable summary
      - checks: list of individual check results
      - error: str | None (set if URL validation fails)
    """
    error = _validate_url(url)
    if error:
        logger.warning("Invalid URL submitted: %s — %s", url, error)
        return {"url": url, "score": 0, "risk_level": "Unknown", "verdict": error,
                "checks": [], "error": error}

    logger.info("Starting scan: %s", url)
    start = time.monotonic()

    checks = [
        url_structure_check.check(url),
        tld_check.check(url),
        domain_check.check(url),
        whois_check.check(url),
        ssl_check.check(url),
        content_check.check(url),
        redirect_check.check(url),
    ]

    total_score = min(sum(c["score"] for c in checks), MAX_SCORE)

    if total_score <= 30:
        risk_level = "Low"
    elif total_score <= 60:
        risk_level = "Medium"
    else:
        risk_level = "High"

    high_risk_checks = [c for c in checks if c["status"] == "HIGH RISK"]
    suspicious_checks = [c for c in checks if c["status"] == "SUSPICIOUS"]

    if risk_level == "High":
        top = (high_risk_checks or suspicious_checks)[0]["detail"] if (high_risk_checks or suspicious_checks) else ""
        verdict = f"HIGH RISK — Multiple phishing indicators detected. {top}"
    elif risk_level == "Medium":
        top = (suspicious_checks or high_risk_checks)[0]["detail"] if (suspicious_checks or high_risk_checks) else ""
        verdict = f"MEDIUM RISK — Some suspicious indicators present. {top}"
    else:
        verdict = "LOW RISK — No significant phishing indicators detected."

    elapsed = time.monotonic() - start
    logger.info(
        "Scan complete: %s | score=%d | risk=%s | %.2fs",
        url, total_score, risk_level, elapsed,
    )

    # Log each flagged check at DEBUG level for full traceability
    for c in checks:
        if c["status"] not in ("PASS", "UNKNOWN"):
            logger.debug("  [%s] %s — %s", c["status"], c["name"], c["detail"])

    return {
        "url": url,
        "score": total_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "checks": checks,
        "error": None,
    }
