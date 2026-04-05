"""
URL structure analysis.

Examines the structure of the URL itself for common phishing patterns:

1. IP address as hostname — legitimate banks never use raw IPs
2. Excessive subdomains — attackers use deep subdomains to bury the real domain
   e.g. "login.stc.verify.malicious.com" — real domain is malicious.com
3. Suspicious path keywords — login, verify, update, secure, account, password
   appearing in URLs that don't belong to a known brand
4. Very long URL — phishing URLs are often padded to obscure the real domain

Score logic:
  IP as hostname         → +20
  4+ subdomain levels    → +15
  Suspicious keywords    → +10
  URL length > 100 chars → +5
"""

import re
from urllib.parse import urlparse
from detector.brands import LEGITIMATE_DOMAINS

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

SUSPICIOUS_KEYWORDS = {
    # English
    "login", "verify", "verification", "update", "secure", "security",
    "account", "password", "signin", "sign-in", "credential", "banking",
    "support", "helpdesk", "alert", "confirm", "reset", "suspended",
    # Arabic-transliterated common phishing words
    "tafa3ul", "tasjil", "hesab",
}


def check(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc.lower().removeprefix("www.")
    path = parsed.path.lower()
    full_url = url.lower()

    issues = []
    score = 0

    # 1. IP as hostname
    if IP_PATTERN.match(hostname):
        issues.append(f"Hostname is a raw IP address ({hostname}) — legitimate services use domain names.")
        score += 20

    # 2. Excessive subdomain depth
    # For ccSLD domains like .com.sa, .gov.sa — the TLD is 2 parts, so we need
    # to subtract 3 (subdomain + SLD + ccSLD) instead of 2.
    parts = hostname.split(".")
    if len(parts) >= 3 and parts[-2] in ("com", "gov", "edu", "net", "org"):
        # e.g. login.stcpay.com.sa → TLD=".com.sa", SLD="stcpay", subdomains=["login"]
        registered = ".".join(parts[-3:])  # stcpay.com.sa
        subdomain_count = len(parts) - 3
    else:
        registered = ".".join(parts[-2:])  # stcpay.com
        subdomain_count = len(parts) - 2

    if subdomain_count >= 3:
        issues.append(
            f"URL has {subdomain_count} subdomain levels — "
            "attackers use deep subdomains to bury the real domain at the end."
        )
        score += 15
    elif subdomain_count == 2:
        # Only flag if the registered domain isn't a known legit one
        if registered not in LEGITIMATE_DOMAINS:
            issues.append(f"URL has {subdomain_count} subdomain levels on an unknown domain.")
            score += 5

    # 3. Suspicious path keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in full_url]
    if found_keywords:
        issues.append(
            f"URL contains suspicious keywords: {', '.join(found_keywords[:3])}."
        )
        score += 10

    # 4. Very long URL
    if len(url) > 150:
        issues.append(f"URL is unusually long ({len(url)} characters).")
        score += 5

    score = min(score, 20)

    if not issues:
        return {
            "name": "URL Structure",
            "status": "PASS",
            "score": 0,
            "detail": "URL structure looks normal.",
        }

    status = "HIGH RISK" if score >= 15 else "SUSPICIOUS" if score >= 8 else "CAUTION"
    return {
        "name": "URL Structure",
        "status": status,
        "score": score,
        "detail": " | ".join(issues),
    }
