"""
Subdomain Brand Injection Detection.

Catches a specific attack pattern that the domain lookalike check misses:
placing a legitimate brand's domain (or label) in the SUBDOMAIN position
to trick users into thinking they're on the real site.

Examples:
  alrajhibank.com.sa.evil-login.xyz   → brand's full domain used as subdomain
  stc.verify-account.xyz             → brand label used as a subdomain
  ncb.com.sa.phishing.com            → full Saudi bank domain as subdomain prefix

The domain lookalike check compares only the REGISTERED domain label.
This check inspects subdomain labels.

Score logic:
  Legitimate brand domain is a subdomain prefix  → +25 HIGH RISK
  Brand label found in subdomain labels           → +20 HIGH RISK
  No brand injection detected                     → +0  PASS
"""

from urllib.parse import urlparse
from detector.brands import SAUDI_BRANDS


def check(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc.lower().removeprefix("www.")
    labels = hostname.split(".")

    for brand, legit_domain in SAUDI_BRANDS.items():
        # Skip if this IS the legitimate domain
        if hostname == legit_domain or hostname.endswith("." + legit_domain):
            continue

        # Pattern 1: full legitimate domain used as a subdomain prefix
        # e.g. "alrajhibank.com.sa.evil.xyz" starts with "alrajhibank.com.sa."
        if hostname.startswith(legit_domain + "."):
            return {
                "name": "Subdomain Brand Injection",
                "status": "HIGH RISK",
                "score": 25,
                "detail": (
                    f'The legitimate domain "{legit_domain}" ({brand}) appears as a '
                    f'subdomain prefix of "{hostname}" — classic trust-spoofing technique.'
                ),
            }

        # Pattern 2: brand's registered label found in subdomain position
        # e.g. "stc.verify-account.xyz" → 'stc' is a subdomain of 'verify-account.xyz'
        brand_label = legit_domain.split(".")[0]
        # Subdomain labels = everything except the last 2 parts (SLD + TLD)
        subdomain_labels = labels[:-2]
        if brand_label in subdomain_labels:
            return {
                "name": "Subdomain Brand Injection",
                "status": "HIGH RISK",
                "score": 20,
                "detail": (
                    f'"{brand_label}" ({brand}) appears as a subdomain label in '
                    f'"{hostname}" — the actual registered domain is unrelated.'
                ),
            }

    return {
        "name": "Subdomain Brand Injection",
        "status": "PASS",
        "score": 0,
        "detail": "No brand name injection detected in subdomain labels.",
    }
