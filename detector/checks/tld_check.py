"""
Suspicious TLD detection.

Phishing domains frequently use free or low-cost TLDs that require no
identity verification. Legitimate Saudi banks and government portals
almost exclusively use .com.sa, .gov.sa, .edu.sa, or well-known TLDs.

Score logic:
  Known bad TLD (.tk, .ml, .ga, .cf, .gq, .xyz, .top, .click, .pw) → +15
  Unusual TLD (.info, .biz, .online, .site, .icu, .live)             → +8
  Trusted TLD (.com.sa, .gov.sa, .com, .net, .org, .sa)             → +0
"""

from urllib.parse import urlparse

BAD_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
            ".click", ".pw", ".cc", ".su", ".ru.com"}

UNUSUAL_TLDS = {".info", ".biz", ".online", ".site", ".icu",
                ".live", ".club", ".shop", ".store", ".fun"}

TRUSTED_TLDS = {".com.sa", ".gov.sa", ".edu.sa", ".sa",
                ".com", ".net", ".org", ".io"}


def _get_tld(domain: str) -> str:
    """Return the TLD portion of a domain (handles .com.sa style)."""
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ("com", "gov", "edu", "net", "org"):
        return f".{parts[-2]}.{parts[-1]}"
    return f".{parts[-1]}"


def check(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().removeprefix("www.")
    tld = _get_tld(domain)

    if tld in BAD_TLDS:
        return {
            "name": "Suspicious TLD",
            "status": "HIGH RISK",
            "score": 15,
            "detail": (
                f'TLD "{tld}" is commonly abused in phishing campaigns '
                f"(free, no identity verification required)."
            ),
        }
    elif tld in UNUSUAL_TLDS:
        return {
            "name": "Suspicious TLD",
            "status": "CAUTION",
            "score": 8,
            "detail": (
                f'TLD "{tld}" is unusual for Saudi financial or government services.'
            ),
        }
    else:
        return {
            "name": "Suspicious TLD",
            "status": "PASS",
            "score": 0,
            "detail": f'TLD "{tld}" is standard.',
        }
