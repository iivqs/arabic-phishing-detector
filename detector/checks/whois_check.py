"""
Domain age check via WHOIS.

Phishing domains are typically registered days or weeks before an attack
and abandoned quickly. A newly registered domain is a strong indicator.

Score logic:
  age < 14 days   → +25 (very high risk)
  age < 30 days   → +15 (suspicious)
  age < 90 days   → +5  (mildly suspicious)
  age >= 90 days  → +0
  WHOIS timeout   → +0  (skip gracefully)
"""

import whois
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone
from urllib.parse import urlparse

WHOIS_TIMEOUT = 8  # seconds — independent of the outer scan timeout


def _fetch_whois(domain: str):
    return whois.whois(domain)


def check(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().removeprefix("www.")

    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_fetch_whois, domain)
            w = future.result(timeout=WHOIS_TIMEOUT)

        creation_date = w.creation_date

        if creation_date is None:
            return {
                "name": "Domain Age",
                "status": "UNKNOWN",
                "score": 0,
                "detail": "WHOIS returned no creation date. Skipping.",
            }

        # python-whois may return a list; use the earliest date
        if isinstance(creation_date, list):
            creation_date = min(creation_date)

        # Ensure timezone-aware comparison
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days

        if age_days < 14:
            return {"name": "Domain Age", "status": "HIGH RISK",  "score": 25,
                    "detail": f"Domain registered only {age_days} days ago."}
        elif age_days < 30:
            return {"name": "Domain Age", "status": "SUSPICIOUS", "score": 15,
                    "detail": f"Domain registered {age_days} days ago (less than 30 days)."}
        elif age_days < 90:
            return {"name": "Domain Age", "status": "CAUTION",    "score": 5,
                    "detail": f"Domain registered {age_days} days ago (less than 90 days)."}
        else:
            return {"name": "Domain Age", "status": "PASS",       "score": 0,
                    "detail": f"Domain has been registered for {age_days} days."}

    except FuturesTimeout:
        return {"name": "Domain Age", "status": "UNKNOWN", "score": 0,
                "detail": f"WHOIS lookup timed out after {WHOIS_TIMEOUT}s. Skipping."}
    except Exception as e:
        return {"name": "Domain Age", "status": "UNKNOWN", "score": 0,
                "detail": f"WHOIS lookup failed: {type(e).__name__}. Skipping."}
