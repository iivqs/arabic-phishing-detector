"""
Redirect chain analysis.

Follows all redirects and compares the final domain to the original.
Phishing pages often redirect the victim through multiple domains to hide
the true destination or to load the real bank site in a frame.

Score logic:
  Final domain differs from entered domain → +15
  No redirects / same domain → +0
  Fetch failed → +0 (skip gracefully)
"""

import requests
from urllib.parse import urlparse

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}
FETCH_TIMEOUT = 10


def _get_base_domain(url: str) -> str:
    """Return netloc without www. prefix."""
    return urlparse(url).netloc.lower().removeprefix("www.")


def check(url: str) -> dict:
    original_domain = _get_base_domain(url)

    try:
        response = requests.get(url, headers=HEADERS, timeout=FETCH_TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        return {
            "name": "Redirect Chain",
            "status": "UNKNOWN",
            "score": 0,
            "detail": f"Could not follow redirects: {type(e).__name__}. Skipping.",
        }

    final_url = response.url
    final_domain = _get_base_domain(final_url)

    redirect_count = len(response.history)

    if redirect_count == 0:
        return {
            "name": "Redirect Chain",
            "status": "PASS",
            "score": 0,
            "detail": "No redirects. URL resolves directly.",
        }

    if original_domain == final_domain:
        return {
            "name": "Redirect Chain",
            "status": "PASS",
            "score": 0,
            "detail": f"{redirect_count} redirect(s) — final domain matches original.",
        }

    chain = " → ".join(
        [url] + [r.headers.get("Location", r.url) for r in response.history] + [final_url]
    )
    return {
        "name": "Redirect Chain",
        "status": "SUSPICIOUS",
        "score": 15,
        "detail": (
            f"Redirected {redirect_count} time(s). Final domain is "
            f'"{final_domain}" (entered: "{original_domain}"). Chain: {chain}'
        ),
    }
