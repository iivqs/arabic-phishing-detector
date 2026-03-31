"""
Page content analysis.

Fetches the page and checks if it contains brand names or Arabic keywords
that belong to a known Saudi brand — but the domain doesn't match that brand.
This is the classic phishing pattern: copy the real site's content onto a
fake domain.

Score logic:
  Brand name found on wrong domain → +30
  Brand name found on correct domain → +0
  Page fetch failed → +0 (skip gracefully)
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse
from detector.brands import SAUDI_BRANDS
from detector.safe_request import safe_get, SSRFError

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}
FETCH_TIMEOUT = 10


def check(url: str) -> dict:
    parsed = urlparse(url)
    target_domain = parsed.netloc.lower().removeprefix("www.")

    try:
        response = safe_get(
            url, headers=HEADERS, timeout=FETCH_TIMEOUT,
            allow_redirects=True, stream=True,
        )
        response.raise_for_status()
        content = response.raw.read(1_048_576, decode_content=True)  # cap at 1 MB
    except SSRFError as e:
        return {
            "name": "Content Analysis",
            "status": "HIGH RISK",
            "score": 30,
            "detail": f"URL targets an internal/private address — SSRF blocked. {e}",
        }
    except Exception as e:
        return {
            "name": "Content Analysis",
            "status": "UNKNOWN",
            "score": 0,
            "detail": f"Could not fetch page: {type(e).__name__}. Skipping.",
        }

    soup = BeautifulSoup(content, "html.parser")
    page_text = soup.get_text(separator=" ", strip=True).lower()
    page_title = soup.title.string.lower() if soup.title else ""
    full_text = page_text + " " + page_title

    matched_brand = None
    matched_domain = None

    for brand, legit_domain in SAUDI_BRANDS.items():
        if brand.lower() in full_text or legit_domain.lower() in full_text:
            matched_brand = brand
            matched_domain = legit_domain
            break

    if matched_brand is None:
        return {
            "name": "Content Analysis",
            "status": "PASS",
            "score": 0,
            "detail": "No known Saudi brand names detected in page content.",
        }

    # Brand found — is the domain the legitimate one?
    if target_domain == matched_domain or target_domain.endswith("." + matched_domain):
        return {
            "name": "Content Analysis",
            "status": "PASS",
            "score": 0,
            "detail": f'Page mentions "{matched_brand}" and domain matches the legitimate site.',
        }

    return {
        "name": "Content Analysis",
        "status": "HIGH RISK",
        "score": 30,
        "detail": (
            f'Page content references "{matched_brand}" (legitimate domain: {matched_domain}) '
            f'but this domain is "{target_domain}". Classic phishing pattern.'
        ),
    }
