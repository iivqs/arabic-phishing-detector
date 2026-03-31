"""
HTML Form Exfiltration Check.

Fetches the page and inspects every <form> element's `action` attribute.
The classic phishing pattern is: clone a legitimate login page but change
the form's POST destination to an attacker-controlled server.

A form that submits to a DIFFERENT domain than the page it lives on is a
strong phishing indicator.

Score logic:
  Form POSTs to external domain  → +25 HIGH RISK
  SSRF-blocked URL               → +25 HIGH RISK
  No forms / all forms on-domain → +0  PASS
  Page fetch failed              → +0  UNKNOWN (skip gracefully)
"""

from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from detector.safe_request import safe_get, SSRFError

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}
FETCH_TIMEOUT = 10


def _base_domain(url: str) -> str:
    """Return netloc without www. prefix."""
    return urlparse(url).netloc.lower().removeprefix("www.")


def check(url: str) -> dict:
    page_domain = _base_domain(url)

    try:
        response = safe_get(
            url, headers=HEADERS, timeout=FETCH_TIMEOUT,
            allow_redirects=True, stream=True,
        )
        response.raise_for_status()
        content = response.raw.read(1_048_576, decode_content=True)  # 1 MB cap
    except SSRFError as e:
        return {
            "name": "Form Exfiltration",
            "status": "HIGH RISK",
            "score": 25,
            "detail": f"URL targets an internal/private address — SSRF blocked. {e}",
        }
    except Exception as e:
        return {
            "name": "Form Exfiltration",
            "status": "UNKNOWN",
            "score": 0,
            "detail": f"Could not fetch page: {type(e).__name__}. Skipping.",
        }

    soup = BeautifulSoup(content, "html.parser")
    forms = soup.find_all("form")

    if not forms:
        return {
            "name": "Form Exfiltration",
            "status": "PASS",
            "score": 0,
            "detail": "No HTML forms found on the page.",
        }

    has_password_field = bool(soup.find("input", {"type": "password"}))

    for form in forms:
        action = form.get("action", "").strip()

        # Empty or relative-path actions submit to the same page — safe
        if not action or action.startswith("/") or action.startswith("#"):
            continue

        # Resolve relative URLs to absolute
        absolute_action = urljoin(url, action)
        action_domain = _base_domain(absolute_action)

        if not action_domain:
            continue

        # If the action domain differs from the page domain → credential theft
        if action_domain != page_domain and not action_domain.endswith("." + page_domain):
            detail = (
                f'Form submits to "{action_domain}" but the page is hosted on '
                f'"{page_domain}"'
            )
            if has_password_field:
                detail += " — page has a password field. Likely credential harvesting."
            return {
                "name": "Form Exfiltration",
                "status": "HIGH RISK",
                "score": 25,
                "detail": detail,
            }

    return {
        "name": "Form Exfiltration",
        "status": "PASS",
        "score": 0,
        "detail": (
            f"Found {len(forms)} form(s) — all submit to the same domain."
            + (" Page has a password field." if has_password_field else "")
        ),
    }
