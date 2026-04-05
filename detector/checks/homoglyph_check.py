"""
IDN Homoglyph / Mixed-Script Detection.

Attackers register Punycode domains (xn-- prefix) containing Unicode characters
that are visually identical to Latin letters — e.g. Cyrillic 'а' (U+0430) vs
Latin 'a' (U+0061). This check detects three attack patterns:

1. Mixed-script labels: a single DNS label containing characters from more than
   one Unicode script (Latin + Cyrillic, Latin + Greek, etc.).
2. Punycode domains whose decoded label is similar to a known Saudi brand label
   after ASCII skeleton normalisation (NFKD + drop non-ASCII).
3. Any Punycode domain that doesn't match the above but still warrants caution.

Score logic:
  Mixed-script label detected         → +20 (HIGH RISK)
  Punycode, decoded close to brand    → +25 (HIGH RISK)
  Punycode, no brand match            → +5  (CAUTION)
  No Punycode / no issues             → +0  (PASS)
"""

import unicodedata
from urllib.parse import urlparse

import Levenshtein

from detector.brands import SAUDI_BRANDS

CLOSE_RATIO = 0.20   # tighter than domain_check — homoglyph attacks are precise


def _get_script(char: str) -> str:
    """Return the first word of the Unicode character name (i.e. the script)."""
    try:
        name = unicodedata.name(char, "")
        return name.split()[0] if name else "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def _is_mixed_script(label: str) -> bool:
    """True if the label mixes characters from more than one Unicode script."""
    scripts = {_get_script(c) for c in label if c.isalpha()}
    meaningful = {s for s in scripts if s not in ("UNKNOWN", "MODIFIER", "COMBINING")}
    return len(meaningful) > 1


def _decode_label(label: str) -> str:
    """Decode a Punycode (ACE) DNS label to Unicode. Returns original on failure."""
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            return label
    return label


def _to_ascii_skeleton(label: str) -> str:
    """
    NFKD-normalise then strip non-ASCII characters.
    Maps many accented / homoglyph characters to their ASCII equivalents.
    """
    normalized = unicodedata.normalize("NFKD", label)
    return normalized.encode("ascii", errors="ignore").decode("ascii").lower()


def check(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc.lower().removeprefix("www.")

    labels = hostname.split(".")
    decoded_labels = [_decode_label(lbl) for lbl in labels]
    has_punycode = any(lbl.startswith("xn--") for lbl in labels)

    # --- Check 1: mixed-script labels ---
    mixed = [lbl for lbl in decoded_labels if _is_mixed_script(lbl)]
    if mixed:
        return {
            "name": "IDN Homoglyph",
            "status": "HIGH RISK",
            "score": 20,
            "detail": (
                f"Domain label(s) {mixed} contain characters from multiple Unicode "
                "scripts — classic homoglyph spoofing technique."
            ),
        }

    # --- Check 2: Punycode similar to a known brand ---
    # Inspect ALL decoded labels, not just the first one — a homoglyph attack
    # can appear in any label position (e.g. login.аpple-sa.com).
    if has_punycode:
        best_ratio, best_match, best_label_str = float("inf"), None, None
        for decoded_label in decoded_labels:
            skeleton = _to_ascii_skeleton(decoded_label)
            if not skeleton:
                continue
            for brand, legit_domain in SAUDI_BRANDS.items():
                legit_label = legit_domain.split(".")[0]
                denom = max(len(skeleton), len(legit_label), 1)
                ratio = Levenshtein.distance(skeleton, legit_label) / denom
                if ratio < best_ratio:
                    best_ratio, best_match, best_label_str = ratio, (brand, legit_domain), decoded_label

        if best_ratio <= CLOSE_RATIO and best_match:
            return {
                "name": "IDN Homoglyph",
                "status": "HIGH RISK",
                "score": 25,
                "detail": (
                    f'Punycode domain "{hostname}" decodes to label "{best_label_str}" '
                    f'which is visually similar to "{best_match[1]}" ({best_match[0]}) — '
                    "homoglyph spoofing suspected."
                ),
            }

        return {
            "name": "IDN Homoglyph",
            "status": "CAUTION",
            "score": 5,
            "detail": (
                f'Domain uses Punycode encoding ("{hostname}"). '
                f'Decoded: {".".join(decoded_labels)}. No brand match found.'
            ),
        }

    return {
        "name": "IDN Homoglyph",
        "status": "PASS",
        "score": 0,
        "detail": "No IDN homoglyph indicators detected.",
    }
