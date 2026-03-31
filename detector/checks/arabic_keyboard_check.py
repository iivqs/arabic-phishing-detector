"""
Arabic Keyboard Layout Typo Detection.

On a standard Arabic keyboard (Windows/Saudi Arabia layout), each Latin key
maps to a specific Arabic character. A Saudi user accidentally typing a URL
while Arabic keyboard is active produces Arabic characters instead of Latin.

Attackers exploit this by registering the Punycode (xn--) equivalent of
what a brand name looks like when typed on an Arabic keyboard — targeting
users who make this common keyboard-switch mistake.

Example:
  Typing "stc" on Arabic keyboard produces: س (s-key) ف (t-key) ؤ (c-key)
  = "سفؤ" → registered as Punycode domain xn--...

This check:
1. Decodes any Punycode labels in the hostname.
2. Identifies labels containing Arabic characters.
3. Reverse-maps each Arabic character back to the Latin key that would
   produce it on an Arabic keyboard.
4. Compares the resulting Latin string against known Saudi brand labels.

Score logic:
  Reverse-mapped label exactly matches brand  → +25 HIGH RISK
  Reverse-mapped label closely matches brand  → +20 HIGH RISK (ratio ≤ 0.25)
  Arabic characters but no brand match        → +0  PASS
  No Arabic characters in domain              → +0  PASS
"""

from urllib.parse import urlparse
import Levenshtein
from detector.brands import SAUDI_BRANDS

# Reverse mapping: Arabic character → Latin key that produces it
# Based on Windows Arabic (101) keyboard layout used in Saudi Arabia
_AR_TO_LATIN: dict[str, str] = {
    "ض": "q", "ص": "w", "ث": "e", "ق": "r", "ف": "t",
    "غ": "y", "ع": "u", "ه": "i", "خ": "o", "ح": "p",
    "ش": "a", "س": "s", "ي": "d", "ب": "f", "ل": "g",
    "ا": "h", "ت": "j", "ن": "k", "م": "l",
    "ظ": "z", "ء": "x", "ؤ": "c", "ر": "v", "ى": "n", "ة": "m",
    # Common diacritic-variant forms
    "أ": "h", "إ": "h", "آ": "h", "ئ": "z", "ؤ": "c",
}

CLOSE_RATIO = 0.25


def _decode_label(label: str) -> str:
    """Decode a Punycode label to Unicode."""
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            return label
    return label


def _reverse_keyboard(text: str) -> str:
    """Map each Arabic character to its Latin keyboard equivalent."""
    return "".join(_AR_TO_LATIN.get(c, "") for c in text)


def _has_arabic(text: str) -> bool:
    """Return True if the text contains any Arabic Unicode characters."""
    return any("\u0600" <= c <= "\u06ff" for c in text)


def check(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc.lower().removeprefix("www.")
    labels = hostname.split(".")

    for label in labels:
        decoded = _decode_label(label)

        if not _has_arabic(decoded):
            continue

        latin_equivalent = _reverse_keyboard(decoded)

        if not latin_equivalent:
            continue

        # Check for exact match first
        for brand, legit_domain in SAUDI_BRANDS.items():
            brand_label = legit_domain.split(".")[0]

            if latin_equivalent == brand_label:
                return {
                    "name": "Arabic Keyboard Typo",
                    "status": "HIGH RISK",
                    "score": 25,
                    "detail": (
                        f'Domain label "{decoded}" (decoded from "{label}") is '
                        f'exactly what you get when typing "{brand_label}" ({brand}) '
                        "on an Arabic keyboard — keyboard-switch phishing attack."
                    ),
                }

        # Check for close match using Levenshtein
        best_ratio, best_match = float("inf"), None
        for brand, legit_domain in SAUDI_BRANDS.items():
            brand_label = legit_domain.split(".")[0]
            denom = max(len(latin_equivalent), len(brand_label), 1)
            ratio = Levenshtein.distance(latin_equivalent, brand_label) / denom
            if ratio < best_ratio:
                best_ratio, best_match = ratio, (brand, legit_domain, brand_label)

        if best_ratio <= CLOSE_RATIO and best_match:
            return {
                "name": "Arabic Keyboard Typo",
                "status": "HIGH RISK",
                "score": 20,
                "detail": (
                    f'Domain label "{decoded}" reverse-maps to "{latin_equivalent}" '
                    f'on a Latin keyboard — closely matches "{best_match[2]}" '
                    f'({best_match[0]}). Likely a keyboard-switch phishing domain.'
                ),
            }

    return {
        "name": "Arabic Keyboard Typo",
        "status": "PASS",
        "score": 0,
        "detail": "No Arabic keyboard layout typosquatting detected.",
    }
