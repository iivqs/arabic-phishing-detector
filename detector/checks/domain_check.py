"""
Domain lookalike detection.

Detects typosquatting against known Saudi brand domains using two strategies:

1. Ratio similarity — edit distance as a fraction of label length.
   Catches character substitutions/insertions in medium-to-long labels.
   e.g. "alrajhi-bank" vs "alrajhibank" → 1/12 = 8% → HIGH RISK

2. Starts-with prefix — target label begins with a brand label (≥ 3 chars).
   Catches "stc-sa.net", "stcphishing.com" etc. even when ratio differs.
   e.g. "stc-sa" starts with "stc" → SUSPICIOUS

Using ratio (not absolute distance) avoids false positives where two short
unrelated words happen to share a small edit distance.

Score logic:
  ratio <= 0.25  → +40 (HIGH RISK)
  ratio <= 0.50  → +20 (SUSPICIOUS)
  starts-with brand label (≥ 3 chars)  → +20 (SUSPICIOUS, only if no ratio hit)
  none of the above  → +0
"""

from urllib.parse import urlparse
import Levenshtein
from detector.brands import SAUDI_BRANDS, LEGITIMATE_DOMAINS

CLOSE_RATIO = 0.25
MODERATE_RATIO = 0.50
MIN_PREFIX_LEN = 3


def _registered_label(domain: str) -> str:
    """Return the leftmost label of a domain (the part before the first dot)."""
    return domain.split(".")[0]


def _similarity_ratio(a: str, b: str) -> float:
    """Edit distance divided by the length of the longer string (0=identical, 1=completely different)."""
    dist = Levenshtein.distance(a, b)
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 0.0
    return dist / max_len


def check(url: str) -> dict:
    parsed = urlparse(url)
    target_domain = parsed.netloc.lower().removeprefix("www.")

    # Already a known legitimate domain — no risk
    if target_domain in LEGITIMATE_DOMAINS:
        return {
            "name": "Domain Lookalike",
            "status": "PASS",
            "score": 0,
            "detail": f'"{target_domain}" is a known legitimate domain.',
        }

    target_label = _registered_label(target_domain)

    best_ratio = float("inf")
    best_ratio_match = None
    prefix_match = None

    for brand, legit_domain in SAUDI_BRANDS.items():
        legit_label = _registered_label(legit_domain)
        ratio = _similarity_ratio(target_label, legit_label)

        if ratio < best_ratio:
            best_ratio = ratio
            best_ratio_match = (brand, legit_domain)

        # Prefix check: target starts with the brand label
        if (
            prefix_match is None
            and len(legit_label) >= MIN_PREFIX_LEN
            and target_label.startswith(legit_label)
            and target_label != legit_label
        ):
            prefix_match = (brand, legit_domain)

    # Ratio-based result takes precedence
    if best_ratio <= CLOSE_RATIO:
        return {
            "name": "Domain Lookalike",
            "status": "HIGH RISK",
            "score": 40,
            "detail": (
                f'"{target_domain}" is suspiciously close to '
                f'"{best_ratio_match[1]}" ({best_ratio_match[0]}) '
                f"— similarity ratio: {best_ratio:.0%}"
            ),
        }
    elif best_ratio <= MODERATE_RATIO:
        return {
            "name": "Domain Lookalike",
            "status": "SUSPICIOUS",
            "score": 20,
            "detail": (
                f'"{target_domain}" resembles "{best_ratio_match[1]}" '
                f'({best_ratio_match[0]}) — similarity ratio: {best_ratio:.0%}'
            ),
        }
    elif prefix_match:
        return {
            "name": "Domain Lookalike",
            "status": "SUSPICIOUS",
            "score": 20,
            "detail": (
                f'"{target_domain}" label starts with "{_registered_label(prefix_match[1])}" '
                f'(brand: {prefix_match[0]}, legit domain: {prefix_match[1]})'
            ),
        }
    else:
        return {
            "name": "Domain Lookalike",
            "status": "PASS",
            "score": 0,
            "detail": f'"{target_domain}" does not resemble any known Saudi brand domain.',
        }
