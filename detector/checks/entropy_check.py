"""
Domain Entropy Analysis.

Measures the Shannon entropy of the registered domain label.
Legitimate, human-readable domain names have low entropy (predictable
character patterns), while algorithmically-generated phishing domains
(DGA — Domain Generation Algorithm) have high entropy because their
characters are essentially random.

Examples:
  "alrajhibank"  → entropy ≈ 3.03  (human-readable, low entropy)
  "stc"          → entropy ≈ 1.58  (very short, skip)
  "xk9vqpnrz2t"  → entropy ≈ 3.46  (random-looking, high entropy)
  "a1b2c3d4e5f6"  → entropy ≈ 3.46  (algorithmic, high entropy)

Score logic:
  Best label length < 7                      → +0  (too short to be meaningful)
  entropy ≥ 4.0                              → +15 HIGH RISK  (very random)
  entropy ≥ 3.8                              → +8  SUSPICIOUS (likely random)
  entropy ≥ 3.4 AND label mixes digits+alpha → +8  SUSPICIOUS (DGA pattern)
  otherwise                                  → +0  PASS
"""

import math
from urllib.parse import urlparse


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits) of a string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _best_label(hostname: str) -> str:
    """
    Return the highest-entropy label from the hostname that is long enough
    to be meaningful. This avoids the need for a public suffix list — instead
    of guessing which label is the "registered domain", we simply examine the
    label most likely to be suspicious (the one with the most entropy).
    Short labels (< 7 chars) are skipped as they are too short to analyse.
    """
    parts = hostname.removeprefix("www.").split(".")
    candidates = [p for p in parts if len(p) >= 7]
    if not candidates:
        # Fall back to the longest label regardless of length
        return max(parts, key=len) if parts else hostname
    return max(candidates, key=_shannon_entropy)


def check(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    label = _best_label(hostname)

    # Too short to analyse meaningfully
    if len(label) < 7:
        return {
            "name": "Domain Entropy",
            "status": "PASS",
            "score": 0,
            "detail": f'Domain label "{label}" is too short for entropy analysis.',
        }

    entropy = _shannon_entropy(label)

    has_digits = any(c.isdigit() for c in label)
    has_letters = any(c.isalpha() for c in label)
    mixed_alphanum = has_digits and has_letters

    if entropy >= 4.0:
        return {
            "name": "Domain Entropy",
            "status": "HIGH RISK",
            "score": 15,
            "detail": (
                f'Domain label "{label}" has very high entropy ({entropy:.2f} bits) — '
                "consistent with an algorithmically-generated phishing domain."
            ),
        }

    if entropy >= 3.8:
        return {
            "name": "Domain Entropy",
            "status": "SUSPICIOUS",
            "score": 8,
            "detail": (
                f'Domain label "{label}" has elevated entropy ({entropy:.2f} bits) — '
                "may be a randomly generated domain."
            ),
        }

    # DGA domains commonly mix digits + letters at moderate entropy
    if mixed_alphanum and entropy >= 3.4:
        return {
            "name": "Domain Entropy",
            "status": "SUSPICIOUS",
            "score": 8,
            "detail": (
                f'Domain label "{label}" mixes letters and digits with elevated '
                f"entropy ({entropy:.2f} bits) — pattern consistent with DGA domains."
            ),
        }

    return {
        "name": "Domain Entropy",
        "status": "PASS",
        "score": 0,
        "detail": f'Domain label "{label}" has normal entropy ({entropy:.2f} bits).',
    }
