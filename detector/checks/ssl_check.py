"""
SSL certificate check.

Legitimate Saudi banking and government sites always use HTTPS with valid certs.
A missing or mismatched certificate is a red flag.

Score logic:
  No HTTPS (http://)           → +20
  HTTPS but cert error         → +20
  HTTPS, cert valid            → +0
"""

import ssl
import socket
from urllib.parse import urlparse


def check(url: str) -> dict:
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return {
            "name": "SSL Certificate",
            "status": "HIGH RISK",
            "score": 20,
            "detail": "Site uses plain HTTP — no encryption. Legitimate Saudi services always use HTTPS.",
        }

    hostname = parsed.netloc.lower().removeprefix("www.").split(":")[0]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                pass  # If we get here, cert is valid and matches hostname

        return {
            "name": "SSL Certificate",
            "status": "PASS",
            "score": 0,
            "detail": f"Valid SSL certificate found for {hostname}.",
        }

    except ssl.SSLCertVerificationError as e:
        return {
            "name": "SSL Certificate",
            "status": "HIGH RISK",
            "score": 20,
            "detail": f"SSL certificate verification failed: {e.reason}",
        }
    except ssl.CertificateError as e:
        return {
            "name": "SSL Certificate",
            "status": "HIGH RISK",
            "score": 20,
            "detail": f"Certificate does not match hostname: {e}",
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "name": "SSL Certificate",
            "status": "UNKNOWN",
            "score": 0,
            "detail": f"Could not connect to check SSL: {type(e).__name__}. Skipping.",
        }
