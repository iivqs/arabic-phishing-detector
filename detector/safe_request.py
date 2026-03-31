"""
SSRF-safe HTTP request helper.

Resolves the hostname BEFORE making the request and blocks any URL that
points to a private, loopback, link-local, or reserved IP range.

Covers:
  - 127.0.0.0/8       loopback
  - 10.0.0.0/8        RFC 1918 private
  - 172.16.0.0/12     RFC 1918 private
  - 192.168.0.0/16    RFC 1918 private
  - 169.254.0.0/16    link-local (AWS metadata at 169.254.169.254)
  - 0.0.0.0/8         "this" network
  - ::1/128           IPv6 loopback
  - fc00::/7          IPv6 unique-local
  - 100.64.0.0/10     carrier-grade NAT
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


class SSRFError(ValueError):
    """Raised when a URL resolves to a blocked (internal) IP address."""


def _resolve_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Resolve hostname to an IP address object. Raises SSRFError on failure."""
    try:
        resolved = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        if not resolved:
            raise SSRFError(f"Could not resolve hostname: {hostname}")
        ip_str = resolved[0][4][0]
        return ipaddress.ip_address(ip_str)
    except socket.gaierror as e:
        raise SSRFError(f"DNS resolution failed for {hostname}: {e}") from e


def _assert_public(url: str) -> None:
    """
    Resolve the URL's hostname and raise SSRFError if it maps to a
    private/reserved address.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("URL has no hostname.")

    # Raw IP in the URL — check directly without DNS
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        # It's a domain name — resolve it
        ip = _resolve_ip(hostname)

    for network in _BLOCKED_NETWORKS:
        if ip in network:
            raise SSRFError(
                f"Blocked: {hostname} resolves to {ip}, which is in reserved range {network}."
            )


def safe_get(url: str, **kwargs) -> requests.Response:
    """
    Drop-in replacement for requests.get() that blocks SSRF attempts.
    Raises SSRFError if the URL resolves to a private/internal address.
    All kwargs are forwarded to requests.get().
    """
    _assert_public(url)
    return requests.get(url, **kwargs)
