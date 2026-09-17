"""SSRF protection for LLM provider endpoints."""

import contextlib
import ipaddress
import urllib.parse

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
}

BLOCKED_TLDS = {
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
}


class SSRFViolationError(ValueError):
    """Raised when an LLM endpoint violates SSRF security boundaries."""


def validate_llm_endpoint(
    url: str,
    allow_private: bool = False,
    allow_http: bool = False,
) -> str:
    """Validate that an LLM base_url is safe and not an SSRF vector.

    Args:
        url: The endpoint URL to validate.
        allow_private: If True, permit private/loopback addresses (e.g. for testing).
        allow_http: If True, permit http:// scheme (e.g. in local development/testing).

    Returns:
        The sanitized base URL (stripped trailing slashes).

    Raises:
        SSRFViolationError: If the URL targets internal, loopback, or metadata services.
    """
    if not url or not isinstance(url, str):
        raise SSRFViolationError("Endpoint URL cannot be empty")

    cleaned = url.strip()
    parsed = urllib.parse.urlparse(cleaned)

    if parsed.scheme not in ("http", "https"):
        raise SSRFViolationError(f"Unsupported endpoint scheme: '{parsed.scheme}'. Must be https.")

    if parsed.scheme == "http" and not (allow_http or allow_private):
        raise SSRFViolationError(
            "Insecure HTTP scheme is not permitted for LLM endpoints. Use HTTPS."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFViolationError(f"Invalid endpoint URL without hostname: '{cleaned}'")

    hostname_lower = hostname.lower()

    if not allow_private:
        # Check blocked hostnames
        if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(".localhost"):
            raise SSRFViolationError(
                f"LLM endpoint targets a forbidden local/metadata host: '{hostname}'"
            )

        # Check blocked private/internal TLDs
        for tld in BLOCKED_TLDS:
            if hostname_lower.endswith(tld):
                raise SSRFViolationError(f"LLM endpoint targets an internal domain: '{hostname}'")

        # Check IP addresses
        ip = None
        with contextlib.suppress(ValueError):
            ip = ipaddress.ip_address(hostname_lower)

        if ip is not None:
            if ip.is_loopback:
                raise SSRFViolationError(f"LLM endpoint targets a loopback IP: '{hostname}'")
            if ip.is_private:
                raise SSRFViolationError(f"LLM endpoint targets a private network IP: '{hostname}'")
            if ip.is_link_local:
                raise SSRFViolationError(f"LLM endpoint targets a link-local IP: '{hostname}'")
            if ip.is_reserved or ip.is_multicast:
                raise SSRFViolationError(f"LLM endpoint targets a reserved IP: '{hostname}'")
            if str(ip) == "169.254.169.254":
                raise SSRFViolationError(
                    f"LLM endpoint targets cloud metadata service: '{hostname}'"
                )
            if str(ip) == "0.0.0.0":
                raise SSRFViolationError(f"LLM endpoint targets wildcard address: '{hostname}'")

    # Return normalized URL without trailing slash
    return cleaned.rstrip("/")
