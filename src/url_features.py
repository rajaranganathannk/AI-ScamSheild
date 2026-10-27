"""URL validation, feature extraction, and human-readable heuristic evidence."""

import ipaddress
import re
from urllib.parse import urlsplit


MAX_URL_LENGTH = 2048
SHORTENER_DOMAINS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "is.gd",
    "rebrand.ly",
    "t.co",
    "tinyurl.com",
}
SUSPICIOUS_KEYWORDS = (
    "account",
    "confirm",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
)
_SUSPICIOUS_CHARACTERS = set("@%\\<>")


class URLValidationError(ValueError):
    """Raised when an input is not a supported, well-formed HTTP(S) URL."""


def normalize_url(value: str) -> str:
    """Trim and validate a URL without making any network request."""
    if not isinstance(value, str):
        raise URLValidationError("Enter a URL as text.")
    value = value.strip()
    if not value:
        raise URLValidationError("Enter a URL to analyze.")
    if len(value) > MAX_URL_LENGTH:
        raise URLValidationError(f"URLs must be {MAX_URL_LENGTH} characters or fewer.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise URLValidationError("The URL contains unsupported control characters.")
    if any(char.isspace() for char in value):
        raise URLValidationError("Spaces are not allowed inside a URL.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            raise URLValidationError("Use a complete URL beginning with http:// or https://.")
        if parsed.port is not None and not 0 < parsed.port < 65536:
            raise URLValidationError("The URL contains an invalid port.")
    except ValueError as exc:
        if isinstance(exc, URLValidationError):
            raise
        raise URLValidationError("The URL could not be parsed.") from exc
    return value


def extract_features(url: str) -> dict[str, float]:
    """Return stable numeric features suitable for a scikit-learn classifier."""
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    hostname = (parsed.hostname or "").rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False

    labels = [label for label in hostname.split(".") if label]
    path = parsed.path or ""
    query = parsed.query or ""
    keyword_matches = sum(
        len(re.findall(rf"(?i){re.escape(keyword)}", normalized))
        for keyword in SUSPICIOUS_KEYWORDS
    )
    try:
        port = parsed.port
    except ValueError:
        port = None

    return {
        "url_length": float(len(normalized)),
        "hostname_length": float(len(hostname)),
        "dot_count": float(hostname.count(".")),
        "subdomain_count": float(max(0, len(labels) - 2)),
        "is_ip_address": float(is_ip),
        "uses_https": float(parsed.scheme.lower() == "https"),
        "suspicious_character_count": float(sum(char in _SUSPICIOUS_CHARACTERS for char in normalized)),
        "percent_encoding_count": float(normalized.count("%")),
        "has_at_symbol": float("@" in normalized),
        "has_punycode": float(any(label.startswith("xn--") for label in labels)),
        "has_non_ascii_hostname": float(any(ord(char) > 127 for char in hostname)),
        "is_shortened": float(hostname in SHORTENER_DOMAINS),
        "suspicious_keyword_count": float(keyword_matches),
        "hyphen_count": float(hostname.count("-")),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "query_parameter_count": float(query.count("&") + (1 if query else 0)),
        "has_fragment": float(bool(parsed.fragment)),
        "has_port": float(port is not None),
        "numeric_hostname_label_count": float(sum(label.isdigit() for label in labels)),
        "hostname_label_count": float(len(labels)),
        "has_credentials": float(parsed.username is not None or parsed.password is not None),
    }


def explain_heuristics(url: str) -> list[dict[str, str]]:
    """Describe URL characteristics; these are signals, not proof of phishing."""
    features = extract_features(url)
    parsed = urlsplit(normalize_url(url))
    evidence: list[dict[str, str]] = []

    def add(key: str, message: str, severity: str = "warning") -> None:
        evidence.append({"key": key, "message": message, "severity": severity})

    if features["is_ip_address"]:
        add("ip-host", "The host is an IP address rather than a recognizable domain.")
    if not features["uses_https"]:
        add("no-https", "The URL uses HTTP, so its connection is not protected by HTTPS.")
    if features["has_at_symbol"]:
        add("at-symbol", "An @ symbol appears in the URL and can obscure the actual destination.")
    if features["has_credentials"]:
        add("credentials", "The URL includes user-information before the host.")
    if features["is_shortened"]:
        add("shortener", "The host is a URL-shortening service, which hides the final destination.")
    if features["has_punycode"] or features["has_non_ascii_hostname"]:
        add("internationalized-host", "The hostname uses internationalized characters or punycode.")
    if features["suspicious_character_count"] or features["percent_encoding_count"]:
        add("encoded-or-unusual", "The URL contains encoded or unusual characters.")
    if features["hostname_label_count"] >= 5:
        add("many-host-labels", "The hostname contains several dot-separated labels.")
    if features["hyphen_count"] >= 3:
        add("many-hyphens", "The hostname contains multiple hyphens.")
    if features["suspicious_keyword_count"]:
        add("sensitive-terms", "The URL contains terms commonly used in account or credential prompts.")
    if features["url_length"] >= 120:
        add("long-url", "The URL is unusually long.")
    if features["query_parameter_count"] >= 5:
        add("many-parameters", "The URL has many query parameters.")
    if not evidence:
        evidence.append(
            {
                "key": "no-obvious-signals",
                "message": "No listed heuristic indicators were detected; this does not establish that the URL is safe.",
                "severity": "info",
            }
        )
    return evidence
