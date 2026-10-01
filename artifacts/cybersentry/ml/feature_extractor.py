"""Deterministic URL-only features shared with the future trained model."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, parse_qsl, urlsplit

FEATURE_NAMES = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "is_https",
    "is_ip",
    "num_subdomains",
    "num_digits",
    "num_letters",
    "num_dots",
    "num_slashes",
    "num_hyphens",
    "num_question_marks",
    "num_ampersands",
    "num_equals",
    "num_at_symbols",
    "num_percent_encoded",
    "has_punycode",
    "has_port",
    "has_fragment",
    "has_credentials",
    "query_parameter_count",
    "suspicious_keyword_count",
)

DEFAULT_SUSPICIOUS_KEYWORDS = (
    "account",
    "bank",
    "bonus",
    "confirm",
    "crypto",
    "free",
    "invoice",
    "login",
    "payment",
    "password",
    "secure",
    "urgent",
    "update",
    "verify",
    "wallet",
)

_ENCODED_COMPONENT_RE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)


def extract_url_features(
    url: str,
    parsed: SplitResult | None = None,
    suspicious_keywords: tuple[str, ...] | list[str] = DEFAULT_SUSPICIOUS_KEYWORDS,
) -> dict[str, int]:
    """Return the fixed 23-value integer feature vector for a normalized HTTP(S) URL.

    The caller should validate and normalize the URL before calling this function.
    Counts are derived only from the provided text; no hostname lookup or request is
    made. ``num_subdomains`` is the number of hostname labels beyond the final two,
    and ``suspicious_keyword_count`` counts distinct configured terms with the same
    alphabetic-boundary matching rule used by CyberSentry's rule analyzer.
    """
    if not isinstance(url, str):
        raise ValueError("URL features require URL text.")
    try:
        parsed_url = parsed if parsed is not None else urlsplit(url)
        hostname = (parsed_url.hostname or "").lower()
        port = parsed_url.port
    except ValueError as error:
        raise ValueError("URL features could not be extracted from invalid URL text.") from error

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    labels = [label for label in hostname.rstrip(".").split(".") if label]
    subdomain_count = 0 if is_ip else max(0, len(labels) - 2)
    lowered_url = url.lower()
    keyword_count = sum(
        1
        for keyword in suspicious_keywords
        if re.search(rf"(?<![a-z]){re.escape(keyword.lower())}(?![a-z])", lowered_url)
    )

    # Keep insertion order aligned with FEATURE_NAMES. This is the numeric input
    # contract used when a verified Google Colab model is connected.
    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(parsed_url.path),
        "query_length": len(parsed_url.query),
        "is_https": int(parsed_url.scheme.lower() == "https"),
        "is_ip": int(is_ip),
        "num_subdomains": subdomain_count,
        "num_digits": sum(character.isdigit() for character in url),
        "num_letters": sum(character.isalpha() for character in url),
        "num_dots": url.count("."),
        "num_slashes": url.count("/"),
        "num_hyphens": url.count("-"),
        "num_question_marks": url.count("?"),
        "num_ampersands": url.count("&"),
        "num_equals": url.count("="),
        "num_at_symbols": url.count("@"),
        "num_percent_encoded": len(_ENCODED_COMPONENT_RE.findall(url)),
        "has_punycode": int(hostname.startswith("xn--") or ".xn--" in hostname),
        "has_port": int(port is not None),
        "has_fragment": int(bool(parsed_url.fragment)),
        "has_credentials": int(parsed_url.username is not None or parsed_url.password is not None),
        "query_parameter_count": len(parse_qsl(parsed_url.query, keep_blank_values=True)),
        "suspicious_keyword_count": keyword_count,
    }
    if tuple(features) != FEATURE_NAMES:
        raise RuntimeError("The URL feature vector order does not match the model contract.")
    return features