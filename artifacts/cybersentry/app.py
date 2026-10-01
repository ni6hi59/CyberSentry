"""CyberSentry: AI/ML-assisted URL investigation dashboard."""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import parse_qsl, urlsplit

from flask import Flask, jsonify, render_template, request

from ml.ml_predict import predict

app = Flask(__name__)

# -------------------------------------------------------------------
# CyberSentry configuration
# -------------------------------------------------------------------

MAX_URL_LENGTH = 4096

SUSPICIOUS_KEYWORDS = {
    "account": "Account-related language can be used to pressure someone into signing in.",
    "bank": "Banking language can be used to imitate a financial institution.",
    "bonus": "Bonus or reward language can create urgency.",
    "confirm": "Confirmation language can make a link feel like an urgent task.",
    "crypto": "Cryptocurrency language can be used in scam campaigns.",
    "free": "Free offers can be used as bait on deceptive landing pages.",
    "invoice": "Invoice language can imitate a payment request.",
    "login": "Login language may target account credentials.",
    "payment": "Payment language can imitate billing or checkout pages.",
    "password": "Password language may target account credentials.",
    "secure": "Security language can make a suspicious link appear trustworthy.",
    "urgent": "Urgent language is a common social-engineering tactic.",
    "update": "Update language can pressure someone into visiting quickly.",
    "verify": "Verification language may target credentials or personal data.",
    "wallet": "Wallet language can target cryptocurrency accounts.",
}

URL_SCHEME_RE = re.compile(
    r"^[a-z][a-z0-9+.-]*://",
    re.IGNORECASE,
)

ENCODED_COMPONENT_RE = re.compile(
    r"%[0-9a-f]{2}",
    re.IGNORECASE,
)


# -------------------------------------------------------------------
# Indicator helper
# -------------------------------------------------------------------

def _indicator(
    indicator_id: str,
    title: str,
    explanation: str,
    evidence: str,
    severity: str = "medium",
) -> dict[str, str]:
    return {
        "id": indicator_id,
        "title": title,
        "explanation": explanation,
        "evidence": evidence,
        "severity": severity,
    }


# -------------------------------------------------------------------
# URL normalization
# -------------------------------------------------------------------

def normalize_url(raw_url: str) -> tuple[str, object]:
    """
    Normalize and validate URL text.

    IMPORTANT:
    This function never opens, resolves, fetches, or connects
    to the submitted URL.
    """

    if not isinstance(raw_url, str):
        raise ValueError("Enter a URL to analyze.")

    value = raw_url.strip()

    if not value:
        raise ValueError("Enter a URL to analyze.")

    if len(value) > MAX_URL_LENGTH:
        raise ValueError(
            f"Please enter a URL shorter than {MAX_URL_LENGTH:,} characters."
        )

    if any(character.isspace() for character in value):
        raise ValueError(
            "URLs cannot contain spaces. Remove spaces and try again."
        )

    if value.startswith("//"):
        normalized = f"https:{value}"
    elif URL_SCHEME_RE.match(value):
        normalized = value
    else:
        normalized = f"https://{value}"

    try:
        parsed = urlsplit(normalized)
    except ValueError as error:
        raise ValueError(
            "Enter a valid HTTP or HTTPS URL."
        ) from error

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(
            "Only HTTP and HTTPS URLs can be analyzed."
        )

    if not parsed.netloc or not parsed.hostname:
        raise ValueError(
            "Enter a URL with a hostname, such as example.com."
        )

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(
            "The URL contains an invalid port number."
        ) from error

    if port is not None and not 1 <= port <= 65535:
        raise ValueError(
            "The URL port must be between 1 and 65,535."
        )

    return normalized, parsed


# -------------------------------------------------------------------
# CyberSentry ML feature extractor
# -------------------------------------------------------------------

def extract_ml_features(
    normalized: str,
    parsed,
) -> dict[str, int | float]:
    """
    Extract the exact 23 features used during ML training.

    The feature names and meanings must remain synchronized with
    the Google Colab training pipeline.
    """

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # IP detection
    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    # Subdomain count
    subdomain_parts = hostname.split(".") if hostname else []

    num_subdomains = max(
        len(subdomain_parts) - 2,
        0,
    )

    # Query parameters
    query_parameter_count = (
        len(
            [
                item
                for item in query.split("&")
                if item
            ]
        )
        if query
        else 0
    )

    # Suspicious keywords
    lowered = normalized.lower()

    suspicious_keyword_count = sum(
        1
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(
            rf"(?<![a-z]){re.escape(keyword)}(?![a-z])",
            lowered,
        )
    )

    # Port
    try:
        has_port = int(parsed.port is not None)
    except ValueError:
        has_port = 0

    return {
        "url_length": len(normalized),

        "hostname_length": len(hostname),

        "path_length": len(path),

        "query_length": len(query),

        "is_https": int(
            parsed.scheme.lower() == "https"
        ),

        "is_ip": is_ip,

        "num_subdomains": num_subdomains,

        "num_digits": sum(
            character.isdigit()
            for character in normalized
        ),

        "num_letters": sum(
            character.isalpha()
            for character in normalized
        ),

        "num_dots": normalized.count("."),

        "num_slashes": normalized.count("/"),

        "num_hyphens": normalized.count("-"),

        "num_question_marks": normalized.count("?"),

        "num_ampersands": normalized.count("&"),

        "num_equals": normalized.count("="),

        "num_at_symbols": normalized.count("@"),

        "num_percent_encoded": len(
            re.findall(
                r"%[0-9a-fA-F]{2}",
                normalized,
            )
        ),

        "has_punycode": int(
            hostname.startswith("xn--")
            or ".xn--" in hostname
        ),

        "has_port": has_port,

        "has_fragment": int(
            bool(parsed.fragment)
        ),

        "has_credentials": int(
            bool(
                parsed.username
                or parsed.password
            )
        ),

        "query_parameter_count": query_parameter_count,

        "suspicious_keyword_count":
            suspicious_keyword_count,
    }


# -------------------------------------------------------------------
# Rule-based risk calculation
# -------------------------------------------------------------------

def calculate_rule_risk(
    indicators: list[dict[str, str]],
    features: dict,
) -> tuple[int, str]:
    """
    Calculate the independent rule-based risk score.

    This is intentionally separate from the ML prediction.
    """

    score = 0

    severity_points = {
        "low": 5,
        "medium": 10,
        "high": 18,
    }

    for indicator in indicators:
        score += severity_points.get(
            indicator["severity"],
            10,
        )

    if features["is_https"] == 0:
        score += 8

    if features["is_ip"]:
        score += 12

    if features["num_subdomains"] >= 3:
        score += 8

    if features["num_digits"] >= 8:
        score += 5

    if features["url_length"] >= 150:
        score += 8

    score = min(
        int(score),
        100,
    )

    if score >= 70:
        level = "High Risk"
    elif score >= 40:
        level = "Medium Risk"
    elif score >= 15:
        level = "Low Risk"
    else:
        level = "Minimal Risk"

    return score, level


# -------------------------------------------------------------------
# Combined risk
# -------------------------------------------------------------------

def calculate_combined_risk(
    rule_score: int,
    ml_result: dict,
) -> tuple[int, str]:
    """
    Combine the independent rule score with the ML phishing probability.

    ML contribution: 60%
    Rule contribution: 40%

    If ML is unavailable, the rule score remains the result.
    """

    if not ml_result.get("available"):
        score = rule_score
    else:
        ml_score = float(
            ml_result.get(
                "phishing_probability",
                0,
            )
        )

        score = round(
            (ml_score * 0.60)
            + (rule_score * 0.40)
        )

    score = max(
        0,
        min(
            int(score),
            100,
        ),
    )

    if score >= 70:
        level = "High Risk"
    elif score >= 40:
        level = "Medium Risk"
    elif score >= 15:
        level = "Low Risk"
    else:
        level = "Minimal Risk"

    return score, level


# -------------------------------------------------------------------
# URL analysis
# -------------------------------------------------------------------

def analyze_url(raw_url: str) -> dict:
    """
    Analyze URL text only.

    CyberSentry NEVER visits, resolves, downloads, or connects
    to the submitted URL.
    """

    normalized, parsed = normalize_url(
        raw_url
    )

    indicators: list[dict[str, str]] = []

    hostname = parsed.hostname or ""

    lowered = normalized.lower()

    encoded_component_count = len(
        ENCODED_COMPONENT_RE.findall(
            normalized
        )
    )

    query_parameter_count = (
        len(
            parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )
        )
        if parsed.query
        else 0
    )

    # ---------------------------------------------------------------
    # IP hostname
    # ---------------------------------------------------------------

    try:
        ipaddress.ip_address(hostname)
        hostname_is_ip = True
    except ValueError:
        hostname_is_ip = False

    if hostname_is_ip:
        indicators.append(
            _indicator(
                "ip-hostname",
                "IP-address hostname",
                "A direct IP address can make website ownership harder to verify.",
                hostname,
                "high",
            )
        )

    # ---------------------------------------------------------------
    # Long URL
    # ---------------------------------------------------------------

    if len(normalized) > 120:
        indicators.append(
            _indicator(
                "long-url",
                "Unusually long URL",
                "Long URLs can hide important information among parameters or encoded characters.",
                f"{len(normalized)} characters detected",
            )
        )

    # ---------------------------------------------------------------
    # @ symbol
    # ---------------------------------------------------------------

    if "@" in normalized:
        indicators.append(
            _indicator(
                "at-symbol",
                "At symbol in URL",
                "An @ symbol can make text before it appear like the destination while the browser uses the hostname after it.",
                "@ symbol present",
                "high",
            )
        )

    # ---------------------------------------------------------------
    # Punycode
    # ---------------------------------------------------------------

    if (
        hostname.startswith("xn--")
        or ".xn--" in hostname
    ):
        indicators.append(
            _indicator(
                "punycode",
                "Punycode hostname",
                "Punycode can represent lookalike internationalized characters.",
                hostname,
                "high",
            )
        )

    # ---------------------------------------------------------------
    # Nested subdomains
    # ---------------------------------------------------------------

    if hostname.count(".") >= 4:
        indicators.append(
            _indicator(
                "nested-subdomains",
                "Many nested subdomains",
                "Several subdomain levels can make the registered domain harder to identify.",
                f"{hostname.count('.') + 1} hostname segments",
            )
        )

    # ---------------------------------------------------------------
    # Non-standard port
    # ---------------------------------------------------------------

    port = parsed.port

    if port is not None and port not in (
        80,
        443,
    ):
        indicators.append(
            _indicator(
                "nonstandard-port",
                "Non-standard port",
                "A port outside the usual web ports is uncommon for ordinary public links.",
                f"Port {port}",
            )
        )

    # ---------------------------------------------------------------
    # Suspicious keywords
    # ---------------------------------------------------------------

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(
            rf"(?<![a-z]){re.escape(keyword)}(?![a-z])",
            lowered,
        )
    ]

    if matched_keywords:
        keyword_list = ", ".join(
            matched_keywords[:4]
        )

        if len(matched_keywords) > 4:
            keyword_list += (
                f" +{len(matched_keywords) - 4} more"
            )

        explanation = " ".join(
            SUSPICIOUS_KEYWORDS[keyword]
            for keyword in matched_keywords[:2]
        )

        indicators.append(
            _indicator(
                "suspicious-keywords",
                "Suspicious keywords",
                explanation,
                keyword_list,
                "medium",
            )
        )

    # ---------------------------------------------------------------
    # Encoded components
    # ---------------------------------------------------------------

    if encoded_component_count >= 3:
        indicators.append(
            _indicator(
                "encoded-components",
                "Multiple encoded components",
                "Several percent-encoded values can make the visible URL harder to inspect.",
                f"{encoded_component_count} percent-encoded values",
                "medium",
            )
        )

    # ---------------------------------------------------------------
    # Many query parameters
    # ---------------------------------------------------------------

    if query_parameter_count >= 6:
        indicators.append(
            _indicator(
                "many-query-parameters",
                "Many query parameters",
                "A large parameter string can obscure information in the visible link.",
                f"{query_parameter_count} query parameters",
                "medium",
            )
        )

    # ---------------------------------------------------------------
    # ML features
    # ---------------------------------------------------------------

    ml_features = extract_ml_features(
        normalized,
        parsed,
    )

    # ---------------------------------------------------------------
    # Rule-based risk
    # ---------------------------------------------------------------

    rule_score, rule_level = calculate_rule_risk(
        indicators,
        ml_features,
    )

    # ---------------------------------------------------------------
    # Machine learning prediction
    # ---------------------------------------------------------------

    ml_result = predict(
        ml_features
    )

    # ---------------------------------------------------------------
    # Combined risk
    # ---------------------------------------------------------------

    combined_score, combined_level = (
        calculate_combined_risk(
            rule_score,
            ml_result,
        )
    )

    # ---------------------------------------------------------------
    # Final response
    # ---------------------------------------------------------------

    return {
        "url": normalized,

        "hostname": (
            hostname
            or "Unable to identify hostname"
        ),

        "category": (
            "Needs Review"
            if indicators
            else "No Obvious Indicators"
        ),

        "indicator_count": len(
            indicators
        ),

        "indicators": indicators,

        # Risk information
        "risk_score": combined_score,
        "risk_level": combined_level,

        "rule_risk_score": rule_score,
        "rule_risk_level": rule_level,

        # ML information
        "ml_available": ml_result.get(
            "available",
            False,
        ),

        "ml_prediction": ml_result.get(
            "prediction_label",
            "Unavailable",
        ),

        "ml_phishing_probability": ml_result.get(
            "phishing_probability"
        ),

        "ml_legitimate_probability": ml_result.get(
            "legitimate_probability"
        ),

        "ml_status": ml_result.get(
            "status",
            "ML model unavailable",
        ),

        "ml_error": ml_result.get(
            "error"
        ),

        # 23 model features
        "features": ml_features,
        "ml_features": ml_features,

        # Human-readable URL information
        "url_features": {
            "length": len(normalized),
            "scheme": parsed.scheme.lower(),
            "hostname": hostname,
            "hostname_is_ip": hostname_is_ip,
            "port": port,
            "path": parsed.path or "/",
            "query_parameter_count":
                query_parameter_count,
            "encoded_component_count":
                encoded_component_count,
            "has_fragment":
                bool(parsed.fragment),
            "has_credentials":
                (
                    parsed.username is not None
                    or parsed.password is not None
                ),
        },

        "analysis_engine": (
            "Rule-Based + Random Forest ML"
            if ml_result.get("available")
            else "Rule-Based URL Analyzer"
        ),

        "note": (
            "CyberSentry analyzes URL text and does not "
            "visit, resolve, download, or connect to the "
            "submitted destination. ML results reflect "
            "the trained model and its dataset."
        ),
    }


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------

@app.get("/")
def index():
    return render_template(
        "index.html"
    )


@app.post("/analyze")
def analyze():
    payload = (
        request.get_json(
            silent=True
        )
        or {}
    )

    raw_url = payload.get(
        "url",
        "",
    )

    try:
        result = analyze_url(
            raw_url
        )

        return jsonify(
            result
        )

    except ValueError as error:
        return jsonify(
            {
                "error": str(error)
            }
        ), 400

    except Exception as error:
        # Do not expose internal stack traces to users.
        app.logger.exception(
            "Unexpected analysis error"
        )

        return jsonify(
            {
                "error": (
                    "CyberSentry could not complete "
                    "the analysis."
                )
            }
        ), 500


# -------------------------------------------------------------------
# Application entry point
# -------------------------------------------------------------------

if __name__ == "__main__":
    port = int(
        os.environ.get(
            "PORT",
            "5000",
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=(
            os.environ.get(
                "FLASK_DEBUG"
            )
            == "1"
        ),
        )
