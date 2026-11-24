"""
Feature Extraction Engine for URLShield AI
AI-Powered Malicious URL Detection System

Extracts 16 structural, lexical, and behavioral features from input URLs
reproducing the LegitPhish dataset feature engineering specification.
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse
from typing import Dict, Any, List, Union
import pandas as pd
import numpy as np

# Exact feature names in order expected by ML/DL models
FEATURE_NAMES = [
    "url_length",
    "has_ip_address",
    "dot_count",
    "https_flag",
    "url_entropy",
    "token_count",
    "subdomain_count",
    "query_param_count",
    "tld_length",
    "path_length",
    "has_hyphen_in_domain",
    "number_of_digits",
    "tld_popularity",
    "suspicious_file_extension",
    "domain_name_length",
    "percentage_numeric_chars",
]

POPULAR_TLDS = {"com", "org", "net", "edu", "gov"}

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".zip", ".bin", ".apk", ".cmd", ".js", ".bat",
    ".scr", ".vbs", ".msi", ".dll", ".ps1", ".hta", ".wsf",
    ".iso", ".tar", ".gz", ".7z", ".rar", ".sh"
)

IPV4_PATTERN = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
TOKEN_DELIMITER_PATTERN = re.compile(r"[/.\?=&]")


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy (base 2) of a string."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return float(entropy)


def extract_features_dict(url: str) -> Dict[str, Any]:
    """
    Extract 16 numerical and binary features from a URL string.
    Safely handles edge cases: empty strings, missing schemes, IP addresses,
    ports, fragments, and malformed inputs.
    Does NOT make any network requests.
    """
    if not isinstance(url, str) or not url.strip():
        # Fallback for empty or invalid input
        return {feat: 0.0 for feat in FEATURE_NAMES}

    url = url.strip()
    url_len = len(url)

    # 1. URL Length
    url_length = url_len

    # 2. IP Address check
    has_ip = 1 if IPV4_PATTERN.search(url) else 0

    # 3. Dot count
    dot_count = url.count(".")

    # 4. HTTPS flag
    https_flag = 1 if url.lower().startswith("https://") else 0

    # 5. Shannon entropy
    entropy = calculate_entropy(url)

    # 6. Token count: split by [/.\?=&]
    token_count = len(TOKEN_DELIMITER_PATTERN.split(url))

    # Parse URL components safely
    # If no scheme present, prepend temporary http:// for parser
    parse_target = url if ("://" in url or url.startswith("//")) else f"http://{url}"
    try:
        parsed = urlparse(parse_target)
    except Exception:
        parsed = urlparse("http://invalid.url")

    # Extract netloc/host and path
    netloc = parsed.netloc or ""
    # Strip port if present for domain analysis, but keep parts
    host_without_port = netloc.split(":")[0] if ":" in netloc else netloc
    path = parsed.path or ""
    query = parsed.query or ""

    # Subdomain, Domain and TLD extraction
    parts = host_without_port.split(".") if host_without_port else []

    if len(parts) >= 2:
        tld = parts[-1].lower()
        domain = parts[-2]
        subdomain_count = len(parts) - 2
        tld_length = len(tld)
        domain_name_length = len(domain)
        has_hyphen_in_domain = 1 if "-" in domain else 0
    elif len(parts) == 1:
        tld = parts[0].lower()
        domain = parts[0]
        subdomain_count = 0
        tld_length = len(tld)
        domain_name_length = len(domain)
        has_hyphen_in_domain = 1 if "-" in domain else 0
    else:
        tld = ""
        domain = ""
        subdomain_count = 0
        tld_length = 0
        domain_name_length = 0
        has_hyphen_in_domain = 0

    # 8. Query parameter count (dataset convention: 1 when no query params)
    if query:
        query_param_count = len(query.split("&"))
    else:
        query_param_count = 1

    # 10. Path length
    path_length = len(path)

    # 12. Number of digits
    num_digits = sum(c.isdigit() for c in url)

    # 13. TLD popularity
    tld_clean = tld.split(":")[0]  # ensure no port attached
    tld_popularity = 1 if tld_clean in POPULAR_TLDS else 0

    # 14. Suspicious file extension
    lower_url = url.lower()
    suspicious_ext = 0
    for ext in SUSPICIOUS_EXTENSIONS:
        if lower_url.endswith(ext) or f"{ext}?" in lower_url or f"{ext}/" in lower_url:
            suspicious_ext = 1
            break

    # 16. Percentage of numeric characters (0-100 scale as in dataset)
    pct_numeric = (num_digits / url_len * 100.0) if url_len > 0 else 0.0

    return {
        "url_length": int(url_length),
        "has_ip_address": int(has_ip),
        "dot_count": int(dot_count),
        "https_flag": int(https_flag),
        "url_entropy": float(entropy),
        "token_count": int(token_count),
        "subdomain_count": int(subdomain_count),
        "query_param_count": int(query_param_count),
        "tld_length": int(tld_length),
        "path_length": int(path_length),
        "has_hyphen_in_domain": int(has_hyphen_in_domain),
        "number_of_digits": int(num_digits),
        "tld_popularity": int(tld_popularity),
        "suspicious_file_extension": int(suspicious_ext),
        "domain_name_length": int(domain_name_length),
        "percentage_numeric_chars": float(pct_numeric),
    }


def extract_features_df(urls: Union[List[str], pd.Series, str]) -> pd.DataFrame:
    """
    Extract features for a list or Series of URLs and return a DataFrame
    with columns ordered exactly as expected by the trained models.
    """
    if isinstance(urls, str):
        urls = [urls]

    rows = [extract_features_dict(u) for u in urls]
    df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    return df


def explain_url_features(features: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Provide human-readable cybersecurity explanations for extracted features.
    """
    explanations = []

    if features.get("has_ip_address", 0) == 1:
        explanations.append({
            "feature": "Raw IP Address Host",
            "risk": "High Risk",
            "desc": "The URL uses a direct IP address rather than a registered domain name, a common phishing/C2 tactic."
        })

    if features.get("https_flag", 0) == 0:
        explanations.append({
            "feature": "Insecure HTTP Protocol",
            "risk": "Medium Risk",
            "desc": "The connection does not use TLS/HTTPS encryption, leaving traffic vulnerable to interception."
        })

    if features.get("suspicious_file_extension", 0) == 1:
        explanations.append({
            "feature": "Executable / Archive Extension",
            "risk": "Critical Risk",
            "desc": "The URL references direct executable or archive payloads (.exe, .zip, .bin, etc.)."
        })

    if features.get("has_hyphen_in_domain", 0) == 1:
        explanations.append({
            "feature": "Hyphenated Domain",
            "risk": "Medium Risk",
            "desc": "Hyphens in domain names are frequently used in typosquatting and brand impersonation attacks."
        })

    if features.get("subdomain_count", 0) >= 3:
        explanations.append({
            "feature": "Excessive Subdomains",
            "risk": "Medium Risk",
            "desc": f"Found {features.get('subdomain_count')} subdomains. Deep subdomain nesting often disguises phishing targets."
        })

    if features.get("url_entropy", 0) > 4.2:
        explanations.append({
            "feature": "High Character Entropy",
            "risk": "Medium Risk",
            "desc": f"Entropy of {features.get('url_entropy', 0):.2f} indicates high randomness/obfuscation, typical of DGA or obfuscated paths."
        })

    if features.get("percentage_numeric_chars", 0) > 20:
        explanations.append({
            "feature": "High Numeric Character Density",
            "risk": "Medium Risk",
            "desc": f"{features.get('percentage_numeric_chars', 0):.1f}% of characters are numbers, characteristic of randomized token generators."
        })

    if features.get("tld_popularity", 0) == 0:
        explanations.append({
            "feature": "Uncommon / High-Risk TLD",
            "risk": "Low-Medium Risk",
            "desc": "The Top-Level Domain is not among the top standard TLDs (.com, .org, .net, .edu, .gov)."
        })

    if not explanations:
        explanations.append({
            "feature": "Standard Lexical Profile",
            "risk": "Low Risk",
            "desc": "No anomalous lexical or structural red flags detected in the URL structure."
        })

    return explanations
