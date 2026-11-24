"""
Unit Tests for URL Feature Extraction Engine
"""

import pytest
import pandas as pd
import numpy as np
from src.feature_extraction import (
    extract_features_dict,
    extract_features_df,
    calculate_entropy,
    explain_url_features,
    FEATURE_NAMES
)


def test_feature_names_order():
    """Verify exact count and ordering of 16 features."""
    assert len(FEATURE_NAMES) == 16
    expected_order = [
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
    assert FEATURE_NAMES == expected_order


def test_legitimate_url_features():
    """Test feature extraction on known legitimate URL."""
    url = "https://www.google.com/search?q=cybersecurity"
    feats = extract_features_dict(url)
    assert feats["https_flag"] == 1
    assert feats["has_ip_address"] == 0
    assert feats["tld_popularity"] == 1  # .com
    assert feats["suspicious_file_extension"] == 0
    assert feats["query_param_count"] == 1
    assert feats["url_length"] == len(url)
    assert feats["dot_count"] == 2


def test_phishing_ip_url():
    """Test feature extraction on an IP-based malware URL."""
    url = "http://192.168.1.100:8080/payload.exe"
    feats = extract_features_dict(url)
    assert feats["has_ip_address"] == 1
    assert feats["https_flag"] == 0
    assert feats["suspicious_file_extension"] == 1
    assert feats["number_of_digits"] >= 14


def test_hyphenated_phishing_domain():
    """Test feature extraction on hyphenated impersonation domain."""
    url = "https://login-apple-security-check.com/verify"
    feats = extract_features_dict(url)
    assert feats["has_hyphen_in_domain"] == 1
    assert feats["tld_popularity"] == 1
    assert feats["https_flag"] == 1


def test_edge_cases():
    """Verify handling of empty strings, missing schemes, and invalid inputs."""
    empty_feats = extract_features_dict("")
    assert len(empty_feats) == 16
    assert empty_feats["url_length"] == 0

    no_scheme_url = "paypal-security-update.com/login"
    no_scheme_feats = extract_features_dict(no_scheme_url)
    assert no_scheme_feats["has_hyphen_in_domain"] == 1
    assert no_scheme_feats["domain_name_length"] > 0

    none_feats = extract_features_dict(None)
    assert len(none_feats) == 16
    assert none_feats["url_length"] == 0


def test_extract_features_df():
    """Verify DataFrame batch output has proper schema and types."""
    urls = [
        "https://example.com/index.html",
        "http://59.183.116.177:55504/Mozi.m",
        "https://sub.domain.sample.org/path?a=1&b=2"
    ]
    df = extract_features_df(urls)
    assert isinstance(df, pd.DataFrame)
    assert df.shape == (3, 16)
    assert list(df.columns) == FEATURE_NAMES
    assert df["has_ip_address"].iloc[1] == 1
    assert df["query_param_count"].iloc[2] == 2


def test_entropy_computation():
    """Verify Shannon entropy calculation."""
    # Single repeated char has zero entropy
    assert calculate_entropy("aaaaaaa") == 0.0
    # Two equally distributed chars have entropy 1.0
    assert abs(calculate_entropy("abababab") - 1.0) < 1e-6
    # Empty string has zero entropy
    assert calculate_entropy("") == 0.0


def test_explain_features():
    """Verify cybersecurity explainability output."""
    feats = {
        "has_ip_address": 1,
        "https_flag": 0,
        "suspicious_file_extension": 1,
        "has_hyphen_in_domain": 1,
        "subdomain_count": 4,
        "url_entropy": 4.5,
        "percentage_numeric_chars": 25.0,
        "tld_popularity": 0
    }
    reasons = explain_url_features(feats)
    assert len(reasons) >= 5
    risks = [r["risk"] for r in reasons]
    assert "High Risk" in risks or "Critical Risk" in risks
