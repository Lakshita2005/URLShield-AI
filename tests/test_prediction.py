"""
Unit tests for URLShield prediction engine.
"""

import pytest
import pandas as pd
from src.prediction import URLShieldPredictor, get_predictor


def test_single_url_prediction():
    predictor = get_predictor("best")
    result = predictor.predict_url("https://www.wikipedia.org/")
    assert "predicted_class" in result
    assert "malicious_probability" in result
    assert "risk_level" in result
    assert 0.0 <= result["malicious_probability"] <= 1.0
    assert result["is_malicious"] is False or result["is_malicious"] is True


def test_malicious_ip_prediction():
    predictor = get_predictor("best")
    # High-risk URL with raw IP and .exe
    result = predictor.predict_url("http://192.168.1.50:8080/setup.exe")
    assert result["malicious_probability"] > 0.5
    assert result["is_malicious"] is True
    assert result["features"]["has_ip_address"] == 1
    assert result["features"]["suspicious_file_extension"] == 1


def test_threshold_adjustment():
    predictor = get_predictor("best")
    url = "http://example-test-site.org/login"
    
    # At high threshold, harder to be malicious
    res_high = predictor.predict_url(url, threshold=0.95)
    # At low threshold, easier to be malicious
    res_low = predictor.predict_url(url, threshold=0.05)
    
    assert res_high["threshold_applied"] == 0.95
    assert res_low["threshold_applied"] == 0.05
    if res_high["is_malicious"]:
        assert res_low["is_malicious"] is True


def test_model_switching():
    predictor = get_predictor("logistic_regression")
    assert predictor.model_name == "logistic_regression"
    res1 = predictor.predict_url("https://google.com")
    assert res1["model_used"] == "logistic_regression"

    predictor.set_model("decision_tree")
    res2 = predictor.predict_url("https://google.com")
    assert res2["model_used"] == "decision_tree"


def test_batch_prediction():
    predictor = get_predictor("best")
    urls = [
        "https://www.github.com",
        "http://59.183.116.177:55504/Mozi.m",
        "https://www.python.org"
    ]
    df_res = predictor.predict_batch(urls)
    assert isinstance(df_res, pd.DataFrame)
    assert len(df_res) == 3
    assert "Prediction" in df_res.columns
    assert "Risk_Tier" in df_res.columns
    assert "Malicious_Score" in df_res.columns
