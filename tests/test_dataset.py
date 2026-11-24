"""
Unit tests for dataset acquisition and preprocessing.
"""

import os
import pytest
import pandas as pd
import numpy as np

PROCESSED_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "processed", "legitphish_processed.csv")
RAW_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw", "url_features_extracted1.csv")


def test_raw_dataset_exists():
    assert os.path.exists(RAW_PATH), "Raw dataset file must exist"
    assert os.path.getsize(RAW_PATH) > 1000000, "Raw dataset must not be empty"


def test_processed_dataset_exists():
    assert os.path.exists(PROCESSED_PATH), "Processed dataset file must exist"
    df = pd.read_csv(PROCESSED_PATH)
    assert len(df) > 90000, "Processed dataset must contain >90,000 clean URLs"


def test_label_normalization():
    df = pd.read_csv(PROCESSED_PATH)
    assert "normalized_label" in df.columns, "Must have normalized_label"
    unique_labels = set(df["normalized_label"].unique())
    assert unique_labels == {0, 1}, "Labels must be binary 0 (Legitimate) and 1 (Malicious)"
    
    # Check that malicious URLs outnumber legitimate in LegitPhish
    mal_count = (df["normalized_label"] == 1).sum()
    leg_count = (df["normalized_label"] == 0).sum()
    assert mal_count > leg_count, "LegitPhish contains more phishing URLs than legitimate"


def test_no_null_features():
    df = pd.read_csv(PROCESSED_PATH)
    from src.feature_extraction import FEATURE_NAMES
    assert df[FEATURE_NAMES].isna().sum().sum() == 0, "No null features allowed in processed dataset"
