"""
Unit tests for trained models and pipelines.
"""

import os
import joblib
import pytest
import numpy as np
import pandas as pd

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
from src.feature_extraction import FEATURE_NAMES


def test_models_exist():
    expected_files = [
        "logistic_regression.pkl",
        "decision_tree.pkl",
        "mlp_classifier.pkl",
        "best_model.pkl",
        "preprocessing_pipeline.pkl"
    ]
    for fname in expected_files:
        path = os.path.join(MODELS_DIR, fname)
        assert os.path.exists(path), f"Expected model file {fname} to exist"
        assert os.path.getsize(path) > 100, f"Model file {fname} is suspiciously small"


def test_pipeline_transform():
    pipe = joblib.load(os.path.join(MODELS_DIR, "preprocessing_pipeline.pkl"))
    dummy_input = pd.DataFrame(np.ones((2, len(FEATURE_NAMES))), columns=FEATURE_NAMES)
    scaled = pipe.transform(dummy_input)
    assert scaled.shape == (2, len(FEATURE_NAMES))
    assert not np.isnan(scaled).any()


def test_models_prediction_shape():
    pipe = joblib.load(os.path.join(MODELS_DIR, "preprocessing_pipeline.pkl"))
    dummy_input = pd.DataFrame(np.ones((3, len(FEATURE_NAMES))), columns=FEATURE_NAMES)
    dummy_scaled = pipe.transform(dummy_input)

    for m_name in ["logistic_regression.pkl", "decision_tree.pkl", "mlp_classifier.pkl", "best_model.pkl"]:
        model = joblib.load(os.path.join(MODELS_DIR, m_name))
        inp = dummy_input if "tree" in m_name else dummy_scaled
        pred = model.predict(inp)
        assert len(pred) == 3
        assert set(pred).issubset({0, 1})
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(inp)
            assert probs.shape == (3, 2)
            assert np.allclose(probs.sum(axis=1), 1.0)
