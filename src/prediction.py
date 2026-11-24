"""
Prediction Engine for URLShield AI
AI-Powered Malicious URL Detection System

Provides high-level prediction services for single URLs and batch CSV uploads.
Safely extracts features, standardizes inputs where required by model type,
computes risk probabilities, and assigns cyber risk tiers.
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Union, Optional

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.feature_extraction import (
    extract_features_dict,
    extract_features_df,
    explain_url_features,
    FEATURE_NAMES
)

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")


class URLShieldPredictor:
    """Predictor class encapsulating models and pipelines."""

    def __init__(self, model_name: str = "best"):
        self.model_name = model_name
        self.pipeline = self._load_pipeline()
        self.model = self._load_model(model_name)

    def _load_pipeline(self):
        pipe_path = os.path.join(MODELS_DIR, "preprocessing_pipeline.pkl")
        if not os.path.exists(pipe_path):
            raise FileNotFoundError(f"Preprocessing pipeline not found at {pipe_path}. Run training first.")
        return joblib.load(pipe_path)

    def _load_model(self, model_name: str):
        mapping = {
            "best": "best_model.pkl",
            "logistic_regression": "logistic_regression.pkl",
            "decision_tree": "decision_tree.pkl",
            "mlp_classifier": "mlp_classifier.pkl",
        }
        filename = mapping.get(model_name.lower(), "best_model.pkl")
        model_path = os.path.join(MODELS_DIR, filename)
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at {model_path}. Run training first.")
        return joblib.load(model_path)

    def set_model(self, model_name: str):
        """Switch active model dynamically."""
        self.model_name = model_name
        self.model = self._load_model(model_name)

    def predict_url(self, url: str, threshold: float = 0.5) -> Dict[str, Any]:
        """
        Analyze a single URL string and return detailed risk assessment.
        """
        features_dict = extract_features_dict(url)
        features_df = pd.DataFrame([features_dict], columns=FEATURE_NAMES)

        # Scale features if model requires scaling (Logistic Regression and MLP)
        is_tree = "tree" in self.model.__class__.__name__.lower()
        if is_tree:
            X_input = features_df
        else:
            X_input = self.pipeline.transform(features_df)

        # Predict probability
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_input)[0]
            malicious_prob = float(probs[1])
            legitimate_prob = float(probs[0])
        else:
            pred = self.model.predict(X_input)[0]
            malicious_prob = 1.0 if pred == 1 else 0.0
            legitimate_prob = 1.0 - malicious_prob

        # Apply configurable classification threshold
        is_malicious = bool(malicious_prob >= threshold)
        pred_label = 1 if is_malicious else 0
        pred_class = "Potentially Malicious" if is_malicious else "Likely Legitimate"

        # Risk Classification
        if malicious_prob < 0.35:
            risk_level = "Low Risk"
            risk_color = "#00e676"  # Green
        elif malicious_prob < 0.65:
            risk_level = "Moderate Risk / Review"
            risk_color = "#ffeb3b"  # Yellow
        elif malicious_prob < 0.85:
            risk_level = "High Risk"
            risk_color = "#ff9100"  # Orange
        else:
            risk_level = "Critical Threat"
            risk_color = "#ff1744"  # Red

        explanations = explain_url_features(features_dict)

        return {
            "url": url,
            "predicted_class": pred_class,
            "is_malicious": is_malicious,
            "predicted_label": pred_label,
            "malicious_probability": malicious_prob,
            "legitimate_probability": legitimate_prob,
            "confidence": max(malicious_prob, legitimate_prob),
            "risk_level": risk_level,
            "risk_color": risk_color,
            "threshold_applied": threshold,
            "features": features_dict,
            "explanations": explanations,
            "model_used": self.model_name
        }

    def predict_batch(self, urls: List[str], threshold: float = 0.5) -> pd.DataFrame:
        """
        Batch prediction for multiple URLs (e.g. from CSV upload).
        """
        features_df = extract_features_df(urls)

        is_tree = "tree" in self.model.__class__.__name__.lower()
        if is_tree:
            X_input = features_df
        else:
            X_input = self.pipeline.transform(features_df)

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_input)[:, 1]
        else:
            preds = self.model.predict(X_input)
            probs = preds.astype(float)

        results = []
        for url, prob, (_, feat_row) in zip(urls, probs, features_df.iterrows()):
            is_mal = bool(prob >= threshold)
            if prob < 0.35:
                risk = "Low Risk"
            elif prob < 0.65:
                risk = "Moderate Risk"
            elif prob < 0.85:
                risk = "High Risk"
            else:
                risk = "Critical Threat"

            results.append({
                "URL": url,
                "Prediction": "Malicious" if is_mal else "Legitimate",
                "Malicious_Score": round(prob, 4),
                "Risk_Tier": risk,
                "URL_Length": int(feat_row["url_length"]),
                "Has_IP": int(feat_row["has_ip_address"]),
                "HTTPS": int(feat_row["https_flag"]),
                "Entropy": round(feat_row["url_entropy"], 2),
                "Suspicious_Ext": int(feat_row["suspicious_file_extension"])
            })

        return pd.DataFrame(results)


# Default global predictor singleton
_global_predictor: Optional[URLShieldPredictor] = None


def get_predictor(model_name: str = "best") -> URLShieldPredictor:
    """Retrieve or instantiate predictor instance."""
    global _global_predictor
    if _global_predictor is None or _global_predictor.model_name != model_name:
        _global_predictor = URLShieldPredictor(model_name=model_name)
    return _global_predictor
