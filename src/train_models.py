"""
Model Training Module for URLShield AI
AI-Powered Malicious URL Detection System

Trains:
1. Logistic Regression (Baseline Linear Classifier)
2. Decision Tree Classifier (Non-linear Tree Model)
3. MLPClassifier (Deep Neural Network with ReLU and Early Stopping)

Saves trained models, pipelines, and training logs to models/ and outputs/.
"""

import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier

from src.preprocessing import prepare_data
from src.feature_extraction import FEATURE_NAMES

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs", "reports")


def train_all_models() -> dict:
    """Train and persist all three models with execution metrics."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    print("[*] Preparing train/test splits and fitted standardizer...")
    X_train, X_test, y_train, y_test, pipeline = prepare_data()

    # Pre-scale features using training-fitted scaler for linear and neural models
    X_train_scaled = pipeline.transform(X_train)
    X_test_scaled = pipeline.transform(X_test)

    training_metadata = {}

    # 1. Logistic Regression
    print("\n" + "="*50)
    print("[*] Training Model 1: Logistic Regression...")
    lr = LogisticRegression(
        C=1.0,
        max_iter=1000,
        solver="lbfgs",
        random_state=42,
        class_weight="balanced"
    )
    t0 = time.time()
    lr.fit(X_train_scaled, y_train)
    lr_train_time = time.time() - t0
    print(f"[+] Logistic Regression trained in {lr_train_time:.2f} seconds.")

    # Save model
    lr_path = os.path.join(MODELS_DIR, "logistic_regression.pkl")
    joblib.dump(lr, lr_path)
    training_metadata["logistic_regression"] = {"train_time": lr_train_time}

    # 2. Decision Tree Classifier
    print("\n" + "="*50)
    print("[*] Training Model 2: Decision Tree Classifier...")
    dt = DecisionTreeClassifier(
        max_depth=18,
        min_samples_split=10,
        min_samples_leaf=4,
        criterion="gini",
        random_state=42,
        class_weight="balanced"
    )
    t0 = time.time()
    # Decision trees are invariant to monotonic feature scaling, using raw X_train
    dt.fit(X_train, y_train)
    dt_train_time = time.time() - t0
    print(f"[+] Decision Tree trained in {dt_train_time:.2f} seconds.")

    # Save model
    dt_path = os.path.join(MODELS_DIR, "decision_tree.pkl")
    joblib.dump(dt, dt_path)
    training_metadata["decision_tree"] = {"train_time": dt_train_time}

    # 3. MLP Classifier (Neural Network)
    print("\n" + "="*50)
    print("[*] Training Model 3: MLP Deep Neural Network...")
    mlp = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation="relu",
        solver="adam",
        alpha=0.0001,
        batch_size=256,
        learning_rate="adaptive",
        learning_rate_init=0.001,
        max_iter=150,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=10,
        random_state=42,
        verbose=False
    )
    t0 = time.time()
    mlp.fit(X_train_scaled, y_train)
    mlp_train_time = time.time() - t0
    print(f"[+] MLP Classifier trained in {mlp_train_time:.2f} seconds over {mlp.n_iter_} iterations.")

    # Save model
    mlp_path = os.path.join(MODELS_DIR, "mlp_classifier.pkl")
    joblib.dump(mlp, mlp_path)
    training_metadata["mlp_classifier"] = {
        "train_time": mlp_train_time,
        "n_iter": int(mlp.n_iter_),
        "loss_curve": [float(x) for x in mlp.loss_curve_]
    }

    # Save training metadata
    meta_path = os.path.join(REPORTS_DIR, "training_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(training_metadata, f, indent=2)
    print(f"[+] Saved training metadata to: {meta_path}")

    return {
        "X_train": X_train,
        "X_test": X_test,
        "X_train_scaled": X_train_scaled,
        "X_test_scaled": X_test_scaled,
        "y_train": y_train,
        "y_test": y_test,
        "pipeline": pipeline,
        "lr": lr,
        "dt": dt,
        "mlp": mlp,
        "training_metadata": training_metadata
    }


if __name__ == "__main__":
    train_all_models()
