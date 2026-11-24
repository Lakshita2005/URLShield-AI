"""
Data Preprocessing Pipeline for URLShield AI
AI-Powered Malicious URL Detection System

Normalizes labels, validates features, removes duplicates/missing values,
and prepares stratified train-test splits with scikit-learn standard scaler pipelines.
"""

import os
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from typing import Tuple, Dict, Any

from src.feature_extraction import FEATURE_NAMES

PROCESSED_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "processed")
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
RAW_DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw", "url_features_extracted1.csv")
PROCESSED_CSV_PATH = os.path.join(PROCESSED_DATA_DIR, "legitphish_processed.csv")
PIPELINE_PATH = os.path.join(MODELS_DIR, "preprocessing_pipeline.pkl")


def clean_and_normalize_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean dataset and normalize target labels.
    
    Original LegitPhish mapping:
      - 0.0 = Phishing
      - 1.0 = Legitimate
      
    Normalized URLShield AI mapping:
      - 0 = Legitimate / Benign
      - 1 = Malicious / Phishing
    """
    print(f"[*] Starting dataset cleaning. Initial shape: {df.shape}")
    
    # 1. Identify label column
    label_col = [c for c in df.columns if "class" in c.lower() or "label" in c.lower()][0]
    
    # 2. Drop missing rows in label or features
    df_clean = df.dropna(subset=[label_col]).copy()
    
    # 3. Drop duplicate URLs if present
    initial_rows = len(df_clean)
    df_clean = df_clean.drop_duplicates(subset=["URL"], keep="first")
    print(f"[*] Dropped {initial_rows - len(df_clean)} duplicate URL records.")
    
    # 4. Target Label Normalization: 0 -> 1 (Malicious), 1 -> 0 (Legitimate)
    df_clean["normalized_label"] = (1 - df_clean[label_col].astype(int)).astype(int)
    
    # 5. Verify feature columns
    for col in FEATURE_NAMES:
        if col not in df_clean.columns:
            raise ValueError(f"Missing required feature column: {col}")
        # Coerce numeric values and fill any rare NaNs with median
        df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(0)
    
    # Retain clean dataframe with URL, features, original ClassLabel, and normalized_label
    cols_to_keep = ["URL"] + FEATURE_NAMES + ["normalized_label"]
    df_processed = df_clean[cols_to_keep].reset_index(drop=True)
    
    print(f"[+] Dataset cleaned successfully. Final shape: {df_processed.shape}")
    print("[*] Normalized class distribution:")
    print(df_processed["normalized_label"].value_counts())
    print("    (0 = Legitimate / Benign, 1 = Malicious / Phishing)")
    
    return df_processed


def prepare_data(
    test_size: float = 0.2, random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, np.ndarray, np.ndarray, Pipeline]:
    """
    Load raw data, clean, normalize, perform stratified 80:20 split,
    fit StandardScaler pipeline on training data ONLY, and save pipeline.
    """
    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)

    if os.path.exists(PROCESSED_CSV_PATH):
        print(f"[*] Loading pre-existing processed dataset: {PROCESSED_CSV_PATH}")
        df = pd.read_csv(PROCESSED_CSV_PATH)
    else:
        print(f"[*] Reading raw dataset from: {RAW_DATA_PATH}")
        df_raw = pd.read_csv(RAW_DATA_PATH)
        df = clean_and_normalize_dataset(df_raw)
        df.to_csv(PROCESSED_CSV_PATH, index=False)
        print(f"[+] Saved processed dataset to: {PROCESSED_CSV_PATH}")

    X = df[FEATURE_NAMES]
    y = df["normalized_label"].values

    # Stratified 80:20 train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"[+] Stratified Train-Test Split (test_size={test_size}, random_state={random_state}):")
    print(f"    X_train shape: {X_train.shape}, y_train: {np.bincount(y_train)}")
    print(f"    X_test shape:  {X_test.shape},  y_test:  {np.bincount(y_test)}")

    # Fit feature scaling pipeline strictly on training data
    pipeline = Pipeline([
        ("scaler", StandardScaler())
    ])
    pipeline.fit(X_train)

    joblib.dump(pipeline, PIPELINE_PATH)
    print(f"[+] Saved preprocessing pipeline to: {PIPELINE_PATH}")

    return X_train, X_test, y_train, y_test, pipeline


if __name__ == "__main__":
    X_train, X_test, y_train, y_test, pipe = prepare_data()
    print("[*] Preprocessing completed successfully.")
