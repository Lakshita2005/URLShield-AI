"""
Model Evaluation and Explainability Module for URLShield AI
AI-Powered Malicious URL Detection System

Computes performance matrices, confusion matrices, ROC/PR curves,
feature importance, and saves the best model to models/best_model.pkl.
"""

import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, classification_report, roc_curve, precision_recall_curve, auc
)
from sklearn.inspection import permutation_importance

from src.feature_extraction import FEATURE_NAMES

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
OUTPUTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs")
CM_DIR = os.path.join(OUTPUTS_DIR, "confusion_matrices")
REPORTS_DIR = os.path.join(OUTPUTS_DIR, "reports")
COMPARISON_DIR = os.path.join(OUTPUTS_DIR, "model_comparison")
PROCESSED_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "processed", "legitphish_processed.csv")


def set_cyber_style():
    """Apply cybersecurity dark theme to matplotlib."""
    plt.style.use("dark_background")
    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["axes.edgecolor"] = "#00f0ff"
    plt.rcParams["axes.linewidth"] = 0.8
    plt.rcParams["grid.color"] = "#223344"
    plt.rcParams["grid.linestyle"] = "--"
    plt.rcParams["grid.alpha"] = 0.5


def evaluate_all():
    """Run full evaluation suite on all models."""
    os.makedirs(CM_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(COMPARISON_DIR, exist_ok=True)
    set_cyber_style()

    print("[*] Loading test data and trained models...")
    df = pd.read_csv(PROCESSED_CSV)
    from sklearn.model_selection import train_test_split
    X = df[FEATURE_NAMES]
    y = df["normalized_label"].values
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    pipeline = joblib.load(os.path.join(MODELS_DIR, "preprocessing_pipeline.pkl"))
    X_test_scaled = pipeline.transform(X_test)

    # Load models
    lr = joblib.load(os.path.join(MODELS_DIR, "logistic_regression.pkl"))
    dt = joblib.load(os.path.join(MODELS_DIR, "decision_tree.pkl"))
    mlp = joblib.load(os.path.join(MODELS_DIR, "mlp_classifier.pkl"))

    # Load training metadata
    meta_path = os.path.join(REPORTS_DIR, "training_metadata.json")
    training_meta = {}
    if os.path.exists(meta_path):
        with open(meta_path, "r") as f:
            training_meta = json.load(f)

    models_dict = {
        "Logistic Regression": {
            "model": lr,
            "X_eval": X_test_scaled,
            "train_time": training_meta.get("logistic_regression", {}).get("train_time", 2.5),
            "key": "logistic_regression"
        },
        "Decision Tree": {
            "model": dt,
            "X_eval": X_test,  # Raw features for tree
            "train_time": training_meta.get("decision_tree", {}).get("train_time", 1.8),
            "key": "decision_tree"
        },
        "MLP Classifier": {
            "model": mlp,
            "X_eval": X_test_scaled,
            "train_time": training_meta.get("mlp_classifier", {}).get("train_time", 15.0),
            "key": "mlp_classifier"
        }
    }

    metrics_list = []
    roc_curves_data = {}
    pr_curves_data = {}
    reports_dict = {}

    for name, item in models_dict.items():
        m = item["model"]
        X_eval = item["X_eval"]
        train_time = item["train_time"]
        key = item["key"]

        print(f"\n[*] Evaluating {name}...")
        # Measure prediction latency
        t0 = time.time()
        y_pred = m.predict(X_eval)
        pred_time = (time.time() - t0) / len(y_test) * 1000.0  # ms per sample

        y_prob = m.predict_proba(X_eval)[:, 1] if hasattr(m, "predict_proba") else y_pred

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_test, y_prob)

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        print(f"    Accuracy:  {acc*100:.2f}% | Precision: {prec*100:.2f}% | Recall: {rec*100:.2f}% | F1: {f1:.4f} | ROC-AUC: {roc_auc:.4f}")
        print(f"    Confusion Matrix: TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")

        # Save individual Confusion Matrix Plot
        plt.figure(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt=",d", cmap="Blues",
                    xticklabels=["Legitimate (0)", "Malicious (1)"],
                    yticklabels=["Legitimate (0)", "Malicious (1)"],
                    cbar=False, linewidths=1, linecolor="#00f0ff")
        plt.title(f"Confusion Matrix: {name}", fontsize=12, pad=12, color="#00f0ff")
        plt.xlabel("Predicted Label", fontsize=10)
        plt.ylabel("True Label", fontsize=10)
        plt.tight_layout()
        cm_path = os.path.join(CM_DIR, f"cm_{key}.png")
        plt.savefig(cm_path, dpi=200)
        plt.close()

        # Classification Report
        clf_rep = classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Malicious (1)"], output_dict=True)
        clf_rep_txt = classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Malicious (1)"])
        with open(os.path.join(REPORTS_DIR, f"classification_report_{key}.txt"), "w") as f:
            f.write(f"CLASSIFICATION REPORT - {name}\n")
            f.write("="*50 + "\n\n")
            f.write(clf_rep_txt)
        pd.DataFrame(clf_rep).transpose().to_csv(os.path.join(REPORTS_DIR, f"classification_report_{key}.csv"))

        # Store curves
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        p_curve, r_curve, _ = precision_recall_curve(y_test, y_prob)
        roc_curves_data[name] = (fpr, tpr, roc_auc)
        pr_curves_data[name] = (r_curve, p_curve, auc(r_curve, p_curve))

        metrics_list.append({
            "Model": name,
            "Accuracy": float(acc),
            "Precision": float(prec),
            "Recall": float(rec),
            "F1-score": float(f1),
            "ROC-AUC": float(roc_auc),
            "Training Time (s)": float(train_time),
            "Prediction Latency (ms/sample)": float(pred_time),
            "True Positive": int(tp),
            "True Negative": int(tn),
            "False Positive": int(fp),
            "False Negative": int(fn),
            "Key": key
        })

    # Combined ROC Curves Plot
    plt.figure(figsize=(8, 6))
    colors = {"Logistic Regression": "#ffab00", "Decision Tree": "#00e5ff", "MLP Classifier": "#00e676"}
    for name, (fpr, tpr, score) in roc_curves_data.items():
        plt.plot(fpr, tpr, label=f"{name} (AUC = {score:.4f})", color=colors.get(name, "#ffffff"), linewidth=2)
    plt.plot([0, 1], [0, 1], "k--", alpha=0.6, label="Random Guess (0.50)")
    plt.title("Receiver Operating Characteristic (ROC) Comparison", fontsize=13, pad=15, color="#00f0ff")
    plt.xlabel("False Positive Rate", fontsize=11)
    plt.ylabel("True Positive Rate (Recall)", fontsize=11)
    plt.legend(loc="lower right", frameon=True, facecolor="#112233", edgecolor="#00f0ff")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "roc_curves_comparison.png"), dpi=200)
    plt.savefig(os.path.join(OUTPUTS_DIR, "charts", "roc_curves_comparison.png"), dpi=200)
    plt.close()

    # Combined Precision-Recall Curves Plot
    plt.figure(figsize=(8, 6))
    for name, (r_curve, p_curve, score) in pr_curves_data.items():
        plt.plot(r_curve, p_curve, label=f"{name} (PR-AUC = {score:.4f})", color=colors.get(name, "#ffffff"), linewidth=2)
    plt.title("Precision-Recall Curves Comparison", fontsize=13, pad=15, color="#00f0ff")
    plt.xlabel("Recall", fontsize=11)
    plt.ylabel("Precision", fontsize=11)
    plt.legend(loc="lower left", frameon=True, facecolor="#112233", edgecolor="#00f0ff")
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "precision_recall_curves.png"), dpi=200)
    plt.savefig(os.path.join(OUTPUTS_DIR, "charts", "precision_recall_curves.png"), dpi=200)
    plt.close()

    # MLP Loss Curve Plot
    mlp_meta = training_meta.get("mlp_classifier", {})
    if "loss_curve" in mlp_meta:
        plt.figure(figsize=(8, 5))
        plt.plot(mlp_meta["loss_curve"], color="#00f0ff", linewidth=2, marker="o", markersize=4)
        plt.title("MLP Deep Neural Network: Training Loss Curve", fontsize=13, pad=15, color="#00f0ff")
        plt.xlabel("Iteration / Epoch", fontsize=11)
        plt.ylabel("Log Loss (Cross-Entropy)", fontsize=11)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(REPORTS_DIR, "mlp_loss_curve.png"), dpi=200)
        plt.savefig(os.path.join(OUTPUTS_DIR, "charts", "mlp_loss_curve.png"), dpi=200)
        plt.close()

    # Save Comparison Table
    metrics_df = pd.DataFrame(metrics_list)
    csv_path = os.path.join(COMPARISON_DIR, "model_comparison.csv")
    metrics_df.to_csv(csv_path, index=False)
    json_path = os.path.join(COMPARISON_DIR, "model_metrics.json")
    with open(json_path, "w") as f:
        json.dump(metrics_list, f, indent=2)
    print(f"\n[+] Saved model comparison table to: {csv_path}")
    print(f"[+] Saved metrics JSON to: {json_path}")

    # Generate Individual Comparison Bar Charts
    metric_cols = [
        ("Accuracy", "Accuracy Score", "#00e5ff"),
        ("Precision", "Precision Score", "#00e676"),
        ("Recall", "Recall Score (Detection Rate)", "#ff1744"),
        ("F1-score", "F1-Score (Harmonic Mean)", "#d500f9"),
        ("ROC-AUC", "Area Under ROC Curve", "#ffd600"),
        ("Training Time (s)", "Training Execution Time (Seconds)", "#ff9100"),
    ]

    for col_name, title, bar_color in metric_cols:
        plt.figure(figsize=(7, 5))
        bars = plt.bar(metrics_df["Model"], metrics_df[col_name], color=bar_color, edgecolor="#ffffff", width=0.45)
        plt.title(f"Model Comparison: {title}", fontsize=12, pad=15, color="#00f0ff")
        plt.ylabel(col_name, fontsize=10)
        for b in bars:
            h = b.get_height()
            fmt_val = f"{h:.4f}" if "Time" not in col_name else f"{h:.2f}s"
            plt.text(b.get_x() + b.get_width()/2., h * 1.01, fmt_val,
                     ha="center", va="bottom", color="#ffffff", fontweight="bold", fontsize=10)
        if "Time" not in col_name:
            plt.ylim(0, 1.15)
        plt.tight_layout()
        clean_name = col_name.lower().replace(" ", "_").replace("(", "").replace(")", "").replace("-", "_")
        plt.savefig(os.path.join(COMPARISON_DIR, f"{clean_name}_comparison.png"), dpi=200)
        plt.savefig(os.path.join(OUTPUTS_DIR, "charts", f"{clean_name}_comparison.png"), dpi=200)
        plt.close()

    # Determine Best Model
    # Cybersecurity priority: Balance high Recall on Malicious URLs (minimize FN) and high F1/ROC-AUC
    # Composite Score = 0.40 * Recall + 0.35 * F1 + 0.25 * ROC-AUC
    best_score = -1
    best_row = None
    for _, row in metrics_df.iterrows():
        comp_score = 0.40 * row["Recall"] + 0.35 * row["F1-score"] + 0.25 * row["ROC-AUC"]
        if comp_score > best_score:
            best_score = comp_score
            best_row = row

    best_key = best_row["Key"]
    best_model_obj = models_dict[best_row["Model"]]["model"]
    best_model_path = os.path.join(MODELS_DIR, "best_model.pkl")
    joblib.dump(best_model_obj, best_model_path)

    best_info = {
        "best_model_name": best_row["Model"],
        "key": best_key,
        "accuracy": best_row["Accuracy"],
        "precision": best_row["Precision"],
        "recall": best_row["Recall"],
        "f1_score": best_row["F1-score"],
        "roc_auc": best_row["ROC-AUC"],
        "composite_score": float(best_score),
        "selection_rationale": (
            "Selected based on multi-criteria cybersecurity threat optimization, prioritizing "
            "malicious URL Recall to minimize dangerous False Negatives while sustaining high F1 and ROC-AUC."
        )
    }
    with open(os.path.join(MODELS_DIR, "best_model_info.json"), "w") as f:
        json.dump(best_info, f, indent=2)

    print(f"\n[+] BEST MODEL SELECTED: {best_row['Model']}")
    print(f"    Accuracy: {best_row['Accuracy']*100:.2f}% | Recall: {best_row['Recall']*100:.2f}% | F1: {best_row['F1-score']:.4f}")
    print(f"[+] Saved to: {best_model_path}")

    # Feature Importance Analysis
    print("\n[*] Conducting Feature Importance Analysis across models...")
    # Decision Tree Importances
    dt_importances = pd.Series(dt.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=False)
    # Logistic Regression Absolute Coefficients
    lr_importances = pd.Series(np.abs(lr.coef_[0]), index=FEATURE_NAMES).sort_values(ascending=False)

    # MLP Permutation Importance on a sample of test data
    perm_sample_X = X_test_scaled[:1500]
    perm_sample_y = y_test[:1500]
    perm_result = permutation_importance(mlp, perm_sample_X, perm_sample_y, n_repeats=5, random_state=42, n_jobs=-1)
    mlp_importances = pd.Series(perm_result.importances_mean, index=FEATURE_NAMES).sort_values(ascending=False)

    feature_imp_summary = pd.DataFrame({
        "Decision_Tree_Gini": dt_importances,
        "Logistic_Regression_AbsCoef": lr_importances,
        "MLP_Permutation_Importance": mlp_importances
    })
    feature_imp_summary.to_csv(os.path.join(REPORTS_DIR, "feature_importance_summary.csv"))

    # Top 10 Feature Importance Plot for Best Model
    plt.figure(figsize=(10, 6))
    if best_row["Model"] == "Decision Tree":
        top10 = dt_importances.head(10).sort_values(ascending=True)
        metric_lbl = "Gini Impurity Reduction"
    elif best_row["Model"] == "Logistic Regression":
        top10 = lr_importances.head(10).sort_values(ascending=True)
        metric_lbl = "Absolute Coefficient Magnitude"
    else:
        top10 = mlp_importances.head(10).sort_values(ascending=True)
        metric_lbl = "Mean Permutation Importance"

    bars = plt.barh(top10.index, top10.values, color="#00f0ff", edgecolor="#ffffff", height=0.6)
    plt.title(f"Top 10 Most Influential URL Features ({best_row['Model']} - {metric_lbl})", fontsize=12, pad=15, color="#00f0ff")
    plt.xlabel(metric_lbl, fontsize=10)
    for b in bars:
        w = b.get_width()
        plt.text(w + 0.002, b.get_y() + b.get_height()/2., f"{w:.3f}",
                 va="center", color="#ffffff", fontsize=9, fontweight="bold")
    plt.xlim(0, max(top10.values) * 1.15)
    plt.tight_layout()
    plt.savefig(os.path.join(REPORTS_DIR, "top10_features_best_model.png"), dpi=200)
    plt.savefig(os.path.join(OUTPUTS_DIR, "charts", "top10_features_best_model.png"), dpi=200)
    plt.close()

    print("[+] Evaluation and Explainability pipeline completed successfully.")
    return metrics_list, best_info


if __name__ == "__main__":
    evaluate_all()
