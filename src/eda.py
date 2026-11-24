"""
Exploratory Data Analysis (EDA) Module for URLShield AI
AI-Powered Malicious URL Detection System

Generates statistical analysis, distribution plots, correlation matrices,
and exports all 10 required visualizations to outputs/charts/.
"""

import os
import sys
from typing import Dict, Any

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import ExtraTreesClassifier

from src.feature_extraction import FEATURE_NAMES

OUTPUTS_CHARTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs", "charts")
PROCESSED_CSV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "processed", "legitphish_processed.csv")


def set_cyber_style():
    """Apply high-contrast dark cybersecurity visual styling."""
    plt.style.use("dark_background")
    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["axes.edgecolor"] = "#00f0ff"
    plt.rcParams["axes.linewidth"] = 0.8
    plt.rcParams["grid.color"] = "#223344"
    plt.rcParams["grid.linestyle"] = "--"
    plt.rcParams["grid.alpha"] = 0.5


def run_eda(df: pd.DataFrame = None) -> Dict[str, Any]:
    """Execute complete EDA and save all 10 charts."""
    os.makedirs(OUTPUTS_CHARTS_DIR, exist_ok=True)
    set_cyber_style()

    if df is None:
        if os.path.exists(PROCESSED_CSV_PATH):
            df = pd.read_csv(PROCESSED_CSV_PATH)
        else:
            from src.preprocessing import prepare_data
            prepare_data()
            df = pd.read_csv(PROCESSED_CSV_PATH)

    print(f"[*] Starting EDA on {len(df):,} records...")

    # Summary Stats
    summary = {
        "total_records": int(len(df)),
        "malicious_count": int((df["normalized_label"] == 1).sum()),
        "legitimate_count": int((df["normalized_label"] == 0).sum()),
        "malicious_ratio": float((df["normalized_label"] == 1).mean()),
        "feature_count": len(FEATURE_NAMES),
    }
    print(f"[+] Malicious (Phishing): {summary['malicious_count']:,} ({summary['malicious_ratio']*100:.2f}%)")
    print(f"[+] Legitimate (Benign):  {summary['legitimate_count']:,} ({(1-summary['malicious_ratio'])*100:.2f}%)")

    # Chart 1: Malicious vs Legitimate URL Distribution
    plt.figure(figsize=(8, 6))
    counts = df["normalized_label"].value_counts().sort_index()
    labels = ["Legitimate (0)", "Malicious (1)"]
    colors = ["#00e676", "#ff1744"]
    bars = plt.bar(labels, counts.values, color=colors, width=0.5, edgecolor="#ffffff", linewidth=0.8)
    for bar in bars:
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., h + 1000, f"{int(h):,}\n({h/len(df)*100:.1f}%)",
                 ha="center", va="bottom", color="#ffffff", fontweight="bold", fontsize=11)
    plt.title("URLShield AI: URL Class Distribution (Legitimate vs Malicious)", fontsize=13, pad=15, color="#00f0ff")
    plt.ylabel("Number of URLs", fontsize=11)
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "01_class_distribution.png"), dpi=200)
    plt.close()

    # Chart 2: URL Length Distribution
    plt.figure(figsize=(9, 5))
    sns.kdeplot(data=df[df["normalized_label"] == 0]["url_length"].clip(upper=200),
                label="Legitimate", color="#00e676", fill=True, alpha=0.35, linewidth=2)
    sns.kdeplot(data=df[df["normalized_label"] == 1]["url_length"].clip(upper=200),
                label="Malicious", color="#ff1744", fill=True, alpha=0.35, linewidth=2)
    plt.title("URL Length Density Distribution by Class (Clipped at 200)", fontsize=13, pad=15, color="#00f0ff")
    plt.xlabel("URL Length (characters)", fontsize=11)
    plt.ylabel("Density", fontsize=11)
    plt.legend(frameon=True, facecolor="#112233", edgecolor="#00f0ff")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "02_url_length_distribution.png"), dpi=200)
    plt.close()

    # Chart 3: URL Entropy Distribution
    plt.figure(figsize=(9, 5))
    sns.kdeplot(data=df[df["normalized_label"] == 0]["url_entropy"],
                label="Legitimate", color="#00e676", fill=True, alpha=0.35, linewidth=2)
    sns.kdeplot(data=df[df["normalized_label"] == 1]["url_entropy"],
                label="Malicious", color="#ff1744", fill=True, alpha=0.35, linewidth=2)
    plt.title("Shannon Entropy Distribution by Class", fontsize=13, pad=15, color="#00f0ff")
    plt.xlabel("Shannon Entropy (Bits per Character)", fontsize=11)
    plt.ylabel("Density", fontsize=11)
    plt.legend(frameon=True, facecolor="#112233", edgecolor="#00f0ff")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "03_url_entropy_distribution.png"), dpi=200)
    plt.close()

    # Chart 4: Number of Subdomains Distribution
    plt.figure(figsize=(9, 5))
    sub_df = df.groupby(["subdomain_count", "normalized_label"]).size().unstack(fill_value=0)
    # Clip subdomains between -1 and 4 for clean presentation
    sub_df_clipped = sub_df.loc[sub_df.index.isin([-1, 0, 1, 2, 3, 4])]
    ax = sub_df_clipped.plot(kind="bar", figsize=(9, 5), color=["#00e676", "#ff1744"], edgecolor="#ffffff")
    plt.title("Subdomain Count Breakdown by Class", fontsize=13, pad=15, color="#00f0ff")
    plt.xlabel("Number of Subdomains", fontsize=11)
    plt.ylabel("Count", fontsize=11)
    plt.legend(["Legitimate", "Malicious"], frameon=True, facecolor="#112233", edgecolor="#00f0ff")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "04_subdomain_count_distribution.png"), dpi=200)
    plt.close()

    # Chart 5: HTTPS vs Non-HTTPS URL Distribution
    plt.figure(figsize=(8, 6))
    https_ct = pd.crosstab(df["https_flag"], df["normalized_label"], normalize="index") * 100
    https_ct.plot(kind="bar", stacked=True, color=["#00e676", "#ff1744"], figsize=(8, 6), edgecolor="#ffffff")
    plt.title("Proportion of Malicious URLs by HTTPS Status", fontsize=13, pad=15, color="#00f0ff")
    plt.xlabel("HTTPS Protocol (0 = HTTP, 1 = HTTPS)", fontsize=11)
    plt.ylabel("Percentage (%)", fontsize=11)
    plt.legend(["Legitimate", "Malicious"], frameon=True, facecolor="#112233", edgecolor="#00f0ff")
    plt.xticks([0, 1], ["HTTP (Insecure)", "HTTPS (Secure/TLS)"], rotation=0)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "05_https_vs_non_https.png"), dpi=200)
    plt.close()

    # Chart 6: Suspicious Extension Distribution
    plt.figure(figsize=(8, 6))
    ext_ct = pd.crosstab(df["suspicious_file_extension"], df["normalized_label"])
    ext_ct.plot(kind="bar", color=["#00e676", "#ff1744"], figsize=(8, 6), edgecolor="#ffffff")
    plt.title("Suspicious File Extension Presence vs Class", fontsize=13, pad=15, color="#00f0ff")
    plt.xlabel("Suspicious File Extension (0 = No, 1 = Yes)", fontsize=11)
    plt.ylabel("URL Count", fontsize=11)
    plt.legend(["Legitimate", "Malicious"], frameon=True, facecolor="#112233", edgecolor="#00f0ff")
    plt.xticks([0, 1], ["Standard URL", "Dangerous Extension (.exe, .zip, etc.)"], rotation=0)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "06_suspicious_extension_distribution.png"), dpi=200)
    plt.close()

    # Chart 7: Correlation Heatmap
    plt.figure(figsize=(14, 11))
    corr_cols = FEATURE_NAMES + ["normalized_label"]
    corr = df[corr_cols].corr()
    mask = np.triu(np.ones_like(corr, dtype=bool))
    cmap = sns.diverging_palette(145, 10, s=85, l=55, as_cmap=True)
    sns.heatmap(corr, mask=mask, cmap=cmap, vmin=-1, vmax=1, annot=True, fmt=".2f",
                square=True, linewidths=0.5, cbar_kws={"shrink": 0.8})
    plt.title("URL Feature Correlation Heatmap (Including Normalized Label)", fontsize=14, pad=15, color="#00f0ff")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "07_correlation_heatmap.png"), dpi=200)
    plt.close()

    # Chart 8: Feature Distribution Histograms
    fig, axes = plt.subplots(4, 4, figsize=(18, 14))
    axes = axes.flatten()
    for i, col in enumerate(FEATURE_NAMES):
        ax = axes[i]
        sns.histplot(data=df, x=col, hue="normalized_label", bins=25, ax=ax,
                     palette=["#00e676", "#ff1744"], element="step", common_norm=False, legend=(i==0))
        ax.set_title(col, fontsize=10, color="#00f0ff")
        ax.set_xlabel("")
        ax.set_ylabel("")
        if i == 0 and ax.get_legend():
            ax.get_legend().get_texts()[0].set_text("Legit")
            ax.get_legend().get_texts()[1].set_text("Malicious")
    plt.suptitle("Feature Distribution Histograms Across LegitPhish Classes", fontsize=15, y=0.99, color="#00f0ff")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "08_feature_distribution_histograms.png"), dpi=200)
    plt.close()

    # Chart 9: Boxplots of Important URL Features
    key_features = ["url_length", "url_entropy", "token_count", "domain_name_length", "percentage_numeric_chars"]
    fig, axes = plt.subplots(1, 5, figsize=(18, 5))
    for i, col in enumerate(key_features):
        ax = axes[i]
        sns.boxplot(x="normalized_label", y=col, data=df, ax=ax,
                    palette=["#00e676", "#ff1744"], boxprops=dict(alpha=0.7), showfliers=False)
        ax.set_title(col, fontsize=11, color="#00f0ff")
        ax.set_xticklabels(["Legit", "Malicious"])
        ax.set_xlabel("")
    plt.suptitle("Comparative Boxplots for Key URL Attributes (Outliers Hidden)", fontsize=14, y=1.02, color="#00f0ff")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "09_feature_boxplots.png"), dpi=200)
    plt.close()

    # Chart 10: Feature Importance Graph (Using Tree-based Gini importance)
    print("[*] Computing feature importance on subset for Chart 10...")
    sample_df = df.sample(min(20000, len(df)), random_state=42)
    et = ExtraTreesClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    et.fit(sample_df[FEATURE_NAMES], sample_df["normalized_label"])
    importances = pd.Series(et.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=True)

    plt.figure(figsize=(10, 8))
    bars = plt.barh(importances.index, importances.values, color="#00f0ff", edgecolor="#ffffff", height=0.65)
    plt.title("URL Feature Importance (Gini Impurity from Tree Ensemble)", fontsize=13, pad=15, color="#00f0ff")
    plt.xlabel("Importance Score", fontsize=11)
    for bar in bars:
        w = bar.get_width()
        plt.text(w + 0.003, bar.get_y() + bar.get_height()/2., f"{w:.3f}",
                 va="center", color="#ffffff", fontsize=9, fontweight="bold")
    plt.xlim(0, max(importances.values) * 1.15)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUTS_CHARTS_DIR, "10_feature_importance.png"), dpi=200)
    plt.close()

    print(f"[+] Successfully generated and saved all 10 EDA charts to: {OUTPUTS_CHARTS_DIR}")
    return summary


if __name__ == "__main__":
    from typing import Dict, Any
    run_eda()
