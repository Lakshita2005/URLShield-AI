# URLSHIELD AI: AI-Powered Malicious URL Detection System
### Machine Learning & Deep Learning Threat Intelligence Platform

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.67.0-FF4B4B.svg)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.9.1-F7931E.svg)](https://scikit-learn.org/)
[![DOI](https://img.shields.io/badge/DOI-10.17632%2Fhx4m73v2sf.2-blue)](https://doi.org/10.17632/hx4m73v2sf.2)

---

## 1. Project Overview

**URLShield AI** is an end-to-end, enterprise-grade AI cybersecurity system developed to classify and defend against phishing and malicious URLs in real time. Rather than relying on static, easily bypassed domain blocklists, URLShield AI assesses threat risks purely through **static, non-intrusive lexical, structural, and information-theoretic URL properties**.

The system protects analysts and end-users by **never executing code, downloading payload binaries, or initiating network handshakes** with target servers during feature extraction.

---

## 2. Problem Statement & Threat Landscape

Malicious URLs are the primary delivery vehicle for over 85% of modern cybersecurity breaches, facilitating:
- **Credential Harvesting**: Sophisticated brand impersonation targeting financial institutions, crypto exchanges, and corporate Single Sign-On (SSO) portals.
- **Drive-By Exploitation & Malware Delivery**: Silent distribution of Ransomware, Remote Access Trojans (RATs), and Botnet loaders (e.g., Mozi).
- **Fast-Flux & DGA Evasion**: Attackers generate thousands of short-lived URLs hourly, outrunning conventional reactive DNS reputation blacklists.

**URLShield AI** solves this challenge by mathematically analyzing the internal structure, entropy, and character tokens of incoming URLs in under 0.05 milliseconds per URL.

---

## 3. Dataset Source, Statistics & Citation

URLShield AI is trained and evaluated on the official **LegitPhish Dataset**, hosted on Mendeley Data.

### Dataset Metadata
- **Source**: Mendeley Data
- **Official URL**: [https://data.mendeley.com/datasets/hx4m73v2sf/2](https://data.mendeley.com/datasets/hx4m73v2sf/2)
- **DOI**: `10.17632/hx4m73v2sf.2`
- **Total Acquired URLs**: 101,219 entries
- **Cleaned Dataset Records**: 100,872 entries (after duplicate URL deduplication)
- **Phishing URLs**: 63,492 (62.94%) — Sourced from URLHaus threat feeds and active phishing campaigns.
- **Legitimate URLs**: 37,380 (37.06%) — Sourced from trusted public sites (Wikipedia, Stack Overflow).

### Label Normalization
> **IMPORTANT NOTE**: The raw LegitPhish dataset encodes `0 = Phishing` and `1 = Legitimate`.  
> URLShield AI normalizes all labels to the standard cybersecurity convention:
> - **`0 = Legitimate / Benign`**
> - **`1 = Malicious / Phishing`**

### Citation
```bibtex
@misc{legitphish2025,
  title={LegitPhish Dataset},
  author={Mendeley Data},
  year={2025},
  version={2},
  publisher={Mendeley Data},
  doi={10.17632/hx4m73v2sf.2},
  url={https://data.mendeley.com/datasets/hx4m73v2sf/2}
}
```

---

## 4. Extracted Feature Engineering Engine

URLShield AI extracts a 16-dimensional feature vector directly from raw URL strings without querying external servers:

| Feature Name | Type | Cybersecurity Significance |
|---|---|---|
| `url_length` | Integer | Total character count; obfuscated URLs and redirect chains tend to be abnormally long. |
| `has_ip_address` | Binary | Direct IPv4 host addressing (`1` indicates host is raw IP, bypassing DNS reputation). |
| `dot_count` | Integer | Count of `.`; excessive dots frequently indicate deep subdomain nesting or masquerading. |
| `https_flag` | Binary | `1` if HTTPS protocol; `0` if plaintext HTTP (insecure communication). |
| `url_entropy` | Float | Shannon entropy ($-\sum p_i \log_2 p_i$); measures randomness from DGA and token obfuscation. |
| `token_count` | Integer | Count of delimiter-separated tokens (`/`, `.`, `?`, `=`, `&`). |
| `subdomain_count` | Integer | Number of subdomains preceding the root domain. |
| `query_param_count` | Integer | Number of GET query parameters passed after `?`. |
| `tld_length` | Integer | Character length of Top-Level Domain (e.g., `com` = 3, `workers.dev` = 3). |
| `path_length` | Integer | Character length of the URL path following the authority component. |
| `has_hyphen_in_domain` | Binary | `1` if `-` is in domain name (common typosquatting / brand-jacking indicator). |
| `number_of_digits` | Integer | Count of numeric characters throughout the entire URL string. |
| `tld_popularity` | Binary | `1` if TLD belongs to high-reputation standard TLDs (`.com`, `.org`, `.net`, `.edu`, `.gov`). |
| `suspicious_file_extension`| Binary | `1` if URL terminates in dangerous extensions (`.exe`, `.zip`, `.bin`, `.apk`, `.cmd`, `.js`). |
| `domain_name_length` | Integer | Character length of the second-level registered domain name. |
| `percentage_numeric_chars` | Float | Percentage ($0\% - 100\%$) of numeric characters in URL. |

---

## 5. Machine Learning & Deep Learning Implementation

The system implements and benchmarks three supervised architectures:

1. **Logistic Regression (Linear Baseline)**:
   - Optimization: L-BFGS Quasi-Newton algorithm
   - Regularization: $L_2$ penalty, $C=1.0$, balanced class weighting
   - Feature Scaling: Scikit-learn `StandardScaler` fitted on training split only
   - Inference latency: $<0.01$ ms per sample

2. **Decision Tree Classifier (Non-linear Tree)**:
   - Splitting Criterion: Gini Impurity
   - Hyperparameters: `max_depth=18`, `min_samples_split=10`, `min_samples_leaf=4`
   - Invariant to monotonic scaling; unscaled inputs
   - Excels at isolating discrete Boolean heuristics (e.g. IP + `.exe`)

3. **Multi-Layer Perceptron (MLP Deep Neural Network - Best Model)**:
   - Topology: Dense Input $\to$ Hidden Layer 1 (64 neurons, ReLU) $\to$ Hidden Layer 2 (32 neurons, ReLU) $\to$ Output (Sigmoid / Softmax)
   - Optimizer: Adam ($\beta_1=0.9, \beta_2=0.999$, learning rate $= 0.001$, adaptive schedule)
   - Regularization: Early stopping ($10$ epochs patience on $10\%$ validation split), $L_2$ weight decay $\alpha=0.0001$
   - Convergence: 29 iterations, log-loss reduced from $0.42$ to $<0.012$

---

## 6. Model Benchmark & Evaluation Matrices

Evaluated on an independent, stratified 20% test partition (20,175 verified URLs: 12,699 Malicious, 7,476 Benign):

| Model Architecture | Accuracy | Precision | Recall (Malicious) | F1-Score | ROC-AUC | Training Time | Prediction Latency |
|---|---|---|---|---|---|---|---|
| **Logistic Regression** | 99.67% | 99.94% | 99.54% | 0.9974 | 0.9998 | 0.31s | 0.004 ms/sample |
| **Decision Tree** | 99.93% | 99.96% | 99.92% | 0.9994 | 0.9997 | 0.27s | 0.003 ms/sample |
| **MLP Neural Network (Best)** | **99.92%** | **99.94%** | **99.93%** | **0.9994** | **1.0000** | 21.31s | 0.012 ms/sample |

### Confusion Matrix Breakdown (MLP Classifier)
- **True Negatives (Legitimate Correctly Cleared)**: $7,469$
- **False Positives (Legitimate Inadvertently Flagged)**: $7$ ($0.09\%$ false alarm rate)
- **False Negatives (Malicious Threats Missed)**: $9$ ($0.07\%$ breach rate)
- **True Positives (Malicious Successfully Blocked)**: $12,690$

---

## 7. Project Folder Structure

```
URLShield AI/
├── app.py                          # Streamlit 8-page cybersecurity application
├── README.md                       # Comprehensive system documentation
├── requirements.txt                # Pinned production dependencies
├── .gitignore                      # Git exclusion rules
├── prompt.md                       # Specification guidelines
├── build_and_run_notebook.py       # Programmatic notebook builder & runner
│
├── data/
│   ├── raw/                        # Original downloaded LegitPhish CSV
│   │   └── url_features_extracted1.csv
│   ├── processed/                  # Normalized, cleaned dataset
│   │   └── legitphish_processed.csv
│   ├── dataset_info.md             # Dataset documentation, metadata & citations
│   └── sample_urls.csv             # Pre-configured test CSV for bulk scanning
│
├── notebooks/
│   └── malicious_url_detection.ipynb # 22-section fully executed Jupyter Notebook
│
├── src/
│   ├── data_loader.py              # Automatic Mendeley API dataset acquisition
│   ├── preprocessing.py            # Deduplication, label mapping, train-test splitting
│   ├── feature_extraction.py       # 16-feature lexical & structural extractor
│   ├── eda.py                      # Exploratory data analysis & 10 charts generator
│   ├── train_models.py             # Model training pipelines (LR, DT, MLP)
│   ├── evaluate_models.py          # Metrics, confusion matrices, ROC/PR curves
│   ├── prediction.py               # Single URL & batch prediction engine
│   └── ui/                         # Modular Cybersecurity SaaS Design System
│       ├── theme.py                # High-contrast color palette & Plotly styling
│       ├── styles.py               # Centralized global SaaS CSS stylesheets
│       ├── components.py           # Reusable KPI cards, headers & threat badges
│       └── sidebar.py              # Telemetry console, model controls & navigation
│
├── models/
│   ├── logistic_regression.pkl     # Trained Logistic Regression model
│   ├── decision_tree.pkl           # Trained Decision Tree model
│   ├── mlp_classifier.pkl          # Trained MLP Neural Network model
│   ├── best_model.pkl              # Optimal selected model (MLP)
│   ├── best_model_info.json        # Selection rationale & metadata
│   └── preprocessing_pipeline.pkl  # StandardScaler pipeline
│
├── outputs/
│   ├── charts/                     # All 10 EDA charts + model curves
│   ├── confusion_matrices/         # High-res confusion matrices for all models
│   ├── reports/                    # Classification reports (CSV/TXT) & curves
│   └── model_comparison/           # Metric tables (CSV/JSON) & comparison plots
│
└── tests/
    ├── test_dataset.py             # Dataset schema & label mapping tests
    ├── test_feature_extraction.py  # Feature extractor unit tests (8 tests)
    ├── test_models.py              # Model persistence & inference tests
    └── test_prediction.py          # Prediction engine & threshold tests
```

---

## 8. Installation & Setup Instructions

### Prerequisites
- Python 3.10+ (Recommended: Python 3.12)
- Git

### Step 1: Clone or Navigate to Project
```bash
cd "c:\Users\HP\Documents\URLShield AI"
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run Automated Dataset Acquisition & Training (Optional - Pre-trained)
All models and data are already acquired, trained, and validated out of the box. To rebuild from scratch:
```bash
python src/data_loader.py
python src/eda.py
python src/train_models.py
python src/evaluate_models.py
```

### Step 4: Run Test Suite
```bash
python -m pytest tests/
```
All 20 unit tests will execute and validate the pipeline.

---

## 9. Launching the Streamlit Application

Launch the **URLShield AI** cybersecurity dashboard using:

```bash
streamlit run app.py
```

The application automatically opens at `http://localhost:8501`.

### Features of the 8 Application Pages:
1. **Security Overview**: Executive KPI metrics, dataset distribution, and threat insights.
2. **Live URL Analysis**: Interactive URL scanner with real-time risk classification, confidence gauge, and lexical explainability.
3. **Bulk URL Scanner**: Batch CSV upload, automatic URL column detection, filterable threat tables, and CSV export.
4. **Threat Intelligence Dashboard**: Interactive Plotly visualizations comparing entropy, length, HTTPS usage, and subdomains.
5. **Model Laboratory**: In-depth architecture breakdown, hyperparameter auditing, and trade-offs.
6. **Performance Analytics**: High-resolution confusion matrices, ROC curves, PR curves, and feature importance rankings.
7. **Ethical AI Lab**: Live threshold simulator ($T \in [0.05, 0.95]$) showing dynamic False Positive vs False Negative trade-offs.
8. **About the Project**: System objectives, academic citations, architecture overview, and operational disclaimers.

---

## 10. Executing the Jupyter Notebook

The complete research notebook is located at:
`notebooks/malicious_url_detection.ipynb`

To launch Jupyter Lab / Notebook:
```bash
jupyter notebook notebooks/malicious_url_detection.ipynb
```
The notebook is already fully executed with all outputs, plots, and tables rendered and saved.

---

## 11. Ethical Considerations & Limitations

- **Alert Fatigue vs. Threat Exposure**: Setting an excessively aggressive classification threshold ($T=0.10$) eliminates False Negatives but increases benign user friction. URLShield AI allows security teams to tune sensitivity according to risk posture.
- **Privacy Preservation**: The feature extraction engine operates locally without transmitting submitted URL query strings (which may contain session tokens or internal user IDs) across the network.
- **Concept Drift**: Attackers continuously evolve TLD selections and domain generation algorithms. Production deployments should incorporate continuous automated retraining cycles.

---

## 12. License & Author Information

Developed by the **URLShield AI Research Team**. Released under the [MIT License](LICENSE).
Academic citation: Mendeley Data LegitPhish Dataset (DOI: [10.17632/hx4m73v2sf.2](https://doi.org/10.17632/hx4m73v2sf.2)).
