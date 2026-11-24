"""
URLSHIELD AI: Intelligent URL Threat Detection & Security Analytics
Enterprise Cybersecurity SaaS Dashboard
Redesigned with high-contrast, modern UI/UX design system.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure project root is available in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Import UI modular design system
from src.ui.theme import (
    BG_MAIN, BG_CARD, BG_SURFACE,
    ACCENT_PRIMARY, ACCENT_SECONDARY,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    BORDER_COLOR, COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER,
    MODEL_PALETTE, apply_plotly_theme
)
from src.ui.styles import get_global_css
from src.ui.components import (
    clean_html,
    render_page_header,
    render_kpi,
    render_card_start,
    render_card_end,
    render_verdict_card,
    render_threat_indicator_card,
    render_model_card,
    render_about_section_card
)
from src.ui.sidebar import render_sidebar

# Import Backend & Prediction Engines
from src.feature_extraction import (
    extract_features_dict,
    extract_features_df,
    explain_url_features,
    FEATURE_NAMES
)
from src.prediction import get_predictor

# --- STREAMLIT PAGE CONFIGURATION ---
st.set_page_config(
    page_title="URLShield AI | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Global Cybersecurity Design System CSS
st.markdown(get_global_css(), unsafe_allow_html=True)


# --- CACHED DATA & MODEL LOADERS ---
@st.cache_resource
def load_all_models():
    """Load and cache pipelines and models."""
    models_dir = os.path.join(BASE_DIR, "models")
    return {
        "MLP Classifier (Best Model)": joblib.load(os.path.join(models_dir, "best_model.pkl")),
        "Decision Tree Classifier": joblib.load(os.path.join(models_dir, "decision_tree.pkl")),
        "Logistic Regression": joblib.load(os.path.join(models_dir, "logistic_regression.pkl")),
        "pipeline": joblib.load(os.path.join(models_dir, "preprocessing_pipeline.pkl")),
    }


@st.cache_data
def load_comparison_data():
    """Load model evaluation comparison table."""
    comp_path = os.path.join(BASE_DIR, "outputs", "model_comparison", "model_comparison.csv")
    if os.path.exists(comp_path):
        return pd.read_csv(comp_path)
    return pd.DataFrame()


@st.cache_data
def load_dataset_summary():
    """Load dataset statistics and a fast sample for dashboard charts."""
    proc_path = os.path.join(BASE_DIR, "data", "processed", "legitphish_processed.csv")
    if os.path.exists(proc_path):
        df = pd.read_csv(proc_path)
        return {
            "total": len(df),
            "malicious": int((df["normalized_label"] == 1).sum()),
            "legitimate": int((df["normalized_label"] == 0).sum()),
            "sample": df.sample(min(8000, len(df)), random_state=42)
        }
    return {"total": 100872, "malicious": 63492, "legitimate": 37380, "sample": pd.DataFrame()}


# Load resources
models_dict = load_all_models()
comparison_df = load_comparison_data()
dataset_stats = load_dataset_summary()


# --- RENDER SIDEBAR ---
selected_page, selected_model_name, classification_threshold = render_sidebar()


# ==============================================================================
# PAGE 1: SECURITY OVERVIEW
# ==============================================================================
if "Security Overview" in selected_page:
    st.markdown(render_page_header(
        title="Security Overview",
        subtitle="Global threat telemetry, dataset telemetry, and multi-model threat detection benchmarks",
        category="EXECUTIVE THREAT CONSOLE",
        badge_text="LIVE TELEMETRY",
        badge_type="safe"
    ), unsafe_allow_html=True)

    # 4 Equal KPI Cards Row
    kpi_cols = st.columns(4)
    with kpi_cols[0]:
        st.markdown(render_kpi(
            label="Total URLs Analysed",
            value=f"{dataset_stats['total']:,}",
            footer_text="Verified Mendeley Dataset",
            border_accent=ACCENT_PRIMARY
        ), unsafe_allow_html=True)

    with kpi_cols[1]:
        mal_pct = (dataset_stats['malicious'] / dataset_stats['total']) * 100
        st.markdown(render_kpi(
            label="Malicious / Phishing",
            value=f"{dataset_stats['malicious']:,}",
            delta_text=f"{mal_pct:.1f}%",
            delta_positive=False,
            footer_text="Threat Ratio",
            border_accent=COLOR_DANGER
        ), unsafe_allow_html=True)

    with kpi_cols[2]:
        leg_pct = (dataset_stats['legitimate'] / dataset_stats['total']) * 100
        st.markdown(render_kpi(
            label="Legitimate / Benign",
            value=f"{dataset_stats['legitimate']:,}",
            delta_text=f"{leg_pct:.1f}%",
            delta_positive=True,
            footer_text="Verified Safe Baseline",
            border_accent=COLOR_SUCCESS
        ), unsafe_allow_html=True)

    with kpi_cols[3]:
        st.markdown(render_kpi(
            label="Optimal Model Accuracy",
            value="99.92%",
            delta_text="99.93% Recall",
            delta_positive=True,
            footer_text="MLP Neural Network",
            border_accent=ACCENT_SECONDARY
        ), unsafe_allow_html=True)

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # Overview Visualizations Row (Nested inside cards for pixel-perfect alignment)
    col_chart_left, col_chart_right = st.columns([1, 1])

    with col_chart_left:
        with st.container(border=True):
            st.markdown(render_card_start(
                title="Threat Class Distribution",
                subtitle="Benchmark composition across 100,872 verified URLs",
                icon="🛡️"
            ), unsafe_allow_html=True)

            fig_donut = go.Figure(data=[go.Pie(
                labels=["Malicious (Phishing)", "Legitimate (Benign)"],
                values=[dataset_stats['malicious'], dataset_stats['legitimate']],
                hole=0.60,
                marker_colors=[COLOR_DANGER, COLOR_SUCCESS],
                textinfo="label+percent",
                insidetextorientation="radial"
            )])
            apply_plotly_theme(fig_donut, height=280, show_legend=False)
            st.plotly_chart(fig_donut, use_container_width=True)

    with col_chart_right:
        with st.container(border=True):
            st.markdown(render_card_start(
                title="Model Discrimination (ROC-AUC Comparison)",
                subtitle="Area Under ROC Curve across supervised architectures",
                icon="📊"
            ), unsafe_allow_html=True)

            if not comparison_df.empty:
                fig_bar = px.bar(
                    comparison_df,
                    x="Model",
                    y="ROC-AUC",
                    color="Model",
                    color_discrete_sequence=MODEL_PALETTE,
                    text="ROC-AUC"
                )
                fig_bar.update_traces(texttemplate='%{text:.4f}', textposition='outside')
                apply_plotly_theme(fig_bar, height=280, show_legend=False)
                fig_bar.update_layout(yaxis=dict(range=[0.998, 1.0006]))
                st.plotly_chart(fig_bar, use_container_width=True)

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Key Threat Intelligence Insights
    st.markdown('<div class="section-title">Empirical Cybersecurity Observations</div>', unsafe_allow_html=True)
    i1, i2, i3 = st.columns(3)
    with i1:
        st.markdown(render_threat_indicator_card(
            risk_title="Raw IP Address Abuse",
            risk_label="Critical Threat",
            desc="Over 48,000 malicious URLs host payloads directly on raw IPv4 endpoints, circumventing traditional domain reputation filters."
        ), unsafe_allow_html=True)
    with i2:
        st.markdown(render_threat_indicator_card(
            risk_title="HTTPS False Sense of Security",
            risk_label="Moderate Risk",
            desc="Over 30% of verified phishing attacks utilize valid SSL/TLS certificates. The padlock icon does NOT guarantee safety."
        ), unsafe_allow_html=True)
    with i3:
        st.markdown(render_threat_indicator_card(
            risk_title="High Character Entropy",
            risk_label="Informative Indicator",
            desc="Malicious URLs exhibit significantly elevated Shannon entropy (>4.2 bits/char) due to Base64 tokens and DGA obfuscation."
        ), unsafe_allow_html=True)


# ==============================================================================
# PAGE 2: LIVE URL ANALYSIS
# ==============================================================================
elif "Live URL Analysis" in selected_page:
    st.markdown(render_page_header(
        title="Live URL Analysis Engine",
        subtitle="Real-time, non-intrusive lexical and structural risk assessment",
        category="REAL-TIME THREAT SCANNER",
        badge_text="SAFE EVALUATION",
        badge_type="info"
    ), unsafe_allow_html=True)

    st.markdown(clean_html("""
    <div style="background-color: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 10px; padding: 14px 18px; margin-bottom: 22px; font-size: 0.95rem; color: #E2E8F0; line-height: 1.5;">
        🛡️ <strong style="color: #38BDF8;">Zero-Risk Analysis Protocol:</strong> URLShield AI analyzes URLs solely using mathematical and static string heuristics. It <strong style="color: #FFFFFF;">never</strong> visits, connects to, or downloads content from the target URL.
    </div>
    """), unsafe_allow_html=True)

    # Sample Presets Row
    st.markdown('<div style="font-size: 0.82rem; font-weight: 700; color: #38BDF8; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 10px;">QUICK-EVALUATION PRESETS</div>', unsafe_allow_html=True)
    p_cols = st.columns(4)
    target_preset = ""
    with p_cols[0]:
        if st.button("🟢 Legitimate: Google", use_container_width=True):
            target_preset = "https://www.google.com/search?q=cybersecurity+threat+intelligence"
    with p_cols[1]:
        if st.button("🔴 Malware: Mozi Botnet", use_container_width=True):
            target_preset = "http://59.183.116.177:55504/Mozi.m"
    with p_cols[2]:
        if st.button("🔴 Phishing: Login Portal", use_container_width=True):
            target_preset = "https://keraekken-loagginnusa.godaddysites.com/"
    with p_cols[3]:
        if st.button("🔴 Trojan: Ngrok Exe", use_container_width=True):
            target_preset = "http://171.100.81.38:8080/xampp/ngrok.exe"

    # URL Input Form
    with st.form("live_analysis_form"):
        user_url = st.text_input(
            "Enter Full URL String to Analyze:",
            value=target_preset if target_preset else "https://www.wikipedia.org/wiki/Computer_security",
            placeholder="e.g. http://192.168.1.50:8080/setup.exe or https://example.com"
        )
        scan_btn = st.form_submit_button("⚡ Analyze Threat Profile", use_container_width=True)

    if scan_btn or target_preset:
        if not user_url or not user_url.strip():
            st.warning("Please enter a valid, non-empty URL string.")
        else:
            model_slug = "mlp_classifier" if "MLP" in selected_model_name else ("decision_tree" if "Tree" in selected_model_name else "logistic_regression")
            predictor = get_predictor(model_slug)
            result = predictor.predict_url(user_url.strip(), threshold=classification_threshold)

            st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
            res_left, res_right = st.columns([1.2, 1])

            with res_left:
                st.markdown(render_verdict_card(result, classification_threshold), unsafe_allow_html=True)

            with res_right:
                with st.container(border=True):
                    st.markdown(render_card_start(
                        title="Threat Severity Meter",
                        subtitle="Calculated probability vs decision threshold",
                        icon="🎯"
                    ), unsafe_allow_html=True)

                    prob_val = result['malicious_probability'] * 100
                    fig_gauge = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=prob_val,
                        number={'suffix': "%", 'font': {'color': result['risk_color'], 'size': 32, 'family': 'Inter'}},
                        gauge={
                            'axis': {'range': [0, 100], 'tickcolor': BORDER_COLOR, 'tickfont': {'color': TEXT_MUTED}},
                            'bar': {'color': result['risk_color']},
                            'steps': [
                                {'range': [0, 35], 'color': "rgba(34, 197, 94, 0.15)"},
                                {'range': [35, 65], 'color': "rgba(245, 158, 11, 0.15)"},
                                {'range': [65, 100], 'color': "rgba(239, 68, 68, 0.15)"}
                            ],
                            'threshold': {
                                'line': {'color': "#ffffff", 'width': 3},
                                'thickness': 0.75,
                                'value': classification_threshold * 100
                            }
                        }
                    ))
                    apply_plotly_theme(fig_gauge, height=195, show_legend=False, margin=dict(l=20, r=20, t=15, b=10))
                    st.plotly_chart(fig_gauge, use_container_width=True)

            # Explainability Indicators
            st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
            st.markdown('<div class="section-title">Explainability & Threat Factors</div>', unsafe_allow_html=True)
            exps = result["explanations"]
            exp_cols = st.columns(len(exps) if len(exps) <= 3 else 3)
            for i, exp in enumerate(exps[:3]):
                with exp_cols[i]:
                    st.markdown(render_threat_indicator_card(
                        risk_title=exp['feature'],
                        risk_label=exp['risk'],
                        desc=exp['desc']
                    ), unsafe_allow_html=True)

            # Extracted 16-Feature Vector Table
            st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
            st.markdown('<div class="section-title">Extracted 16-Feature Lexical Vector</div>', unsafe_allow_html=True)
            feat_items = list(result["features"].items())
            half = len(feat_items) // 2
            
            f1, f2 = st.columns(2)
            with f1:
                df_f1 = pd.DataFrame(feat_items[:half], columns=["Feature Attribute", "Computed Value"])
                st.dataframe(df_f1, use_container_width=True, hide_index=True)
            with f2:
                df_f2 = pd.DataFrame(feat_items[half:], columns=["Feature Attribute", "Computed Value"])
                st.dataframe(df_f2, use_container_width=True, hide_index=True)


# ==============================================================================
# PAGE 3: BULK URL SCANNER
# ==============================================================================
elif "Bulk URL Scanner" in selected_page:
    st.markdown(render_page_header(
        title="Bulk URL Scanner",
        subtitle="Batch threat evaluation for proxy logs, email feeds, and CSV exports",
        category="ENTERPRISE BATCH PROCESSING",
        badge_text="BATCH READY",
        badge_type="info"
    ), unsafe_allow_html=True)

    # Sample CSV Download Button
    sample_csv_path = os.path.join(BASE_DIR, "data", "sample_urls.csv")
    if os.path.exists(sample_csv_path):
        with open(sample_csv_path, "rb") as f:
            st.download_button(
                "📥 Download Pre-configured Sample CSV for Testing",
                data=f,
                file_name="sample_urls_test.csv",
                mime="text/csv",
                help="Download a clean CSV containing mixed legitimate and malicious URLs."
            )

    uploaded_file = st.file_uploader("Upload CSV containing URL records:", type=["csv"])

    if uploaded_file is not None:
        try:
            df_upload = pd.read_csv(uploaded_file)
            st.success(f"Loaded CSV with {len(df_upload):,} rows and {len(df_upload.columns)} columns.")

            # Identify URL Column
            url_candidates = [c for c in df_upload.columns if "url" in c.lower() or "link" in c.lower() or "domain" in c.lower()]
            default_idx = df_upload.columns.get_loc(url_candidates[0]) if url_candidates else 0
            selected_url_col = st.selectbox("Select Target URL Column:", df_upload.columns, index=int(default_idx))

            if st.button("🚀 Execute Batch Threat Scan", use_container_width=True):
                with st.spinner("Extracting features and scoring URLs..."):
                    model_slug = "mlp_classifier" if "MLP" in selected_model_name else ("decision_tree" if "Tree" in selected_model_name else "logistic_regression")
                    predictor = get_predictor(model_slug)
                    urls = df_upload[selected_url_col].astype(str).tolist()
                    batch_res = predictor.predict_batch(urls, threshold=classification_threshold)

                    merged = pd.concat([df_upload, batch_res.drop(columns=["URL"])], axis=1)

                    total_scanned = len(merged)
                    mal_count = int((merged["Prediction"] == "Malicious").sum())
                    leg_count = total_scanned - mal_count

                    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
                    m1, m2, m3, m4 = st.columns(4)
                    with m1:
                        st.markdown(render_kpi("Total Scanned", f"{total_scanned:,}", footer_text="Batch Size"), unsafe_allow_html=True)
                    with m2:
                        st.markdown(render_kpi("Malicious Flagged", f"{mal_count:,}", delta_text=f"{mal_count/total_scanned*100:.1f}%", delta_positive=False, border_accent=COLOR_DANGER), unsafe_allow_html=True)
                    with m3:
                        st.markdown(render_kpi("Legitimate Clear", f"{leg_count:,}", delta_text=f"{leg_count/total_scanned*100:.1f}%", delta_positive=True, border_accent=COLOR_SUCCESS), unsafe_allow_html=True)
                    with m4:
                        st.markdown(render_kpi("Active Threshold", f"{classification_threshold:.2f}", footer_text=selected_model_name.split(' ')[0]), unsafe_allow_html=True)

                    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)
                    st.markdown('<div class="section-title">Inspection Results Table</div>', unsafe_allow_html=True)
                    st.dataframe(merged, use_container_width=True)

                    csv_data = merged.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        "📥 Download Complete Batch Results as CSV",
                        data=csv_data,
                        file_name="urlshield_bulk_scan_results.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
        except Exception as e:
            st.error(f"Error parsing uploaded file: {e}")


# ==============================================================================
# PAGE 4: THREAT INTELLIGENCE DASHBOARD
# ==============================================================================
elif "Threat Intelligence" in selected_page:
    st.markdown(render_page_header(
        title="Threat Intelligence Dashboard",
        subtitle="Empirical lexical & structural feature distributions across 100,872 verified URLs",
        category="THREAT ANALYTICS",
        badge_text="LEGITPHISH DATASET",
        badge_type="info"
    ), unsafe_allow_html=True)

    df_sample = dataset_stats["sample"]
    if df_sample.empty:
        st.warning("Dataset sample is loading.")
    else:
        # Row 1: Length and Entropy Distributions
        c1, c2 = st.columns(2)
        with c1:
            with st.container(border=True):
                st.markdown(render_card_start(
                    title="URL Length Distribution (Clipped at 180 chars)",
                    subtitle="Comparative character count between malicious and benign classes",
                    icon="📏"
                ), unsafe_allow_html=True)

                fig_len = px.histogram(
                    df_sample[df_sample["url_length"] <= 180],
                    x="url_length",
                    color="normalized_label",
                    barmode="overlay",
                    nbins=35,
                    color_discrete_map={0: COLOR_SUCCESS, 1: COLOR_DANGER},
                    labels={"url_length": "URL Length", "normalized_label": "Class"}
                )
                apply_plotly_theme(fig_len, height=270)
                st.plotly_chart(fig_len, use_container_width=True)

        with c2:
            with st.container(border=True):
                st.markdown(render_card_start(
                    title="Shannon Character Entropy (Bits / Char)",
                    subtitle="Randomness and algorithmic obfuscation metric distribution",
                    icon="⚡"
                ), unsafe_allow_html=True)

                fig_ent = px.box(
                    df_sample,
                    x="normalized_label",
                    y="url_entropy",
                    color="normalized_label",
                    color_discrete_map={0: COLOR_SUCCESS, 1: COLOR_DANGER},
                    labels={"url_entropy": "Shannon Entropy", "normalized_label": "Class"}
                )
                apply_plotly_theme(fig_ent, height=270, show_legend=False)
                fig_ent.update_xaxes(tickvals=[0, 1], ticktext=["Legitimate", "Malicious"])
                st.plotly_chart(fig_ent, use_container_width=True)

        st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

        # Row 2: Subdomains and HTTPS
        c3, c4 = st.columns(2)
        with c3:
            with st.container(border=True):
                st.markdown(render_card_start(
                    title="Subdomain Count Distribution",
                    subtitle="Breakdown of domain prefix depth across threat categories",
                    icon="🌐"
                ), unsafe_allow_html=True)

                sub_agg = df_sample.groupby(["subdomain_count", "normalized_label"]).size().reset_index(name="count")
                sub_agg = sub_agg[sub_agg["subdomain_count"].isin([-1, 0, 1, 2, 3, 4])]
                fig_sub = px.bar(
                    sub_agg,
                    x="subdomain_count",
                    y="count",
                    color="normalized_label",
                    barmode="group",
                    color_discrete_map={0: COLOR_SUCCESS, 1: COLOR_DANGER},
                    labels={"subdomain_count": "Subdomains Count", "count": "URLs"}
                )
                apply_plotly_theme(fig_sub, height=270)
                st.plotly_chart(fig_sub, use_container_width=True)

        with c4:
            with st.container(border=True):
                st.markdown(render_card_start(
                    title="HTTPS Adoption by Threat Class",
                    subtitle="Encrypted TLS vs plaintext HTTP protocol frequencies",
                    icon="🔒"
                ), unsafe_allow_html=True)

                https_agg = df_sample.groupby(["https_flag", "normalized_label"]).size().reset_index(name="count")
                fig_https = px.bar(
                    https_agg,
                    x="https_flag",
                    y="count",
                    color="normalized_label",
                    barmode="group",
                    color_discrete_map={0: COLOR_SUCCESS, 1: COLOR_DANGER},
                    labels={"https_flag": "HTTPS (0=HTTP, 1=HTTPS)", "count": "URLs"}
                )
                apply_plotly_theme(fig_https, height=270)
                fig_https.update_xaxes(tickvals=[0, 1], ticktext=["HTTP (Insecure)", "HTTPS (TLS)"])
                st.plotly_chart(fig_https, use_container_width=True)


# ==============================================================================
# PAGE 5: MODEL LABORATORY
# ==============================================================================
elif "Model Laboratory" in selected_page:
    st.markdown(render_page_header(
        title="Model Laboratory",
        subtitle="Architecture benchmarks, hyperparameter auditing, and trade-off telemetry",
        category="MACHINE LEARNING AUDIT",
        badge_text="3 MODELS TRAINED",
        badge_type="info"
    ), unsafe_allow_html=True)

    # Benchmark Cards Row
    m1, m2, m3 = st.columns(3)
    with m1:
        st.markdown(render_model_card(
            name="Logistic Regression",
            model_type="Linear Supervised Baseline",
            acc=0.9967,
            prec=0.9994,
            rec=0.9954,
            f1=0.9974,
            train_time=0.31,
            is_best=False
        ), unsafe_allow_html=True)

    with m2:
        st.markdown(render_model_card(
            name="Decision Tree",
            model_type="Non-Linear Decision Tree",
            acc=0.9993,
            prec=0.9996,
            rec=0.9992,
            f1=0.9994,
            train_time=0.27,
            is_best=False
        ), unsafe_allow_html=True)

    with m3:
        st.markdown(render_model_card(
            name="MLP Neural Network",
            model_type="Deep Multi-Layer Perceptron",
            acc=0.9992,
            prec=0.9994,
            rec=0.9993,
            f1=0.9994,
            train_time=21.31,
            is_best=True
        ), unsafe_allow_html=True)

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">Comparative Performance Table</div>', unsafe_allow_html=True)
    if not comparison_df.empty:
        st.dataframe(comparison_df.style.format({
            "Accuracy": "{:.4f}",
            "Precision": "{:.4f}",
            "Recall": "{:.4f}",
            "F1-score": "{:.4f}",
            "ROC-AUC": "{:.4f}",
            "Training Time (s)": "{:.2f}s",
            "Prediction Latency (ms/sample)": "{:.4f} ms"
        }), use_container_width=True)


# ==============================================================================
# PAGE 6: PERFORMANCE ANALYTICS
# ==============================================================================
elif "Performance Analytics" in selected_page:
    st.markdown(render_page_header(
        title="Performance Analytics",
        subtitle="Confusion matrices, discrimination dynamics, and feature importance rankings",
        category="MODEL EVALUATION",
        badge_text="20,175 TEST SAMPLES",
        badge_type="info"
    ), unsafe_allow_html=True)

    tab_cm, tab_curves, tab_feats = st.tabs(["📊 Confusion Matrices", "📈 ROC & PR Dynamics", "🎯 Feature Importance"])

    with tab_cm:
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        cm_c1, cm_c2, cm_c3 = st.columns(3)
        cm_base = os.path.join(BASE_DIR, "outputs", "confusion_matrices")
        with cm_c1:
            st.image(os.path.join(cm_base, "cm_logistic_regression.png"), caption="Logistic Regression Confusion Matrix")
        with cm_c2:
            st.image(os.path.join(cm_base, "cm_decision_tree.png"), caption="Decision Tree Confusion Matrix")
        with cm_c3:
            st.image(os.path.join(cm_base, "cm_mlp_classifier.png"), caption="MLP Classifier Confusion Matrix")

    with tab_curves:
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        rc1, rc2 = st.columns(2)
        rep_base = os.path.join(BASE_DIR, "outputs", "reports")
        with rc1:
            st.image(os.path.join(rep_base, "roc_curves_comparison.png"), caption="Receiver Operating Characteristic (ROC)")
        with rc2:
            st.image(os.path.join(rep_base, "precision_recall_curves.png"), caption="Precision-Recall Curves")

    with tab_feats:
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        st.image(os.path.join(BASE_DIR, "outputs", "charts", "top10_features_best_model.png"), caption="Top 10 Most Influential Features (Optimal Model)")


# ==============================================================================
# PAGE 7: ETHICAL AI LAB
# ==============================================================================
elif "Ethical AI Lab" in selected_page:
    st.markdown(render_page_header(
        title="Ethical AI & Threshold Lab",
        subtitle="Simulate classification policy trade-offs, alert fatigue, and operational risk boundaries",
        category="RESPONSIBLE CYBERSECURITY",
        badge_text="POLICY SIMULATOR",
        badge_type="warning"
    ), unsafe_allow_html=True)

    st.markdown("""
    <p style="color: #CBD5E1; font-size: 1rem; line-height: 1.6;">
        In enterprise security operations (SOC), detection thresholds govern the fundamental trade-off between <strong>preventing breaches (Recall)</strong> and <strong>avoiding false alerts (Precision)</strong>. Adjust the slider to simulate real-time policy modifications on the test cohort.
    </p>
    """, unsafe_allow_html=True)

    sim_thresh = st.slider(
        "Simulated Decision Threshold ($T$):",
        min_value=0.05,
        max_value=0.95,
        value=0.50,
        step=0.05
    )

    # Compute live metrics on the test partition
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

    proc_csv = os.path.join(BASE_DIR, "data", "processed", "legitphish_processed.csv")
    df_p = pd.read_csv(proc_csv)
    X = df_p[FEATURE_NAMES]
    y = df_p["normalized_label"].values
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    pipe = models_dict["pipeline"]
    best_m = models_dict["MLP Classifier (Best Model)"]
    y_probs = best_m.predict_proba(pipe.transform(X_test))[:, 1]
    sim_preds = (y_probs >= sim_thresh).astype(int)

    sim_cm = confusion_matrix(y_test, sim_preds)
    tn, fp, fn, tp = sim_cm.ravel()
    p_val = precision_score(y_test, sim_preds)
    r_val = recall_score(y_test, sim_preds)
    f_val = f1_score(y_test, sim_preds)

    col_sim_left, col_sim_right = st.columns([1.1, 1])

    with col_sim_left:
        audit_html = f"""
        <div class="cyber-card">
            <div style="font-size: 0.85rem; font-weight: 700; color: {ACCENT_PRIMARY}; text-transform: uppercase; letter-spacing: 0.06em;">
                POLICY AUDIT AT THRESHOLD T = {sim_thresh:.2f}
            </div>
            <div style="display: flex; gap: 24px; margin-top: 14px; margin-bottom: 18px;">
                <div>
                    <span style="font-size: 0.82rem; font-weight: 600; color: {TEXT_MUTED};">PRECISION</span>
                    <div style="font-size: 1.4rem; font-weight: 800; color: {ACCENT_PRIMARY};">{p_val*100:.2f}%</div>
                </div>
                <div>
                    <span style="font-size: 0.82rem; font-weight: 600; color: {TEXT_MUTED};">RECALL</span>
                    <div style="font-size: 1.4rem; font-weight: 800; color: {COLOR_SUCCESS};">{r_val*100:.2f}%</div>
                </div>
                <div>
                    <span style="font-size: 0.82rem; font-weight: 600; color: {TEXT_MUTED};">F1-SCORE</span>
                    <div style="font-size: 1.4rem; font-weight: 800; color: {COLOR_WARNING};">{f_val:.4f}</div>
                </div>
            </div>
            
            <div style="display: flex; flex-direction: column; gap: 12px;">
                <div style="background-color: rgba(248, 113, 113, 0.12); border: 1px solid rgba(248, 113, 113, 0.35); border-radius: 10px; padding: 14px 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong style="color: {COLOR_DANGER}; font-size: 0.95rem;">False Negatives (Threats Missed)</strong>
                        <span style="font-size: 1.2rem; font-weight: 800; color: {COLOR_DANGER};">{fn:,}</span>
                    </div>
                    <small style="color: {TEXT_SECONDARY}; font-size: 0.85rem;">Phishing campaigns erroneously classified as benign.</small>
                </div>
                
                <div style="background-color: rgba(251, 191, 36, 0.12); border: 1px solid rgba(251, 191, 36, 0.35); border-radius: 10px; padding: 14px 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong style="color: {COLOR_WARNING}; font-size: 0.95rem;">False Positives (Benign Blocked)</strong>
                        <span style="font-size: 1.2rem; font-weight: 800; color: {COLOR_WARNING};">{fp:,}</span>
                    </div>
                    <small style="color: {TEXT_SECONDARY}; font-size: 0.85rem;">Legitimate employee requests blocked, causing workflow friction.</small>
                </div>
            </div>
        </div>
        """
        st.markdown(clean_html(audit_html), unsafe_allow_html=True)

    with col_sim_right:
        with st.container(border=True):
            st.markdown(render_card_start(
                title=f"Dynamic Confusion Matrix (T = {sim_thresh:.2f})",
                subtitle="Real-time classification boundary recalculation",
                icon="⚖️"
            ), unsafe_allow_html=True)

            fig_cm = px.imshow(
                sim_cm,
                labels=dict(x="Predicted Label", y="Actual Label", color="Count"),
                x=["Legitimate (0)", "Malicious (1)"],
                y=["Legitimate (0)", "Malicious (1)"],
                text_auto=True,
                color_continuous_scale="Blues"
            )
            apply_plotly_theme(fig_cm, height=240, show_legend=False)
            st.plotly_chart(fig_cm, use_container_width=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">Ethical Considerations in Autonomous Security Systems</div>', unsafe_allow_html=True)

    e1, e2, e3 = st.columns(3)
    with e1:
        st.markdown(render_about_section_card(
            title="Why Legitimate URLs Get Flagged",
            icon="⚠️",
            content_html="Modern single-sign-on (OAuth), CDN endpoints, and email tracking links frequently contain randomized hashes and Base64 tokens. These structural patterns elevate character entropy and mimic phishing signatures, risking legitimate traffic denial."
        ), unsafe_allow_html=True)

    with e2:
        st.markdown(render_about_section_card(
            title="Privacy in Threat Telemetry",
            icon="🔒",
            content_html="GET query parameters frequently leak sensitive authentication tokens, session IDs, and email addresses. URLShield AI enforces client-side static analysis, protecting end-user confidential data from external transit."
        ), unsafe_allow_html=True)

    with e3:
        st.markdown(render_about_section_card(
            title="Concept Drift & Bias",
            icon="🌐",
            content_html="Threat actors continuously pivot toward novel top-level domains, decentralized gateways (IPFS), and cloud worker endpoints. Static classifiers require routine retraining to prevent degradation against emerging attack vectors."
        ), unsafe_allow_html=True)


# ==============================================================================
# PAGE 8: ABOUT THE PROJECT
# ==============================================================================
elif "About the Project" in selected_page:
    st.markdown(render_page_header(
        title="About URLShield AI",
        subtitle="System architecture, research methodology, technology stack, and academic citation",
        category="SYSTEM DOCUMENTATION",
        badge_text="VERSION 2.0",
        badge_type="info"
    ), unsafe_allow_html=True)

    col_ab1, col_ab2 = st.columns([1, 1])

    with col_ab1:
        st.markdown(render_about_section_card(
            title="Project Overview & Objectives",
            icon="🎯",
            content_html="""
            <p><strong>URLShield AI</strong> is a full-lifecycle artificial intelligence platform developed to detect malicious and phishing uniform resource locators using purely lexical and structural characteristics.</p>
            <ul>
                <li><strong>Non-Intrusive Extraction</strong>: Extracts 16 lexical and structural attributes without remote connections.</li>
                <li><strong>High Recall Priority</strong>: Minimizes dangerous False Negatives to block threat delivery before perimeter penetration.</li>
                <li><strong>Explainable Predictions</strong>: Generates human-comprehensible security justifications for every verdict.</li>
            </ul>
            """
        ), unsafe_allow_html=True)

        st.markdown(render_about_section_card(
            title="Dataset Citation & Metadata",
            icon="📚",
            content_html="""
            <p>Built upon the official <strong>LegitPhish Dataset</strong> published on Mendeley Data.</p>
            <div style="background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; padding: 14px; font-family: monospace; font-size: 0.88rem; color: #38BDF8; margin-bottom: 14px; line-height: 1.5;">
                DOI: 10.17632/hx4m73v2sf.2<br/>
                URL: https://data.mendeley.com/datasets/hx4m73v2sf/2<br/>
                Version: 2.0 (Verified Benchmark)
            </div>
            <p style="margin: 0;">Total Records: <strong>101,219 URLs</strong> (63,678 Phishing, 37,540 Legitimate).</p>
            """
        ), unsafe_allow_html=True)

    with col_ab2:
        st.markdown(render_about_section_card(
            title="Technology Stack",
            icon="🛠️",
            content_html="""
            <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px;">
                <span class="badge badge-info">Python 3.12</span>
                <span class="badge badge-info">Scikit-Learn 1.9</span>
                <span class="badge badge-info">Streamlit 1.67</span>
                <span class="badge badge-info">Plotly Express</span>
                <span class="badge badge-info">Pandas & NumPy</span>
                <span class="badge badge-info">Shannon Entropy</span>
                <span class="badge badge-info">Pytest Harness</span>
            </div>
            <p>Built with enterprise Python software design patterns, including Scikit-Learn feature scaling pipelines, modular feature extractors, and cached predictors.</p>
            """
        ), unsafe_allow_html=True)

        st.markdown(render_about_section_card(
            title="Operational Disclaimers",
            icon="⚠️",
            content_html="""
            <p>URLShield AI generates probabilistic machine learning risk predictions based strictly on static URL properties.</p>
            <ul>
                <li>A rating of <em>Likely Legitimate</em> does not guarantee total immunity against zero-day targeted attacks or compromised legitimate web hosts.</li>
                <li>The engine never connects to or visits submitted URLs, safeguarding analysts from remote code execution or drive-by payload distribution.</li>
            </ul>
            """
        ), unsafe_allow_html=True)
