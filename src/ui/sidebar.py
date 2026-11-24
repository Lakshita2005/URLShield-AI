"""
Sidebar Navigation and Control Console for URLShield AI
High Contrast & High Legibility Design System
"""

import streamlit as st
from typing import Tuple
from src.ui.theme import (
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_PRIMARY, BORDER_COLOR, COLOR_SUCCESS, BG_CARD
)
from src.ui.components import clean_html


def render_sidebar() -> Tuple[str, str, float]:
    """
    Render professional sidebar with branding, navigation, engine controls, and status telemetry.
    Returns: (selected_page, selected_model_name, threshold)
    """
    with st.sidebar:
        # 1. Brand & Identity
        brand_html = f"""
        <div style="padding-bottom: 20px; margin-bottom: 16px; border-bottom: 1px solid {BORDER_COLOR};">
            <div style="display: flex; align-items: center; gap: 12px;">
                <div style="width: 42px; height: 42px; background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.4); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 22px;">
                    🛡️
                </div>
                <div>
                    <h2 style="font-size: 1.25rem; font-weight: 800; color: {TEXT_PRIMARY}; margin: 0; letter-spacing: -0.01em;">
                        URLSHIELD <span style="color: {ACCENT_PRIMARY};">AI</span>
                    </h2>
                    <div style="font-size: 0.82rem; color: #94A3B8; font-weight: 600;">
                        Intelligent Threat Analytics
                    </div>
                </div>
            </div>
        </div>
        """
        st.markdown(clean_html(brand_html), unsafe_allow_html=True)

        # 2. Navigation Console
        nav_header = f"""
        <div style="font-size: 0.82rem; font-weight: 700; color: {ACCENT_PRIMARY}; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 10px;">
            CONSOLE MODULES
        </div>
        """
        st.markdown(clean_html(nav_header), unsafe_allow_html=True)

        nav_options = [
            "📊 Security Overview",
            "🔍 Live URL Analysis",
            "📁 Bulk URL Scanner",
            "📈 Threat Intelligence",
            "🧪 Model Laboratory",
            "📉 Performance Analytics",
            "⚖️ Ethical AI Lab",
            "ℹ️ About the Project"
        ]

        selected_page = st.radio(
            "Console Navigation",
            nav_options,
            index=0,
            label_visibility="collapsed"
        )

        st.markdown(f'<div style="margin-top: 18px; margin-bottom: 16px; border-top: 1px solid {BORDER_COLOR};"></div>', unsafe_allow_html=True)

        # 3. Engine Settings Box
        engine_header = f"""
        <div style="font-size: 0.82rem; font-weight: 700; color: {ACCENT_PRIMARY}; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 10px;">
            DETECTION ENGINE CONTROLS
        </div>
        """
        st.markdown(clean_html(engine_header), unsafe_allow_html=True)

        model_choices = [
            "MLP Classifier (Best Model)",
            "Decision Tree Classifier",
            "Logistic Regression"
        ]
        selected_model = st.selectbox(
            "Active Architecture",
            model_choices,
            index=0,
            help="Select which trained supervised model scores submitted URLs."
        )

        threshold = st.slider(
            "Classification Threshold",
            min_value=0.05,
            max_value=0.95,
            value=0.50,
            step=0.05,
            help="Threshold for labeling URL as Malicious. Lower values increase Recall (fewer missed threats); higher values increase Precision."
        )

        # 4. Telemetry Status Box
        telemetry_html = f"""
        <div class="sidebar-info-box">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <span style="font-size: 0.78rem; font-weight: 700; color: #CBD5E1; text-transform: uppercase; letter-spacing: 0.06em;">ENGINE TELEMETRY</span>
                <span style="display: inline-flex; align-items: center; gap: 6px; color: {COLOR_SUCCESS}; font-size: 0.78rem; font-weight: 700;">
                    <span class="pulsing-dot" style="width: 7px; height: 7px;"></span> ONLINE
                </span>
            </div>
            <div style="font-size: 0.85rem; color: {TEXT_SECONDARY}; line-height: 1.6;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 3px;">
                    <span style="color: {TEXT_MUTED}; font-weight: 500;">Architecture:</span>
                    <span style="color: {TEXT_PRIMARY}; font-weight: 700;">{selected_model.split(' ')[0]}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 3px;">
                    <span style="color: {TEXT_MUTED}; font-weight: 500;">Dataset:</span>
                    <span style="color: {TEXT_PRIMARY}; font-weight: 700;">LegitPhish v2</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 3px;">
                    <span style="color: {TEXT_MUTED}; font-weight: 500;">DOI:</span>
                    <span style="color: {ACCENT_PRIMARY}; font-family: monospace; font-size: 0.8rem; font-weight: 600;">10.17632/hx4m</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="color: {TEXT_MUTED}; font-weight: 500;">Test Accuracy:</span>
                    <span style="color: {COLOR_SUCCESS}; font-weight: 800;">99.92%</span>
                </div>
            </div>
        </div>
        """
        st.markdown(clean_html(telemetry_html), unsafe_allow_html=True)

    return selected_page, selected_model, threshold
