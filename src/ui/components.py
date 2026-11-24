"""
Reusable UI Components for URLShield AI
Premium Cybersecurity Dashboard Components - High Contrast & High Legibility
"""

import re
from typing import Optional, List, Dict, Any
from src.ui.theme import (
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_PRIMARY, ACCENT_SECONDARY, BORDER_COLOR,
    COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER,
    BG_CARD, BG_SURFACE
)


def clean_html(raw_html: str) -> str:
    """Strip all leading/trailing whitespace from each line to prevent Markdown code-block triggering."""
    lines = [line.strip() for line in raw_html.strip().splitlines() if line.strip()]
    return "".join(lines)


def render_page_header(
    title: str,
    subtitle: str,
    category: str = "THREAT INTELLIGENCE PLATFORM",
    badge_text: Optional[str] = None,
    badge_type: str = "info"
) -> str:
    """Generate high-contrast, professional SaaS top header banner HTML with live status indicator."""
    badge_class = f"badge-{badge_type}"
    badge_html = f'<div class="header-badge {badge_class}"><span class="pulsing-dot" style="margin-right: 6px;"></span>{badge_text}</div>' if badge_text else ''
    
    html = f"""
    <div class="top-header-container">
        <div>
            <div class="header-breadcrumb">{category}</div>
            <h1 class="header-title">{title}</h1>
            <p class="header-subtitle">{subtitle}</p>
        </div>
        {badge_html}
    </div>
    """
    return clean_html(html)


def render_kpi(
    label: str,
    value: str,
    footer_text: Optional[str] = None,
    delta_text: Optional[str] = None,
    delta_positive: bool = True,
    border_accent: Optional[str] = None
) -> str:
    """Generate professional SaaS KPI card HTML with high contrast and readable typography."""
    delta_color = COLOR_SUCCESS if delta_positive else COLOR_DANGER
    delta_html = f'<span style="color: {delta_color}; font-weight: 700; margin-right: 6px;">{delta_text}</span>' if delta_text else ''
    border_style = f'border-left: 4px solid {border_accent};' if border_accent else ''

    footer_content = ""
    if footer_text or delta_text:
        footer_content = f'<div class="kpi-footer">{delta_html}<span style="color: {TEXT_SECONDARY}; font-weight: 500;">{footer_text or ""}</span></div>'

    html = f"""
    <div class="kpi-card" style="{border_style}">
        <div>
            <div class="kpi-label">{label}</div>
            <div class="kpi-value">{value}</div>
        </div>
        {footer_content}
    </div>
    """
    return clean_html(html)


def render_card_start(title: str, subtitle: Optional[str] = None, icon: Optional[str] = None) -> str:
    """Generate styled header for container card enclosing charts and components."""
    icon_html = f'<span style="margin-right: 8px; font-size: 1.15rem;">{icon}</span>' if icon else ''
    sub_html = f'<p style="font-size: 0.88rem; color: {TEXT_MUTED}; margin: 4px 0 0 0; font-weight: 500;">{subtitle}</p>' if subtitle else ''
    
    html = f"""
    <div style="border-bottom: 1px solid {BORDER_COLOR}; padding-bottom: 12px; margin-bottom: 14px;">
        <div style="font-size: 1.15rem; font-weight: 700; color: {TEXT_PRIMARY}; display: flex; align-items: center;">
            {icon_html}{title}
        </div>
        {sub_html}
    </div>
    """
    return clean_html(html)


def render_card_end() -> str:
    """Close the container card (noop when using native Streamlit container)."""
    return ""


def render_verdict_card(result: Dict[str, Any], threshold: float) -> str:
    """Generate verdict risk card for live URL analysis."""
    is_mal = result["is_malicious"]
    prob = result["malicious_probability"]
    
    if prob < 0.35:
        badge_class = "badge-safe"
        badge_text = "LIKELY LEGITIMATE"
        accent_color = COLOR_SUCCESS
        border_color = COLOR_SUCCESS
    elif prob < 0.65:
        badge_class = "badge-warning"
        badge_text = "MODERATE RISK / SUSPICIOUS"
        accent_color = COLOR_WARNING
        border_color = COLOR_WARNING
    else:
        badge_class = "badge-danger"
        badge_text = "CRITICAL THREAT / PHISHING"
        accent_color = COLOR_DANGER
        border_color = COLOR_DANGER

    html = f"""
    <div class="cyber-card" style="border-left: 5px solid {border_color};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <span style="font-size: 0.82rem; font-weight: 700; color: {TEXT_MUTED}; letter-spacing: 0.06em; text-transform: uppercase;">
                SCAN VERDICT
            </span>
            <span class="badge {badge_class}">{badge_text}</span>
        </div>
        
        <div style="font-size: 1.6rem; font-weight: 800; color: {accent_color}; margin-bottom: 10px;">
            {result['predicted_class']}
        </div>
        
        <div style="background-color: {BG_SURFACE}; border: 1px solid {BORDER_COLOR}; padding: 12px 16px; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 0.92rem; color: {TEXT_PRIMARY}; word-break: break-all; margin-bottom: 18px;">
            {result['url']}
        </div>
        
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; border-top: 1px solid {BORDER_COLOR}; padding-top: 16px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 600; color: {TEXT_MUTED}; text-transform: uppercase;">Threat Probability</div>
                <div style="font-size: 1.5rem; font-weight: 800; color: {accent_color};">{prob*100:.1f}%</div>
            </div>
            <div>
                <div style="font-size: 0.78rem; font-weight: 600; color: {TEXT_MUTED}; text-transform: uppercase;">Confidence Score</div>
                <div style="font-size: 1.5rem; font-weight: 800; color: {TEXT_PRIMARY};">{result['confidence']*100:.1f}%</div>
            </div>
            <div>
                <div style="font-size: 0.78rem; font-weight: 600; color: {TEXT_MUTED}; text-transform: uppercase;">Active Threshold</div>
                <div style="font-size: 1.5rem; font-weight: 800; color: {ACCENT_PRIMARY};">{threshold:.2f}</div>
            </div>
        </div>
    </div>
    """
    return clean_html(html)


def render_threat_indicator_card(risk_title: str, risk_label: str, desc: str) -> str:
    """Generate modular threat indicator card with high contrast."""
    risk_lower = risk_label.lower()
    if "high" in risk_lower or "critical" in risk_lower:
        card_class = "danger"
        badge_class = "badge-danger"
    elif "medium" in risk_lower or "moderate" in risk_lower:
        card_class = "warning"
        badge_class = "badge-warning"
    else:
        card_class = "success"
        badge_class = "badge-safe"

    html = f"""
    <div class="threat-card {card_class}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 1rem; font-weight: 700; color: {TEXT_PRIMARY};">{risk_title}</span>
            <span class="badge {badge_class}">{risk_label}</span>
        </div>
        <p style="font-size: 0.88rem; color: {TEXT_SECONDARY}; margin: 0; line-height: 1.5; font-weight: 400;">
            {desc}
        </p>
    </div>
    """
    return clean_html(html)


def render_model_card(
    name: str,
    model_type: str,
    acc: float,
    prec: float,
    rec: float,
    f1: float,
    train_time: float,
    is_best: bool = False
) -> str:
    """Generate comparative model specification card."""
    badge_html = f'<span class="badge badge-info" style="font-size: 0.75rem;">OPTIMAL (BEST)</span>' if is_best else f'<span class="badge badge-safe" style="font-size: 0.75rem;">READY</span>'
    border_accent = f'border: 2px solid {ACCENT_PRIMARY}; box-shadow: 0 4px 18px rgba(56, 189, 248, 0.2);' if is_best else f'border: 1px solid {BORDER_COLOR};'

    html = f"""
    <div class="cyber-card" style="{border_accent}">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 600; color: {TEXT_MUTED}; text-transform: uppercase;">{model_type}</div>
                <div style="font-size: 1.25rem; font-weight: 800; color: {TEXT_PRIMARY};">{name}</div>
            </div>
            {badge_html}
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 14px; border-top: 1px solid {BORDER_COLOR}; padding-top: 14px;">
            <div>
                <span style="font-size: 0.78rem; font-weight: 600; color: {TEXT_MUTED};">ACCURACY</span>
                <div style="font-size: 1.25rem; font-weight: 800; color: {ACCENT_PRIMARY};">{acc*100:.2f}%</div>
            </div>
            <div>
                <span style="font-size: 0.78rem; font-weight: 600; color: {TEXT_MUTED};">RECALL (MALICIOUS)</span>
                <div style="font-size: 1.25rem; font-weight: 800; color: {COLOR_DANGER};">{rec*100:.2f}%</div>
            </div>
            <div>
                <span style="font-size: 0.78rem; font-weight: 600; color: {TEXT_MUTED};">PRECISION</span>
                <div style="font-size: 1.25rem; font-weight: 800; color: {COLOR_SUCCESS};">{prec*100:.2f}%</div>
            </div>
            <div>
                <span style="font-size: 0.78rem; font-weight: 600; color: {TEXT_MUTED};">F1-SCORE</span>
                <div style="font-size: 1.25rem; font-weight: 800; color: {TEXT_PRIMARY};">{f1:.4f}</div>
            </div>
        </div>
        
        <div style="margin-top: 14px; font-size: 0.85rem; color: {TEXT_MUTED}; display: flex; justify-content: space-between; border-top: 1px solid {BORDER_COLOR}; padding-top: 10px;">
            <span>Training Time</span>
            <span style="color: {TEXT_PRIMARY}; font-weight: 700;">{train_time:.2f}s</span>
        </div>
    </div>
    """
    return clean_html(html)


def render_about_section_card(title: str, content_html: str, icon: str = "🛡️") -> str:
    """Generate structured section card for the About page."""
    html = f"""
    <div class="cyber-card" style="margin-bottom: 22px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 14px; border-bottom: 1px solid {BORDER_COLOR}; padding-bottom: 12px;">
            <span style="font-size: 1.4rem;">{icon}</span>
            <span style="font-size: 1.2rem; font-weight: 800; color: {TEXT_PRIMARY};">{title}</span>
        </div>
        <div style="font-size: 0.95rem; color: {TEXT_SECONDARY}; line-height: 1.65;">
            {content_html}
        </div>
    </div>
    """
    return clean_html(html)
