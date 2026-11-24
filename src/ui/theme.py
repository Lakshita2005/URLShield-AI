"""
Color Palette and Plotly Theme Configuration for URLShield AI
Enterprise Cybersecurity SaaS Design System - High Contrast & High Legibility
"""

import plotly.graph_objects as go

# --- COLOR SYSTEM SPECIFICATION (HIGH CONTRAST & MODERN SLATE NAVY) ---
BG_MAIN = "#0F172A"          # Tailwind Slate-900: Sleek, high-contrast slate-navy canvas
BG_SIDEBAR = "#090E1A"       # Deep slate grounding sidebar
BG_CARD = "#1E293B"          # Tailwind Slate-800: Elevated container card, distinct from canvas
BG_SURFACE = "#334155"       # Tailwind Slate-700: Secondary interactive surface / inputs / pills
ACCENT_PRIMARY = "#38BDF8"   # Electric Sky Cyan (Tailwind Sky-400)
ACCENT_SECONDARY = "#60A5FA" # Electric Blue (Tailwind Blue-400)
TEXT_PRIMARY = "#FFFFFF"     # 100% Pure White for maximum contrast & crispness
TEXT_SECONDARY = "#F1F5F9"   # Tailwind Slate-100: Bright, super legible body copy
TEXT_MUTED = "#94A3B8"       # Tailwind Slate-400: Clear, legible metadata
BORDER_COLOR = "#334155"     # Tailwind Slate-700: Clean, visible container borders
COLOR_SUCCESS = "#4ADE80"    # Emerald Green (Tailwind Green-400)
COLOR_WARNING = "#FBBF24"    # Amber Yellow (Tailwind Amber-400)
COLOR_DANGER = "#F87171"     # Coral Red (Tailwind Red-400)

# High-contrast model comparison palette
MODEL_PALETTE = ["#38BDF8", "#818CF8", "#4ADE80"]

CLASS_COLOR_MAP = {
    0: COLOR_SUCCESS,  # Legitimate / Benign
    1: COLOR_DANGER    # Malicious / Phishing
}


def apply_plotly_theme(fig: go.Figure, height: int = 340, show_legend: bool = True, margin: dict = None) -> go.Figure:
    """
    Apply unified dark cybersecurity theme to any Plotly figure.
    Uses transparent background, large legible typography, and crisp gridlines.
    """
    if margin is None:
        margin = dict(l=40, r=25, t=30, b=40)

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            size=14,
            color=TEXT_SECONDARY
        ),
        title_font=dict(
            family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            size=16,
            color=TEXT_PRIMARY,
            weight=700
        ),
        legend=dict(
            font=dict(color=TEXT_SECONDARY, size=13),
            bgcolor="rgba(30, 41, 59, 0.95)",
            bordercolor=BORDER_COLOR,
            borderwidth=1,
            orientation="h",
            yanchor="bottom",
            y=1.03,
            xanchor="right",
            x=1
        ) if show_legend else dict(visible=False),
        xaxis=dict(
            gridcolor="rgba(51, 65, 85, 0.7)",
            gridwidth=1,
            zerolinecolor=BORDER_COLOR,
            tickfont=dict(color=TEXT_SECONDARY, size=13, weight=500),
            title_font=dict(color=TEXT_PRIMARY, size=14, weight=600)
        ),
        yaxis=dict(
            gridcolor="rgba(51, 65, 85, 0.7)",
            gridwidth=1,
            zerolinecolor=BORDER_COLOR,
            tickfont=dict(color=TEXT_SECONDARY, size=13, weight=500),
            title_font=dict(color=TEXT_PRIMARY, size=14, weight=600)
        ),
        hoverlabel=dict(
            bgcolor="#1E293B",
            bordercolor=ACCENT_PRIMARY,
            font=dict(color=TEXT_PRIMARY, size=13, family="Inter", weight=600)
        ),
        height=height,
        margin=margin
    )
    return fig
