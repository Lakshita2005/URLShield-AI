"""
Global CSS Stylesheet for URLShield AI
Premium Cybersecurity SaaS Dashboard Design System - High Contrast & High Legibility
"""

from src.ui.theme import (
    BG_MAIN, BG_SIDEBAR, BG_CARD, BG_SURFACE,
    ACCENT_PRIMARY, ACCENT_SECONDARY,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    BORDER_COLOR, COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER
)

def get_global_css() -> str:
    """Return inject-ready CSS for Streamlit with high contrast and pixel-perfect layout."""
    return f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* --- GLOBAL APPLICATION RESET & BASE --- */
    html, body, [class*="css"] {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        color: {TEXT_PRIMARY};
    }}

    .stApp {{
        background-color: {BG_MAIN} !important;
        color: {TEXT_PRIMARY} !important;
    }}

    /* Main Container Padding & Clearance */
    .block-container {{
        max-width: 1440px !important;
        padding-top: 1.75rem !important;
        padding-bottom: 3.5rem !important;
        padding-left: 2.25rem !important;
        padding-right: 2.25rem !important;
    }}

    /* ELIMINATE FROZEN TOP HEADER BAR OVERLAY ENTIRELY */
    header[data-testid="stHeader"],
    div[data-testid="stDecoration"],
    div[data-testid="stToolbar"],
    #MainMenu,
    footer {{
        display: none !important;
        visibility: hidden !important;
        height: 0px !important;
        min-height: 0px !important;
        margin: 0 !important;
        padding: 0 !important;
        border: none !important;
        pointer-events: none !important;
    }}

    /* Pulse animation for live status badges */
    @keyframes live-pulse {{
        0% {{ box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.7); }}
        70% {{ box-shadow: 0 0 0 8px rgba(74, 222, 128, 0); }}
        100% {{ box-shadow: 0 0 0 0 rgba(74, 222, 128, 0); }}
    }}

    .pulsing-dot {{
        width: 9px;
        height: 9px;
        background-color: {COLOR_SUCCESS};
        border-radius: 50%;
        display: inline-block;
        animation: live-pulse 2s infinite;
    }}

    /* --- SIDEBAR CUSTOMIZATION --- */
    section[data-testid="stSidebar"] {{
        background-color: {BG_SIDEBAR} !important;
        border-right: 1px solid {BORDER_COLOR} !important;
        width: 320px !important;
    }}

    section[data-testid="stSidebar"] .block-container {{
        padding: 1.5rem 1.15rem !important;
    }}

    /* Hide standard circular radio input */
    section[data-testid="stSidebar"] [data-testid="stRadio"] > label {{
        display: none !important;
    }}

    section[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] {{
        gap: 4px !important;
    }}

    section[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label > div:first-child {{
        display: none !important;
    }}

    /* SaaS Navigation Pills */
    section[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"] {{
        background-color: transparent !important;
        padding: 11px 14px !important;
        border-radius: 9px !important;
        border: 1px solid transparent !important;
        transition: all 0.2s ease-in-out !important;
        margin-bottom: 3px !important;
        width: 100% !important;
        cursor: pointer !important;
    }}

    section[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"]:hover {{
        background-color: {BG_CARD} !important;
        border-color: {BORDER_COLOR} !important;
        transform: translateX(3px);
    }}

    /* Nav Item Label Text - Bright, Clear, High-Contrast */
    section[data-testid="stSidebar"] [data-testid="stRadio"] label p,
    section[data-testid="stSidebar"] [data-testid="stRadio"] label span {{
        color: {TEXT_SECONDARY} !important;
        font-size: 1rem !important;
        font-weight: 600 !important;
        margin: 0 !important;
        line-height: 1.4 !important;
    }}

    section[data-testid="stSidebar"] [data-testid="stRadio"] label:hover p {{
        color: {TEXT_PRIMARY} !important;
    }}

    /* Active Nav Item */
    section[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"][aria-checked="true"] {{
        background: linear-gradient(90deg, rgba(56, 189, 248, 0.22) 0%, rgba(30, 41, 59, 0.8) 100%) !important;
        border: 1px solid {ACCENT_PRIMARY} !important;
        border-left: 4px solid {ACCENT_PRIMARY} !important;
        box-shadow: 0 2px 12px rgba(56, 189, 248, 0.25) !important;
    }}

    section[data-testid="stSidebar"] [data-testid="stRadio"] label[data-baseweb="radio"][aria-checked="true"] p {{
        color: {ACCENT_PRIMARY} !important;
        font-weight: 700 !important;
    }}

    /* Widget Labels */
    .stWidgetLabel p,
    .stSelectbox label p,
    .stSlider label p,
    .stTextInput label p {{
        color: {TEXT_SECONDARY} !important;
        font-size: 0.88rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.04em !important;
        text-transform: uppercase !important;
        margin-bottom: 6px !important;
    }}

    /* --- TOP HEADER BANNER (NO OVERLAY, COMPLETE BREATHING ROOM) --- */
    .top-header-container {{
        background: linear-gradient(135deg, #1E293B 0%, #172554 100%);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 14px;
        padding: 26px 32px;
        margin-top: 4px;
        margin-bottom: 26px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35), 0 0 15px rgba(56, 189, 248, 0.08);
    }}

    .header-breadcrumb {{
        font-size: 0.85rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: {ACCENT_PRIMARY};
        margin-bottom: 6px;
    }}

    .header-title {{
        font-size: 2.2rem;
        font-weight: 800;
        color: {TEXT_PRIMARY};
        margin: 0;
        letter-spacing: -0.02em;
        line-height: 1.2;
    }}

    .header-subtitle {{
        font-size: 1.05rem;
        color: #CBD5E1;
        margin-top: 6px;
        margin-bottom: 0;
        line-height: 1.4;
    }}

    .header-badge {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background-color: rgba(74, 222, 128, 0.15);
        border: 1px solid rgba(74, 222, 128, 0.4);
        color: {COLOR_SUCCESS};
        padding: 8px 18px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }}

    /* --- REUSABLE CARDS & CONTAINERS --- */
    .cyber-card {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER_COLOR};
        border-radius: 14px;
        padding: 24px;
        height: 100%;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
        transition: all 0.25s ease-in-out;
    }}

    .cyber-card:hover {{
        border-color: {ACCENT_PRIMARY};
        transform: translateY(-3px);
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4), 0 0 16px rgba(56, 189, 248, 0.2);
    }}

    /* Card Wrapper around Charts */
    .chart-wrapper-card {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER_COLOR};
        border-radius: 14px;
        padding: 22px 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
        transition: all 0.25s ease-in-out;
    }}

    .chart-wrapper-card:hover {{
        border-color: rgba(56, 189, 248, 0.45);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35), 0 0 14px rgba(56, 189, 248, 0.15);
    }}

    .chart-header {{
        border-bottom: 1px solid {BG_SURFACE};
        padding-bottom: 14px;
        margin-bottom: 16px;
    }}

    .chart-body {{
        width: 100%;
    }}

    /* KPI metric card - Larger font, crisp contrast */
    .kpi-card {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER_COLOR};
        border-radius: 14px;
        padding: 22px 24px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        min-height: 140px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
        transition: all 0.25s ease-in-out;
    }}

    .kpi-card:hover {{
        transform: translateY(-3px);
        border-color: {ACCENT_PRIMARY};
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4), 0 0 18px rgba(56, 189, 248, 0.25);
    }}

    .kpi-label {{
        font-size: 0.88rem;
        font-weight: 700;
        color: {TEXT_MUTED};
        letter-spacing: 0.06em;
        text-transform: uppercase;
        margin-bottom: 8px;
    }}

    .kpi-value {{
        font-size: 2.35rem;
        font-weight: 800;
        color: {TEXT_PRIMARY};
        line-height: 1.1;
        margin-bottom: 12px;
        letter-spacing: -0.02em;
    }}

    .kpi-footer {{
        font-size: 0.92rem;
        color: {TEXT_SECONDARY};
        display: flex;
        align-items: center;
        border-top: 1px solid {BG_SURFACE};
        padding-top: 10px;
        margin-top: 4px;
        font-weight: 500;
    }}

    /* Threat Indicator Card */
    .threat-card {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER_COLOR};
        border-radius: 14px;
        padding: 20px 22px;
        margin-bottom: 16px;
        border-left: 5px solid {ACCENT_PRIMARY};
        transition: all 0.25s ease-in-out;
    }}

    .threat-card:hover {{
        transform: translateY(-2px);
        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.35);
    }}

    .threat-card.danger {{
        border-left-color: {COLOR_DANGER};
    }}

    .threat-card.warning {{
        border-left-color: {COLOR_WARNING};
    }}

    .threat-card.success {{
        border-left-color: {COLOR_SUCCESS};
    }}

    /* Status Badges */
    .badge {{
        display: inline-flex;
        align-items: center;
        padding: 5px 14px;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }}

    .badge-safe {{
        background-color: rgba(74, 222, 128, 0.16);
        border: 1px solid rgba(74, 222, 128, 0.45);
        color: {COLOR_SUCCESS};
    }}

    .badge-warning {{
        background-color: rgba(251, 191, 36, 0.16);
        border: 1px solid rgba(251, 191, 36, 0.45);
        color: {COLOR_WARNING};
    }}

    .badge-danger {{
        background-color: rgba(248, 113, 113, 0.16);
        border: 1px solid rgba(248, 113, 113, 0.45);
        color: {COLOR_DANGER};
    }}

    .badge-info {{
        background-color: rgba(56, 189, 248, 0.16);
        border: 1px solid rgba(56, 189, 248, 0.45);
        color: {ACCENT_PRIMARY};
    }}

    /* Section title */
    .section-title {{
        font-size: 1.35rem;
        font-weight: 700;
        color: {TEXT_PRIMARY};
        margin-top: 10px;
        margin-bottom: 18px;
        display: flex;
        align-items: center;
        gap: 10px;
        border-left: 4px solid {ACCENT_PRIMARY};
        padding-left: 14px;
    }}

    /* --- STREAMLIT WIDGETS OVERRIDES --- */
    /* Selectboxes and Dropdowns */
    [data-baseweb="select"] {{
        background-color: {BG_CARD} !important;
        border: 1px solid {BORDER_COLOR} !important;
        border-radius: 9px !important;
    }}

    [data-baseweb="select"] div,
    [data-baseweb="select"] span {{
        color: {TEXT_PRIMARY} !important;
        font-size: 0.98rem !important;
        font-weight: 500 !important;
    }}

    /* Text Inputs */
    .stTextInput > div > div > input {{
        background-color: {BG_CARD} !important;
        border: 1px solid {BORDER_COLOR} !important;
        color: {TEXT_PRIMARY} !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1rem !important;
        border-radius: 9px !important;
        padding: 12px 18px !important;
    }}

    .stTextInput > div > div > input:focus {{
        border-color: {ACCENT_PRIMARY} !important;
        box-shadow: 0 0 0 1px {ACCENT_PRIMARY} !important;
    }}

    /* Buttons */
    .stButton > button {{
        background: linear-gradient(135deg, #0284C7 0%, #0369A1 100%) !important;
        color: #FFFFFF !important;
        font-weight: 700 !important;
        font-size: 0.98rem !important;
        border: 1px solid rgba(56, 189, 248, 0.4) !important;
        border-radius: 9px !important;
        padding: 11px 24px !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 4px 14px rgba(2, 132, 199, 0.35) !important;
    }}

    .stButton > button:hover {{
        background: linear-gradient(135deg, #38BDF8 0%, #0284C7 100%) !important;
        box-shadow: 0 6px 20px rgba(56, 189, 248, 0.5) !important;
        transform: translateY(-2px) !important;
        color: #FFFFFF !important;
    }}

    /* Dataframe table styling */
    [data-testid="stDataFrame"] {{
        border: 1px solid {BORDER_COLOR} !important;
        border-radius: 12px !important;
        overflow: hidden !important;
    }}

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 8px;
        background-color: {BG_SIDEBAR};
        padding: 6px;
        border-radius: 12px;
        border: 1px solid {BORDER_COLOR};
    }}

    .stTabs [data-baseweb="tab"] {{
        background-color: transparent;
        color: {TEXT_SECONDARY};
        border-radius: 8px;
        padding: 10px 20px;
        font-size: 0.95rem;
        font-weight: 600;
        border: none;
    }}

    .stTabs [aria-selected="true"] {{
        background-color: {BG_CARD} !important;
        color: {ACCENT_PRIMARY} !important;
        font-weight: 700 !important;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.35);
    }}

    /* Native Streamlit Bordered Container as Interactive SaaS Card */
    [data-testid="stVerticalBlockBorderWrapper"] > div {{
        background-color: {BG_CARD} !important;
        border: 1px solid {BORDER_COLOR} !important;
        border-radius: 14px !important;
        padding: 22px 24px !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25) !important;
        transition: all 0.25s ease-in-out !important;
    }}

    [data-testid="stVerticalBlockBorderWrapper"] > div:hover {{
        border-color: rgba(56, 189, 248, 0.45) !important;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35), 0 0 14px rgba(56, 189, 248, 0.15) !important;
    }}

    /* Slider Customization */
    .stSlider [data-testid="stThumbValue"] {{
        color: {ACCENT_PRIMARY} !important;
        font-weight: 700 !important;
        font-size: 0.95rem !important;
    }}

    .stSlider [data-baseweb="slider"] div[role="slider"] {{
        background-color: {ACCENT_PRIMARY} !important;
        border: 2px solid #FFFFFF !important;
    }}

    /* Sidebar info box */
    .sidebar-info-box {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER_COLOR};
        border-radius: 12px;
        padding: 16px 18px;
        margin-top: 18px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }}
</style>
"""
