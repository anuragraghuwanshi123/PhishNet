import requests
import streamlit as st
import streamlit as st
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import json
import io
import warnings
warnings.filterwarnings('ignore')

# ============================================================
# API Config
# ============================================================
API_BASE      = "https://phishnet-t6pj.onrender.com"
TIMEOUT       = 60
MODEL_OPTIONS = ["Random Forest", "ANN", "SVM"]

# ============================================================
# Page Config
# ============================================================
st.set_page_config(
    page_title="PhishNet – Phishing Detector",
    layout="centered",
    page_icon="🛡️"
)

# ============================================================
# CSS — High-contrast dark navy theme, crisp readable text
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

:root {
    --bg:           #0d1117;
    --surface:      #161b22;
    --surface2:     #1c2330;
    --surface3:     #21293a;
    --border:       #2a3444;
    --border2:      #344055;
    --accent:       #58a6ff;
    --accent-dim:   #1f4068;
    --success:      #3fb950;
    --success-dim:  #1a3a25;
    --danger:       #f85149;
    --danger-dim:   #3a1a1a;
    --warn:         #e3b341;
    --warn-dim:     #3a2e00;
    --text:         #e6edf3;
    --text-dim:     #8b949e;
    --text-muted:   #6e7681;
    --white:        #ffffff;
}

html, body, [class*="css"] {
    font-family: 'Nunito', sans-serif !important;
    color: var(--text) !important;
}

.stApp {
    background-color: var(--bg);
    background-image:
        radial-gradient(ellipse 70% 35% at 20% 0%, rgba(88,166,255,0.06) 0%, transparent 50%),
        radial-gradient(ellipse 50% 30% at 80% 100%, rgba(63,185,80,0.04) 0%, transparent 50%);
}

#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 1.6rem; padding-bottom: 4rem; max-width: 880px; }

/* ── Force all text to be visible ── */
p, span, div, label, li, td, th, small {
    color: var(--text) !important;
}
h1, h2, h3, h4, h5, h6 { color: var(--white) !important; }
.stCaption p { color: var(--text-dim) !important; }

/* ── Hero ── */
.hero {
    text-align: center;
    padding: 2.8rem 1rem 2rem;
}
.hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    background: rgba(88,166,255,0.1);
    border: 1px solid rgba(88,166,255,0.25);
    color: var(--accent);
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    padding: 0.3rem 1rem;
    border-radius: 30px;
    margin-bottom: 1.1rem;
}
.hero-title {
    font-size: clamp(2.6rem, 7vw, 4rem);
    font-weight: 800;
    color: var(--white) !important;
    margin: 0 0 0.5rem;
    letter-spacing: -0.03em;
    line-height: 1.08;
}
.hero-title .accent { color: var(--accent); }
.hero-sub {
    font-size: 1rem;
    color: var(--text-dim) !important;
    font-weight: 400;
    margin: 0;
}
.hero-divider {
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--border2) 30%, var(--border2) 70%, transparent);
    margin: 2rem auto 0;
    width: 75%;
}

/* ── Section heading ── */
.sec-heading {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.2em;
    color: var(--accent) !important;
    text-transform: uppercase;
    margin: 1.8rem 0 0.9rem;
}
.sec-heading::after {
    content: '';
    flex: 1;
    height: 1px;
    background: linear-gradient(90deg, var(--border2), transparent);
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    padding: 4px !important;
    gap: 2px !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: var(--text-muted) !important;
    border-radius: 9px !important;
    font-size: 0.83rem !important;
    font-weight: 600 !important;
    padding: 0.45rem 1.1rem !important;
    border: none !important;
}
.stTabs [aria-selected="true"] {
    background: var(--surface3) !important;
    color: var(--accent) !important;
    box-shadow: 0 1px 6px rgba(0,0,0,0.4) !important;
}

/* ── Radio (model selector) ── */
div[data-testid="stRadio"] > div {
    display: flex !important;
    gap: 0.6rem !important;
    flex-wrap: wrap !important;
}
div[data-testid="stRadio"] label {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    color: var(--text-dim) !important;
    font-size: 0.84rem !important;
    font-weight: 600 !important;
    padding: 0.42rem 1.2rem !important;
    cursor: pointer !important;
    transition: all 0.18s !important;
}
div[data-testid="stRadio"] label:hover {
    border-color: var(--accent) !important;
    color: var(--accent) !important;
}

/* ── Inputs ── */
div[data-testid="stTextInput"] label,
div[data-testid="stNumberInput"] label {
    color: var(--text-dim) !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
}
div[data-testid="stTextInput"] input,
div[data-testid="stNumberInput"] input {
    background: var(--surface) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 9px !important;
    color: var(--white) !important;
    font-size: 0.92rem !important;
}
div[data-testid="stTextInput"] input:focus,
div[data-testid="stNumberInput"] input:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px rgba(88,166,255,0.15) !important;
}
div[data-testid="stNumberInput"] button {
    background: var(--surface2) !important;
    border-color: var(--border) !important;
    color: var(--accent) !important;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #1f6feb, #388bfd) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 9px !important;
    font-weight: 700 !important;
    font-size: 0.9rem !important;
    padding: 0.65rem 1.6rem !important;
    box-shadow: 0 4px 18px rgba(88,166,255,0.25) !important;
    width: 100% !important;
    transition: all 0.2s ease !important;
    letter-spacing: 0.02em !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #388bfd, #58a6ff) !important;
    box-shadow: 0 6px 26px rgba(88,166,255,0.4) !important;
    transform: translateY(-1px) !important;
    color: #ffffff !important;
}

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    background: var(--surface) !important;
    border: 1.5px dashed var(--border2) !important;
    border-radius: 10px !important;
}
[data-testid="stFileUploader"] label,
[data-testid="stFileUploader"] span,
[data-testid="stFileUploader"] p { color: var(--text-dim) !important; }

/* ── st.metric ── */
[data-testid="metric-container"] {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    padding: 1rem 1.2rem !important;
}
[data-testid="metric-container"] label { color: var(--text-dim) !important; font-size: 0.77rem !important; }
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: var(--white) !important;
    font-size: 1.7rem !important;
    font-weight: 800 !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* ── Dataframe ── */
[data-testid="stDataFrame"] { border-radius: 10px !important; overflow: hidden; }

/* ── Alerts ── */
div[data-testid="stAlert"] { border-radius: 10px !important; }

/* ── Checkbox ── */
div[data-testid="stCheckbox"] label { color: var(--text) !important; font-size: 0.9rem !important; font-weight: 600 !important; }

/* ── Spinner ── */
div[data-testid="stSpinner"] > div { border-top-color: var(--accent) !important; }

/* ── st.write / markdown text ── */
.stMarkdown p { color: var(--text) !important; }

/* ── Result card ── */
.result-card {
    border-radius: 16px;
    padding: 2rem 2.2rem;
    text-align: center;
    margin-top: 1.2rem;
    animation: riseIn 0.45s cubic-bezier(0.16,1,0.3,1);
}
@keyframes riseIn {
    from { opacity: 0; transform: translateY(16px) scale(0.97); }
    to   { opacity: 1; transform: translateY(0)    scale(1); }
}
.result-card.phishing {
    background: linear-gradient(140deg, #200a0a, #280d0d);
    border: 1px solid #5a1a1a;
    box-shadow: 0 0 60px rgba(248,81,73,0.1);
}
.result-card.legit {
    background: linear-gradient(140deg, #0a1f0d, #0d2410);
    border: 1px solid #1a4a22;
    box-shadow: 0 0 60px rgba(63,185,80,0.1);
}
.result-emoji  { font-size: 3.2rem; display: block; margin-bottom: 0.6rem; }
.result-label  { font-size: 1.85rem; font-weight: 800; margin: 0; letter-spacing: -0.02em; }
.result-label.phishing { color: #f85149 !important; }
.result-label.legit    { color: #3fb950 !important; }
.result-sub    { font-size: 0.82rem; color: var(--text-muted) !important; margin-top: 0.35rem; }

/* ── Risk badge ── */
.risk-badge {
    display: inline-block;
    padding: 0.32rem 1.1rem;
    border-radius: 30px;
    font-size: 0.76rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    margin-top: 0.8rem;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
}
.risk-critical { background: rgba(248,81,73,0.12);  color: #f85149 !important; border: 1px solid #5a1a1a; }
.risk-high     { background: rgba(227,179,65,0.12);  color: #e3b341 !important; border: 1px solid #5a4000; }
.risk-medium   { background: rgba(227,179,65,0.08);  color: #c9a030 !important; border: 1px solid #3a2e00; }
.risk-low      { background: rgba(63,185,80,0.12);   color: #3fb950 !important; border: 1px solid #1a4a22; }

/* ── Probability bars ── */
.prob-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 1.3rem 1.5rem;
    margin: 1rem 0 0;
}
.prob-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}
.prob-label { font-size: 0.83rem; font-weight: 600; color: var(--text) !important; }
.prob-value { font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; font-weight: 700; }
.prob-value.danger { color: #f85149 !important; }
.prob-value.safe   { color: #3fb950 !important; }
.prob-track {
    height: 10px;
    background: var(--surface3);
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 1rem;
}
.prob-fill {
    height: 100%;
    border-radius: 10px;
    transition: width 0.9s cubic-bezier(0.16,1,0.3,1);
}
.prob-fill.danger { background: linear-gradient(90deg, #c0392b, #f85149); }
.prob-fill.safe   { background: linear-gradient(90deg, #27ae60, #3fb950); }

/* ── Eval section card ── */
.eval-section-header {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 2rem 0 0.3rem;
    padding-bottom: 0.6rem;
    border-bottom: 1px solid var(--border);
}
.eval-section-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--white) !important;
}

/* ── Metric card grid ── */
.metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 0.75rem;
    margin: 0.8rem 0 1.4rem;
}
.metric-card {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1rem 0.8rem;
    text-align: center;
    transition: border-color 0.2s;
}
.metric-card:hover { border-color: var(--accent); }
.metric-card .mc-label {
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.14em;
    color: var(--text-muted) !important;
    text-transform: uppercase;
    margin-bottom: 0.3rem;
}
.metric-card .mc-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--accent) !important;
}

/* ── Summary table styling ── */
.summary-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
    margin: 0.6rem 0 1.4rem;
}
.summary-table th {
    background: var(--surface3);
    color: var(--text-dim) !important;
    font-size: 0.74rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 0.7rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border2);
}
.summary-table td {
    padding: 0.65rem 1rem;
    color: var(--text) !important;
    border-bottom: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.84rem;
}
.summary-table tr:hover td { background: var(--surface2); }
.summary-table .model-name { font-weight: 700; color: var(--white) !important; font-family: 'Nunito', sans-serif !important; }
.best-val { color: #3fb950 !important; font-weight: 700; }
</style>
""", unsafe_allow_html=True)

# ── Matplotlib dark style ──────────────────────────────────────
plt.rcParams.update({
    "figure.facecolor":  "#161b22",
    "axes.facecolor":    "#0d1117",
    "axes.edgecolor":    "#2a3444",
    "axes.labelcolor":   "#8b949e",
    "xtick.color":       "#6e7681",
    "ytick.color":       "#6e7681",
    "text.color":        "#e6edf3",
    "grid.color":        "#21293a",
    "legend.facecolor":  "#161b22",
    "legend.edgecolor":  "#2a3444",
})

# ============================================================
# Helper functions
# ============================================================
FEATURE_NAMES = [
    "UsingIP","LongURL","ShortURL","Symbol@","Redirecting//",
    "PrefixSuffix-","SubDomains","HTTPS","DomainRegLen","Favicon",
    "NonStdPort","HTTPSDomainURL","RequestURL","AnchorURL",
    "LinksInScriptTags","ServerFormHandler","InfoEmail","AbnormalURL",
    "WebsiteForwarding","StatusBarCust","DisableRightClick",
    "UsingPopupWindow","IframeRedirection","AgeofDomain","DNSRecording",
    "WebsiteTraffic","PageRank","GoogleIndex","LinksPointingToPage",
    "StatsReport"
]

def parse_api_response(raw):
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return {"error": raw}
    return raw

def normalise_prob(val):
    """Convert any probability value to [0.0, 1.0]."""
    try:
        v = float(val)
    except (TypeError, ValueError):
        return 0.5
    if 0.0 <= v <= 1.0:
        return v
    if 1.0 < v <= 100.0:
        return v / 100.0
    return max(0.0, min(1.0, v / 100.0))

def risk_badge(prob):
    if prob > 0.80:
        return '<span class="risk-badge risk-critical">● CRITICAL</span>'
    elif prob > 0.60:
        return '<span class="risk-badge risk-high">● HIGH</span>'
    elif prob > 0.40:
        return '<span class="risk-badge risk-medium">● MEDIUM</span>'
    else:
        return '<span class="risk-badge risk-low">● LOW</span>'

def show_result(prob):
    prob     = normalise_prob(prob)
    is_phish = prob > 0.5
    cls      = "phishing" if is_phish else "legit"
    emoji    = "🚨" if is_phish else "✅"
    txt      = "Phishing Detected" if is_phish else "Legitimate Website"
    phish_pct = prob * 100
    legit_pct = (1 - prob) * 100

    st.markdown(f"""
    <div class="result-card {cls}">
        <span class="result-emoji">{emoji}</span>
        <p class="result-label {cls}">{txt}</p>
        <p class="result-sub">Analysed with {model_choice}</p>
        {risk_badge(prob)}
    </div>
    """, unsafe_allow_html=True)

    danger_bar_color = "danger" if is_phish else "safe"
    safe_bar_color   = "safe"

    st.markdown(f"""
    <div class="prob-wrap">
        <div class="prob-row">
            <span class="prob-label">🚨 Phishing Probability</span>
            <span class="prob-value danger">{phish_pct:.1f}%</span>
        </div>
        <div class="prob-track">
            <div class="prob-fill danger" style="width:{phish_pct:.1f}%"></div>
        </div>
        <div class="prob-row">
            <span class="prob-label">✅ Legitimate Probability</span>
            <span class="prob-value safe">{legit_pct:.1f}%</span>
        </div>
        <div class="prob-track">
            <div class="prob-fill safe" style="width:{legit_pct:.1f}%"></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def explain_df(features_dict):
    rows = []
    for feat, val in features_dict.items():
        if val == -1:   meaning = "🚨 Phishing"
        elif val == 0:  meaning = "⚠️ Suspicious"
        else:           meaning = "✅ Legitimate"
        rows.append({"Feature": feat, "Value": val, "Meaning": meaning})
    return pd.DataFrame(rows)

def fetch_image_from_api(path):
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=TIMEOUT)
        r.raise_for_status()
        return r.content
    except Exception:
        return None

def fetch_csv_from_api(path):
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=TIMEOUT)
        r.raise_for_status()
        return pd.read_csv(io.StringIO(r.text))
    except Exception:
        return None

def render_metric_cards(metrics_dict):
    """Render a HTML metric grid for evaluation."""
    cards_html = '<div class="metric-grid">'
    for label, val in metrics_dict.items():
        try:
            fval = float(val)
            # If ≤1 treat as fraction → convert to %, else already %
            if fval <= 1.0:
                display = f"{fval*100:.2f}%"
            else:
                display = f"{fval:.2f}%"
        except Exception:
            display = str(val)
        nice_label = label.replace("_"," ").title()
        cards_html += f"""
        <div class="metric-card">
            <div class="mc-label">{nice_label}</div>
            <div class="mc-value">{display}</div>
        </div>"""
    cards_html += '</div>'
    st.markdown(cards_html, unsafe_allow_html=True)

def eval_section(icon, title):
    """Render an evaluation section header."""
    st.markdown(f"""
    <div class="eval-section-header">
        <span style="font-size:1.3rem">{icon}</span>
        <span class="eval-section-title">{title}</span>
    </div>
    """, unsafe_allow_html=True)

def extract_scalar_metrics(data):
    """
    Extract scalar performance metrics from an eval data dict.
    Checks both inline keys and the model_summary CSV.
    Returns a dict {key: float}.
    """
    scalar_keys = ["accuracy", "precision", "recall", "f1_score", "f1", "auc", "roc_auc"]
    scalars = {}
    # 1. Inline keys in the response dict
    for k in scalar_keys:
        if k in data:
            try:
                scalars[k] = float(data[k])
            except Exception:
                pass
    # 2. Fall back to model_summary CSV
    if not scalars:
        rpts = data.get("reports", {})
        summary_path = rpts.get("model_summary")
        if summary_path:
            df_ms = fetch_csv_from_api(summary_path)
            if df_ms is not None:
                for col in df_ms.columns:
                    if col.lower() in scalar_keys:
                        try:
                            scalars[col.lower()] = float(df_ms[col].iloc[0])
                        except Exception:
                            pass
    return scalars

# ============================================================
# HERO
# ============================================================
st.markdown("""
<div class="hero">
    <div class="hero-badge">🛡️ &nbsp;AI-Powered Security</div>
    <h1 class="hero-title">Phish<span class="accent">Net</span></h1>
    <p class="hero-sub">Detect phishing websites instantly with machine learning &amp; deep learning</p>
    <div class="hero-divider"></div>
</div>
""", unsafe_allow_html=True)

# ============================================================
# Model Selector
# ============================================================
st.markdown('<div class="sec-heading">Active Model</div>', unsafe_allow_html=True)
model_choice = st.radio("Model", MODEL_OPTIONS, horizontal=True, label_visibility="collapsed")

# ============================================================
# TABS
# ============================================================
tab1, tab2, tab3, tab4 = st.tabs([
    "🔗 URL Auto-Scan",
    "✍️ Manual Features",
    "📤 Batch CSV",
    "📊 Model Evaluation"
])

# ──────────────────────────────────────────────────────────────
# TAB 1 — URL Auto-Scan
# ──────────────────────────────────────────────────────────────
with tab1:
    st.markdown('<div class="sec-heading">Automatic URL Analysis</div>', unsafe_allow_html=True)
    st.caption("Enter any URL — features are extracted on the server and fed into your chosen model.")

    url_input = st.text_input("URL to scan", placeholder="https://www.example.com", label_visibility="collapsed")

    if st.button("🔍 Analyze URL", key="analyze_url"):
        if not url_input.strip():
            st.warning("⚠️ Please enter a URL first.")
        else:
            with st.spinner("Extracting features & running prediction… (~15 s on first call)"):
                try:
                    resp = requests.post(
                        f"{API_BASE}/predict/url",
                        json={"url": url_input.strip(), "model_name": model_choice},
                        timeout=TIMEOUT
                    )
                    resp.raise_for_status()
                    data = parse_api_response(resp.json())

                    if isinstance(data, dict):
                        raw_prob     = data.get("phishing_probability",
                                       data.get("phishing_prob",
                                       data.get("probability", 0.5)))
                        features_raw = data.get("features", {})
                    else:
                        raw_prob     = 1.0 if "phish" in str(data).lower() else 0.0
                        features_raw = {}

                    show_result(raw_prob)

                    if features_raw:
                        st.markdown('<div class="sec-heading">Extracted Features</div>', unsafe_allow_html=True)
                        feat_df = explain_df(features_raw)
                        st.dataframe(feat_df, use_container_width=True)

                        dangerous  = (feat_df["Value"] == -1).sum()
                        suspicious = (feat_df["Value"] ==  0).sum()
                        safe       = (feat_df["Value"] ==  1).sum()
                        c1, c2, c3 = st.columns(3)
                        c1.metric("🚨 Dangerous",  int(dangerous))
                        c2.metric("⚠️ Suspicious", int(suspicious))
                        c3.metric("✅ Safe",        int(safe))

                        risky = feat_df[feat_df["Value"] == -1]["Feature"].head(5).tolist()
                        if risky:
                            st.warning("Top risky features: " + ", ".join(risky))

                except requests.exceptions.Timeout:
                    st.error("⏳ Request timed out. Retry in ~30 s.")
                except requests.exceptions.HTTPError as e:
                    st.error(f"HTTP {e.response.status_code}: {e.response.text}")
                except Exception as e:
                    st.error(f"⚠️ Error: {e}")


# ──────────────────────────────────────────────────────────────
# TAB 2 — Manual Features
# ──────────────────────────────────────────────────────────────
with tab2:
    st.markdown('<div class="sec-heading">Manual Feature Input</div>', unsafe_allow_html=True)
    st.caption("Values: **1** = Legitimate &nbsp;|&nbsp; **0** = Suspicious &nbsp;|&nbsp; **−1** = Phishing")

    cols_ui    = st.columns(3)
    user_input = []
    for i, name in enumerate(FEATURE_NAMES):
        with cols_ui[i % 3]:
            val = st.number_input(name, min_value=-1, max_value=1, value=0, step=1, key=f"feat_{i}")
            user_input.append(int(val))

    if st.button("🔎 Predict", key="predict_manual"):
        with st.spinner("Running prediction…"):
            try:
                resp = requests.post(
                    f"{API_BASE}/predict/manual",
                    json={"features": user_input},
                    timeout=TIMEOUT
                )
                resp.raise_for_status()
                data = parse_api_response(resp.json())

                if isinstance(data, dict):
                    raw_prob = data.get("phishing_probability",
                               data.get("phishing_prob",
                               data.get("probability", 0.5)))
                else:
                    raw_prob = 1.0 if "phish" in str(data).lower() else 0.0

                show_result(raw_prob)

            except requests.exceptions.Timeout:
                st.error("⏳ Timed out. Retry in ~30 s.")
            except requests.exceptions.HTTPError as e:
                st.error(f"HTTP {e.response.status_code}: {e.response.text}")
            except Exception as e:
                st.error(f"⚠️ Error: {e}")


# ──────────────────────────────────────────────────────────────
# TAB 3 — Batch CSV
# ──────────────────────────────────────────────────────────────
with tab3:
    st.markdown('<div class="sec-heading">Batch CSV Prediction</div>', unsafe_allow_html=True)
    st.caption("Upload a CSV with **30 feature columns**. The server processes every row.")

    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded_file is not None:
        df_preview = pd.read_csv(uploaded_file)
        st.write(f"**Preview** — {len(df_preview)} rows × {df_preview.shape[1]} columns")
        st.dataframe(df_preview.head(5), use_container_width=True)

        if st.button("🚀 Run Batch Prediction", key="batch_predict"):
            uploaded_file.seek(0)
            with st.spinner(f"Processing {len(df_preview)} rows…"):
                try:
                    resp = requests.post(
                        f"{API_BASE}/predict/batch",
                        params={"model_name": model_choice},
                        files={"file": ("batch.csv", uploaded_file, "text/csv")},
                        timeout=max(TIMEOUT, len(df_preview) * 2)
                    )
                    resp.raise_for_status()
                    data = parse_api_response(resp.json())

                    if isinstance(data, list):
                        result_df = pd.DataFrame(data)
                    elif isinstance(data, dict) and "predictions" in data:
                        result_df = pd.DataFrame(data["predictions"])
                    elif isinstance(data, dict) and "results" in data:
                        result_df = pd.DataFrame(data["results"])
                    else:
                        result_df = (pd.DataFrame([data]) if isinstance(data, dict)
                                     else pd.DataFrame({"result": [str(data)]}))

                    # Normalise probability columns → show as %
                    for col in result_df.columns:
                        if "prob" in col.lower() or "probability" in col.lower():
                            result_df[col] = result_df[col].apply(
                                lambda x: f"{normalise_prob(x)*100:.2f}%"
                            )

                    st.success(f"✅ Predictions complete for {len(result_df)} rows.")
                    st.dataframe(result_df, use_container_width=True)
                    st.download_button("📥 Download Results",
                                       result_df.to_csv(index=False).encode("utf-8"),
                                       "phishing_predictions.csv", "text/csv")

                except requests.exceptions.Timeout:
                    st.error("⏳ Timed out. Try a smaller file or retry.")
                except requests.exceptions.HTTPError as e:
                    st.error(f"HTTP {e.response.status_code}: {e.response.text}")
                except Exception as e:
                    st.error(f"⚠️ Error: {e}")


# ──────────────────────────────────────────────────────────────
# TAB 4 — Model Evaluation  (matches deployed screenshot exactly)
# ──────────────────────────────────────────────────────────────
with tab4:

    if "eval_data" not in st.session_state:
        st.session_state.eval_data = {}

    if st.button("📊 Load Evaluation", key="load_eval"):
        with st.spinner(f"Fetching evaluation for {model_choice}…"):
            try:
                resp = requests.get(
                    f"{API_BASE}/model/evaluation",
                    params={"model_name": model_choice},
                    timeout=TIMEOUT
                )
                resp.raise_for_status()
                st.session_state.eval_data[model_choice] = parse_api_response(resp.json())
                st.success(f"✅ Evaluation loaded for **{model_choice}**")
            except requests.exceptions.Timeout:
                st.error("⏳ Timed out. Retry in ~30 s.")
            except requests.exceptions.HTTPError as e:
                st.error(f"HTTP {e.response.status_code}: {e.response.text}")
            except Exception as e:
                st.error(f"⚠️ Error: {e}")

    data = st.session_state.eval_data.get(model_choice)

    if data and isinstance(data, dict):
        reports = data.get("reports", {})

        # ── 📈 ROC Curve ──────────────────────────────────────
        st.header("📈 ROC Curve")
        show_roc = st.checkbox("Show ROC Curve for Test Set", key="cb_roc", value=False)
        if show_roc:
            roc_path = reports.get("roc_curve")
            if roc_path:
                img = fetch_image_from_api(roc_path)
                if img:
                    st.image(img, use_container_width=True)
                else:
                    st.warning("Could not load ROC curve image from API.")
            else:
                fpr     = data.get("fpr", [])
                tpr     = data.get("tpr", [])
                auc_val = data.get("auc", data.get("roc_auc"))
                if fpr and tpr:
                    fig, ax = plt.subplots(figsize=(7, 4.5))
                    lbl = f"ROC curve (AUC = {auc_val:.2f})" if auc_val else "ROC curve"
                    ax.plot(fpr, tpr, color="#e3743a", lw=2.5, label=lbl)
                    ax.plot([0,1],[0,1], color="#4466aa", lw=1.5, linestyle="--")
                    ax.set_xlabel("False Positive Rate")
                    ax.set_ylabel("True Positive Rate")
                    ax.set_title(f"ROC Curve – {model_choice}", fontsize=13, pad=10)
                    ax.legend(loc="lower right")
                    ax.grid(True, alpha=0.2)
                    plt.tight_layout()
                    st.pyplot(fig)
                    plt.close(fig)
                else:
                    st.info("No ROC curve data available for this model.")

        # ── 📋 Confusion Matrix & Classification Report ───────
        st.header("📋 Confusion Matrix & Classification Report")
        show_cm = st.checkbox("Show Confusion Matrix and Classification Report", key="cb_cm", value=False)
        if show_cm:
            # Classification report — from inline dict first
            if "classification_report" in data:
                st.markdown("### Classification Report")
                report = data["classification_report"]
                if isinstance(report, dict):
                    st.dataframe(
                        pd.DataFrame(report).transpose().style.format("{:.4f}"),
                        use_container_width=True
                    )
                else:
                    st.text(report)
            else:
                # Fall back to model_summary CSV
                summary_path = reports.get("model_summary")
                if summary_path:
                    df_s = fetch_csv_from_api(summary_path)
                    if df_s is not None and not df_s.empty:
                        st.markdown("### Classification Report")
                        st.dataframe(
                            df_s.style.format(
                                {c: "{:.4f}" for c in df_s.select_dtypes("number").columns}
                            ),
                            use_container_width=True
                        )

            # Confusion matrix — image from API first, then inline array
            cm_path = reports.get("confusion_matrix")
            if cm_path:
                img = fetch_image_from_api(cm_path)
                if img:
                    st.image(img, use_container_width=True)
            elif "confusion_matrix" in data:
                cm = np.array(data["confusion_matrix"])
                fig, ax = plt.subplots(figsize=(5, 4))
                im = ax.imshow(cm, cmap="Blues")
                ax.set_xticks([0,1]); ax.set_yticks([0,1])
                ax.set_xticklabels(["Phishing","Legitimate"])
                ax.set_yticklabels(["Phishing","Legitimate"])
                ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
                ax.set_title(f"Confusion Matrix – {model_choice}")
                for i in range(2):
                    for j in range(2):
                        ax.text(j, i, str(cm[i,j]), ha="center", va="center",
                                color="white", fontsize=14, fontweight="bold")
                plt.colorbar(im, ax=ax); plt.tight_layout()
                st.pyplot(fig)
                plt.close(fig)

    elif data:
        st.info(str(data))

    # ── 📊 Final Model Performance Summary ───────────────────
    st.header("📊 Final Model Performance Summary")
    show_summary = st.checkbox("Show Summary Comparison for All Models", key="cb_summary", value=False)

    if show_summary:
        # Auto-fetch any missing models silently
        missing = [m for m in MODEL_OPTIONS if m not in st.session_state.eval_data]
        if missing:
            with st.spinner("Loading all model data…"):
                for m in missing:
                    try:
                        r = requests.get(f"{API_BASE}/model/evaluation",
                                         params={"model_name": m}, timeout=TIMEOUT)
                        r.raise_for_status()
                        st.session_state.eval_data[m] = parse_api_response(r.json())
                    except Exception as e:
                        st.session_state.eval_data[m] = {"error": str(e)}

        # ── Only render once ALL models are available ─────────
        all_fetched = all(m in st.session_state.eval_data for m in MODEL_OPTIONS)
        if not all_fetched:
            st.info("Could not load all model data. Please try again.")
        else:
            # Build rows
            rows = []
            for m in MODEL_OPTIONS:
                d = st.session_state.eval_data.get(m, {})
                if not isinstance(d, dict) or "error" in d:
                    continue
                scalars = extract_scalar_metrics(d)
                if scalars:
                    row = {"Model": m}
                    row.update(scalars)
                    rows.append(row)

            if not rows:
                st.warning("No metric data found for any model.")
            else:
                # Normalise into display DataFrame
                display_rows = []
                for row in rows:
                    dr = {"Model": row["Model"]}
                    auc_v = row.get("auc", row.get("roc_auc"))
                    if auc_v is not None:
                        dr["AUC Score"] = float(auc_v)
                    acc_v = row.get("accuracy")
                    if acc_v is not None:
                        dr["Accuracy (%)"] = float(acc_v) * 100 if float(acc_v) <= 1.0 else float(acc_v)
                    for k, label in [("precision","Precision"), ("recall","Recall"),
                                     ("f1_score","F1-Score"), ("f1","F1-Score")]:
                        if k in row and label not in dr:
                            dr[label] = float(row[k])
                    display_rows.append(dr)

                cmp_df = pd.DataFrame(display_rows).set_index("Model")

                # Plain st.dataframe — matches screenshot exactly
                st.dataframe(cmp_df, use_container_width=True)

                # ── Bar chart — All Metrics Overview ─────────
                all_metric_cols = list(cmp_df.columns)
                if all_metric_cols and not cmp_df.empty:
                    cmp_plot = cmp_df[all_metric_cols].copy()
                    for c in cmp_plot.columns:
                        try:
                            if cmp_plot[c].max() <= 1.0:
                                cmp_plot[c] = cmp_plot[c] * 100
                        except Exception:
                            pass

                    bar_palette = ["#6e7dff", "#3fb950", "#e3743a", "#e3b341", "#c971e0"]
                    plot_models = list(cmp_plot.index)
                    x     = np.arange(len(plot_models))
                    all_c = list(cmp_plot.columns)
                    w     = 0.75 / max(len(all_c), 1)

                    fig, ax = plt.subplots(figsize=(11, 5.5))
                    legend_patches = []

                    for i, (col, color) in enumerate(zip(all_c, bar_palette)):
                        vals   = cmp_plot[col].astype(float).values
                        offset = x + i * w - (len(all_c) - 1) * w / 2
                        bars   = ax.bar(offset, vals, w * 0.88,
                                        color=color, alpha=0.9, edgecolor="none", zorder=3)
                        legend_patches.append(mpatches.Patch(color=color, label=col))
                        for bar in bars:
                            h = bar.get_height()
                            ax.annotate(f"{h:.1f}",
                                        xy=(bar.get_x() + bar.get_width() / 2, h),
                                        xytext=(0, 4), textcoords="offset points",
                                        ha="center", va="bottom",
                                        fontsize=7.5, color="#e6edf3", fontweight="600")

                    ax.set_xticks(x)
                    ax.set_xticklabels(plot_models, fontsize=11, fontweight="600")
                    ax.set_xlabel("Model", fontsize=10, labelpad=8)
                    ax.set_ylabel("Score (%)", fontsize=10, labelpad=8)
                    ax.set_title("Model Comparison: Metrics Overview",
                                 fontsize=13, pad=12, fontweight="700")
                    ax.legend(handles=legend_patches, framealpha=0.7, fontsize=8.5,
                              loc="lower right")
                    ax.grid(axis="y", linestyle="--", alpha=0.2, zorder=0)
                    ax.spines[["top","right"]].set_visible(False)
                    ax.set_ylim(0, 110)
                    plt.tight_layout(pad=1.5)
                    st.pyplot(fig)
                    plt.close(fig)