import streamlit as st
import pandas as pd
from data_fetcher import fetch_cve_data, get_sample_data
from ml_classifier import get_threat_category, train_severity_model, predict_severity
from visualizations import (severity_donut, daily_trend,
                             category_bar, score_histogram,
                             severity_over_time)

# ── PAGE CONFIG ───────────────────────────────────────────────
st.set_page_config(
    page_title="CyberPulse | Cyber Intelligence",
    page_icon="⛊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── CUSTOM CSS ────────────────────────────────────────────────
st.markdown("""
<style>
/* Import font */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

/* Global */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Background */
.stApp {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1117 50%, #0a0e1a 100%);
}

/* Hide default header */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1117 0%, #161b22 100%);
    border-right: 1px solid #21262d;
}

[data-testid="stSidebar"] .stMarkdown h1,
[data-testid="stSidebar"] .stMarkdown h2,
[data-testid="stSidebar"] .stMarkdown h3 {
    color: #58a6ff;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #161b22 0%, #1c2333 100%);
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 1rem 1.2rem;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}

[data-testid="stMetric"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(88,166,255,0.15);
    border-color: #58a6ff;
}

[data-testid="stMetricLabel"] {
    color: #8b949e !important;
    font-size: 13px !important;
    font-weight: 500 !important;
}

[data-testid="stMetricValue"] {
    color: #f0f6fc !important;
    font-size: 28px !important;
    font-weight: 700 !important;
}

/* Chart containers */
[data-testid="stPlotlyChart"] {
    background: linear-gradient(135deg, #161b22 0%, #1c2333 100%);
    border: 1px solid #21262d;
    border-radius: 16px;
    padding: 0.5rem;
    transition: box-shadow 0.2s ease;
}

[data-testid="stPlotlyChart"]:hover {
    box-shadow: 0 4px 20px rgba(88,166,255,0.1);
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #1f6feb 0%, #388bfd 100%);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 0.5rem 1.5rem;
    font-weight: 600;
    font-size: 14px;
    transition: all 0.2s ease;
    width: 100%;
}

.stButton > button:hover {
    background: linear-gradient(135deg, #388bfd 0%, #58a6ff 100%);
    transform: translateY(-1px);
    box-shadow: 0 4px 15px rgba(56,139,253,0.4);
}

/* Text area */
.stTextArea textarea {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    color: #f0f6fc;
    font-family: 'Inter', sans-serif;
}

.stTextArea textarea:focus {
    border-color: #58a6ff;
    box-shadow: 0 0 0 3px rgba(88,166,255,0.1);
}

/* Divider */
hr {
    border-color: #21262d;
    margin: 1.5rem 0;
}

/* Success/Info/Warning boxes */
.stSuccess {
    background: rgba(35,134,54,0.15);
    border: 1px solid #238636;
    border-radius: 8px;
}

.stInfo {
    background: rgba(31,111,235,0.15);
    border: 1px solid #1f6feb;
    border-radius: 8px;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border: 1px solid #21262d;
    border-radius: 12px;
    overflow: hidden;
}

/* Slider */
.stSlider [data-baseweb="slider"] {
    padding-top: 1rem;
}

/* Multiselect */
.stMultiSelect [data-baseweb="select"] {
    background: #161b22;
    border-color: #21262d;
}

/* Spinner */
.stSpinner {
    color: #58a6ff;
}

/* Section headers */
.section-header {
    font-size: 18px;
    font-weight: 600;
    color: #f0f6fc;
    margin: 1.5rem 0 1rem 0;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid #1f6feb;
    display: inline-block;
}

/* Badge */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
}

.badge-critical { background: rgba(248,81,73,0.2); color: #f85149; border: 1px solid #f85149; }
.badge-high     { background: rgba(210,153,34,0.2); color: #d2991c; border: 1px solid #d2991c; }
.badge-medium   { background: rgba(227,179,65,0.2); color: #e3b341; border: 1px solid #e3b341; }
.badge-low      { background: rgba(63,185,80,0.2);  color: #3fb950; border: 1px solid #3fb950; }
</style>
""", unsafe_allow_html=True)


# ── HEADER BANNER ─────────────────────────────────────────────
st.markdown("""
<div style="
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%);
    border: 1px solid #21262d;
    border-radius: 16px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
">
    <div style="
        position: absolute; top: 0; left: 0; right: 0; bottom: 0;
        background: radial-gradient(ellipse at 20% 50%, rgba(31,111,235,0.08) 0%, transparent 60%),
                    radial-gradient(ellipse at 80% 50%, rgba(248,81,73,0.05) 0%, transparent 60%);
    "></div>
    <div style="position: relative; z-index: 1;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
            <span style="font-size: 32px;">⛊</span>
            <h1 style="
                margin: 0;
                font-size: 28px;
                font-weight: 700;
                background: linear-gradient(135deg, #58a6ff, #f0f6fc);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            ">ThreatLens</h1>
            <span style="
                background: rgba(31,111,235,0.2);
                color: #58a6ff;
                border: 1px solid #1f6feb;
                border-radius: 20px;
                padding: 2px 12px;
                font-size: 12px;
                font-weight: 600;
            ">LIVE</span>
        </div>
        <p style="margin: 0; color: #8b949e; font-size: 15px;">
            Real-time Cybersecurity Threat Intelligence Dashboard
            &nbsp;·&nbsp; Powered by NVD CVE API
            &nbsp;·&nbsp; ML-Powered Classification
        </p>
    </div>
</div>
""", unsafe_allow_html=True)


# ── SIDEBAR ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 1rem 0 1.5rem 0;">
        <div style="font-size: 40px; margin-bottom: 8px;">⛊</div>
        <div style="font-size: 18px; font-weight: 700; color: #58a6ff;">ThreatLens</div>
        <div style="font-size: 12px; color: #8b949e;">Cyber Intelligence Platform</div>
    </div>
    <hr style="border-color: #21262d; margin-bottom: 1.5rem;">
    """, unsafe_allow_html=True)

    st.markdown("**⚙️ Data Controls**")
    days = st.slider("Days of data", 7, 365, 30)

    st.markdown("<br>**🔍 Severity Filter**", unsafe_allow_html=True)
    severity_filter = st.multiselect(
        "",
        ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"],
        default=["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]
    )

    st.markdown("<br>", unsafe_allow_html=True)
    fetch_btn = st.button(" ↻ Refresh Data")

    st.markdown("""
    <hr style="border-color: #21262d; margin: 1.5rem 0;">
    <div style="font-size: 12px; color: #8b949e; text-align: center;">
        Data source: NVD CVE API<br>
        Auto-refreshes on filter change
    </div>
    """, unsafe_allow_html=True)


# ── LOAD DATA ─────────────────────────────────────────────────
with st.spinner("🔍 Fetching threat intelligence data..."):
    try:
        df = fetch_cve_data(days_back=days)
        if df is None or len(df) == 0:
            st.warning("⚠︎ API unavailable :( showing sample data")
            df = get_sample_data(days)
    except Exception as e:
        st.error(f"Error: {e}")
        df = get_sample_data(days)

df["Category"] = df["Description"].apply(get_threat_category)
df_filtered = df[df["Severity"].isin(severity_filter)]

if len(df_filtered) == 0:
    st.warning("No data matches filters. Try selecting more severity levels.")
    st.stop()

# ── TRAIN ML ──────────────────────────────────────────────────
with st.spinner("🤖 Training ML classifier..."):
    model, vectorizer = train_severity_model(df_filtered)

# ── STATUS BAR ────────────────────────────────────────────────
col_s1, col_s2, col_s3 = st.columns([2,2,1])
with col_s1:
    source = "🟢 Live NVD Data" if df['Source'].iloc[0] == 'NVD' else "🟡 Sample Data"
    st.success(f"{source} · {len(df_filtered)} CVEs loaded")
with col_s3:
    st.markdown(f"<div style='text-align:right; color:#8b949e; font-size:13px; padding-top:8px;'>Last {days} days</div>",
                unsafe_allow_html=True)

# ── KPI METRICS ───────────────────────────────────────────────
st.markdown("<div class='section-header'>📊 Key Metrics</div>", unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("🔢 Total CVEs",       len(df_filtered))
k2.metric("🔴 Critical",         len(df_filtered[df_filtered['Severity']=='CRITICAL']))
k3.metric("🟠 High",             len(df_filtered[df_filtered['Severity']=='HIGH']))
k4.metric("📊 Avg CVSS Score",   round(df_filtered['Score'].mean(), 1) if df_filtered['Score'].notna().any() else "N/A")
k5.metric("🗂️ Categories",       df_filtered['Category'].nunique())

st.markdown("<br>", unsafe_allow_html=True)
st.divider()

# ── CHARTS ROW 1 ──────────────────────────────────────────────
st.markdown("<div class='section-header'>📈 Threat Overview</div>", unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

c1, c2 = st.columns(2)
with c1:
    st.plotly_chart(severity_donut(df_filtered),  use_container_width=True)
with c2:
    st.plotly_chart(daily_trend(df_filtered),     use_container_width=True)

# ── CHARTS ROW 2 ──────────────────────────────────────────────
c3, c4 = st.columns(2)
with c3:
    st.plotly_chart(category_bar(df_filtered),    use_container_width=True)
with c4:
    st.plotly_chart(score_histogram(df_filtered), use_container_width=True)

# ── CHART ROW 3 ───────────────────────────────────────────────
st.plotly_chart(severity_over_time(df_filtered),  use_container_width=True)

st.divider()

# ── RAW DATA ──────────────────────────────────────────────────
st.markdown("<div class='section-header'>📋 CVE Intelligence Feed</div>", unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

search = st.text_input("🔎 Search CVEs", placeholder="Search by ID, keyword, category...")
df_display = df_filtered.copy()
if search:
    mask = (
        df_display['CVE_ID'].str.contains(search, case=False, na=False) |
        df_display['Description'].str.contains(search, case=False, na=False) |
        df_display['Category'].str.contains(search, case=False, na=False)
    )
    df_display = df_display[mask]

st.dataframe(
    df_display[['CVE_ID','Published','Severity','Score','Category','Description']],
    use_container_width=True,
    height=400
)

st.caption(f"Showing {len(df_display)} of {len(df_filtered)} records")

st.divider()

# ── ML PREDICTOR ──────────────────────────────────────────────
st.markdown("<div class='section-header'>🤖 ML Severity Predictor</div>", unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

st.markdown("""
<div style="
    background: linear-gradient(135deg, #161b22, #1c2333);
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1rem;
">
    <p style="color: #8b949e; margin: 0; font-size: 14px;">
         Enter any vulnerability description below and our ML model will predict
        its severity level and threat category in real time.
    </p>
</div>
""", unsafe_allow_html=True)

user_input = st.text_area(
    "Vulnerability Description",
    placeholder="e.g. Buffer overflow in OpenSSL allows remote attackers to execute arbitrary code via crafted packets...",
    height=120
)

if st.button("🔍 Analyse Threat"):
    if user_input:
        with st.spinner("Analysing threat..."):
            prediction = predict_severity(model, vectorizer, user_input)
            category   = get_threat_category(user_input)

        r1, r2, r3 = st.columns(3)
        with r1:
            color = {
                'CRITICAL':"#ef2016",'HIGH':"#ee8a18",
                'MEDIUM':"#f6e710",'LOW':'#3fb950'
            }.get(prediction, "#526274")
            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, #161b22, #1c2333);
                border: 1px solid {color};
                border-radius: 12px;
                padding: 1.2rem;
                text-align: center;
            ">
                <div style="color: #8b949e; font-size: 12px; margin-bottom: 4px;">PREDICTED SEVERITY</div>
                <div style="color: {color}; font-size: 22px; font-weight: 700;">{prediction}</div>
            </div>
            """, unsafe_allow_html=True)
        with r2:
            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, #161b22, #1c2333);
                border: 1px solid #21262d;
                border-radius: 12px;
                padding: 1.2rem;
                text-align: center;
            ">
                <div style="color: #8b949e; font-size: 12px; margin-bottom: 4px;">THREAT CATEGORY</div>
                <div style="color: #58a6ff; font-size: 22px; font-weight: 700;">{category}</div>
            </div>
            """, unsafe_allow_html=True)
        with r3:
            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, #161b22, #1c2333);
                border: 1px solid #21262d;
                border-radius: 12px;
                padding: 1.2rem;
                text-align: center;
            ">
                <div style="color: #8b949e; font-size: 12px; margin-bottom: 4px;">RISK ACTION</div>
                <div style="color: #3fb950; font-size: 16px; font-weight: 600;">
                    {"🚨 Patch Immediately" if prediction == "CRITICAL"
                     else "⚠️ Patch Soon" if prediction == "HIGH"
                     else "📋 Schedule Patch" if prediction == "MEDIUM"
                     else "📝 Monitor"}
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.warning("Please enter a vulnerability description first.")

# ── FOOTER ────────────────────────────────────────────────────
st.markdown("""
<div style="
    margin-top: 3rem;
    padding: 1.5rem;
    border-top: 1px solid #21262d;
    text-align: center;
    color: #8b949e;
    font-size: 13px;
">
    ⛉ CyberPulse · Built with Python, Streamlit & Scikit-learn
    &nbsp;·&nbsp; Data from NVD CVE API
    &nbsp;·&nbsp; Made by <strong style="color: #58a6ff;">Your Name</strong>
</div>
""", unsafe_allow_html=True)