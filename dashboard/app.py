
import time
import random
import sys
import os
from datetime import datetime

import streamlit as st

# Allow imports from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.risk_fusion import RiskFusionEngine
from core.response_agent import ResponseAgent
from dashboard.components.risk_gauge import render_risk_gauge
from dashboard.components.alert_table import render_alert_table
from dashboard.components.attack_chart import render_attack_chart

# ── Page config

st.set_page_config(
    page_title="Attack Me If You Can",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS

st.markdown("""
<style>
    .stMetric { background: #0e1117; border: 1px solid #262730; border-radius: 8px; padding: 16px; }
    .risk-critical { color: #E24B4A; font-weight: 700; }
    .risk-high     { color: #EF9F27; font-weight: 700; }
    .risk-medium   { color: #F9CB42; font-weight: 700; }
    .risk-low      { color: #1D9E75; font-weight: 700; }
    h1 { font-size: 1.6rem !important; }
</style>
""", unsafe_allow_html=True)

# Sidebar

with st.sidebar:
    st.title("⚙️ Settings")

    st.subheader("Simulation Mode")
    sim_mode = st.toggle("Live Simulation", value=False)
    refresh_rate = st.slider("Refresh Rate (seconds)", 1, 10, 3)

    st.subheader("Manual Test")
    ids_manual     = st.slider("IDS Score",     0.0, 1.0, 0.5, 0.01)
    anomaly_manual = st.slider("Anomaly Score", 0.0, 1.0, 0.5, 0.01)
    log_manual     = st.slider("Log Score",     0.0, 1.0, 0.5, 0.01)
    run_manual     = st.button("▶ Run Manual Test")

    st.subheader("Demo Attacks")
    col1, col2 = st.columns(2)
    with col1:
        btn_ddos    = st.button("DDoS")
        btn_bruteforce = st.button("Brute Force")
    with col2:
        btn_sqli    = st.button("SQL Injection")
        btn_normal  = st.button("Normal")

    st.divider()
    st.caption("Developed by TopIQ")

# Session state 

if "events" not in st.session_state:
    st.session_state.events = []

if "total_blocked" not in st.session_state:
    st.session_state.total_blocked = 0

if "total_alerts" not in st.session_state:
    st.session_state.total_alerts = 0

# Header

st.title("🛡️ Attck me if you can — Halmoushy")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Fusion engine & response agent

engine   = RiskFusionEngine()
responder = ResponseAgent()

#  Determine current sample 

DEMO_SCENARIOS = {
    "ddos":       (0.95, 0.92, 0.90, "DDoS"),
    "bruteforce": (0.85, 0.60, 0.75, "Brute Force"),
    "sqli":       (0.78, 0.50, 0.82, "SQL Injection"),
    "normal":     (0.05, 0.08, 0.10, "Normal Traffic"),
}

ids_score, anomaly_score, log_score = ids_manual, anomaly_manual, log_manual
scenario_name = "Manual"

if btn_ddos:        ids_score, anomaly_score, log_score, scenario_name = DEMO_SCENARIOS["ddos"]
elif btn_bruteforce:ids_score, anomaly_score, log_score, scenario_name = DEMO_SCENARIOS["bruteforce"]
elif btn_sqli:      ids_score, anomaly_score, log_score, scenario_name = DEMO_SCENARIOS["sqli"]
elif btn_normal:    ids_score, anomaly_score, log_score, scenario_name = DEMO_SCENARIOS["normal"]
elif sim_mode:
    ids_score     = round(random.uniform(0.0, 1.0), 3)
    anomaly_score = round(random.uniform(0.0, 1.0), 3)
    log_score     = round(random.uniform(0.0, 1.0), 3)
    scenario_name = "Simulated"

# Run fusion

result = engine.fuse_detailed(ids_score, anomaly_score, log_score)
action = responder.ACTIONS[result.risk_level]

# Record event
event = {
    "time":         datetime.now().strftime("%H:%M:%S"),
    "scenario":     scenario_name,
    "ids":          result.ids_score,
    "anomaly":      result.anomaly_score,
    "log":          result.log_score,
    "score":        result.final_score,
    "level":        result.risk_level,
    "action":       action,
    "rule":         result.rule_triggered,
}
st.session_state.events.append(event)
if len(st.session_state.events) > 100:
    st.session_state.events = st.session_state.events[-100:]

if action == "BLOCK_IP":     st.session_state.total_blocked += 1
if action == "SEND_ALERT":   st.session_state.total_alerts  += 1

# Top metrics row 
m1, m2, m3, m4, m5 = st.columns(5)

level_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
icon = level_colors.get(result.risk_level, "⚪")

m1.metric("Risk Level",     f"{icon} {result.risk_level}")
m2.metric("Final Score",    f"{result.final_score:.3f}")
m3.metric("Action",         action)
m4.metric("Total Blocked",  st.session_state.total_blocked)
m5.metric("Total Alerts",   st.session_state.total_alerts)

st.divider()

# Main content

col_gauge, col_chart = st.columns([1, 2])

with col_gauge:
    st.subheader("Risk Score")
    render_risk_gauge(result.final_score, result.risk_level)

    st.subheader("Agent Scores")
    st.progress(result.ids_score,     text=f"IDS Agent:     {result.ids_score:.3f}")
    st.progress(result.anomaly_score, text=f"Anomaly Agent: {result.anomaly_score:.3f}")
    st.progress(result.log_score,     text=f"Log Agent:     {result.log_score:.3f}")

    if result.rule_triggered != "none":
        st.info(f"⚡ Smart Rule: {result.rule_triggered}")

    st.subheader("Fusion Explanation")
    st.code(engine.explain(ids_score, anomaly_score, log_score))

with col_chart:
    st.subheader("Attack Events Timeline")
    render_attack_chart(st.session_state.events)

st.divider()

#  Recent alerts table

st.subheader("Recent Decisions")
render_alert_table(st.session_state.events[-20:])

#  Auto-refresh in simulation mode 

if sim_mode:
    time.sleep(refresh_rate)
    st.rerun()
