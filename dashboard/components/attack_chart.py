"""
dashboard/components/attack_chart.py — Attack timeline chart

Renders a Plotly line chart of risk scores over time,
with color-coded markers for each risk level.
"""

import plotly.graph_objects as go
import streamlit as st


LEVEL_COLORS = {
    "CRITICAL": "#E24B4A",
    "HIGH":     "#EF9F27",
    "MEDIUM":   "#F9CB42",
    "LOW":      "#1D9E75",
}


def render_attack_chart(events: list):
    """
    Render an attack timeline chart.

    Args:
        events: list of event dicts with keys: time, score, level, scenario
    """
    if not events:
        st.info("No events recorded yet. Run a test or enable simulation.")
        return

    times   = [e["time"]  for e in events]
    scores  = [e["score"] for e in events]
    levels  = [e["level"] for e in events]
    labels  = [e.get("scenario", "") for e in events]
    colors  = [LEVEL_COLORS.get(lvl, "#888") for lvl in levels]

    fig = go.Figure()

    # Background zone bands
    for y0, y1, color, name in [
        (0.00, 0.40, "rgba(29,158,117,0.06)",  "LOW"),
        (0.40, 0.65, "rgba(249,203,66,0.06)",  "MEDIUM"),
        (0.65, 0.85, "rgba(239,159,39,0.06)",  "HIGH"),
        (0.85, 1.00, "rgba(226,75,74,0.06)",   "CRITICAL"),
    ]:
        fig.add_hrect(y0=y0, y1=y1, fillcolor=color, line_width=0, annotation_text=name,
                      annotation_position="right", annotation_font_size=10,
                      annotation_font_color="#666")

    # Line
    fig.add_trace(go.Scatter(
        x=times,
        y=scores,
        mode="lines+markers",
        line=dict(color="#378ADD", width=2),
        marker=dict(color=colors, size=10, line=dict(width=1, color="#111")),
        text=[f"{l}: {s:.3f} — {n}" for l, s, n in zip(levels, scores, labels)],
        hovertemplate="%{text}<extra></extra>",
        name="Risk Score",
    ))

    # Threshold lines
    for y, color, label in [
        (0.85, "#E24B4A", "CRITICAL"),
        (0.65, "#EF9F27", "HIGH"),
        (0.40, "#F9CB42", "MEDIUM"),
    ]:
        fig.add_hline(y=y, line_dash="dash", line_color=color, line_width=1,
                      annotation_text=label, annotation_position="left",
                      annotation_font_color=color, annotation_font_size=10)

    fig.update_layout(
        height=320,
        xaxis_title="Time",
        yaxis_title="Risk Score",
        yaxis=dict(range=[0, 1.05], gridcolor="#222"),
        xaxis=dict(gridcolor="#222", tickangle=-30),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#ccc"),
        margin=dict(l=10, r=80, t=20, b=40),
        showlegend=False,
    )

    st.plotly_chart(fig, use_container_width=True)
