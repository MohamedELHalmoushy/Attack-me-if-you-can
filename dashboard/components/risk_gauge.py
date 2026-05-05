import plotly.graph_objects as go
import streamlit as st


LEVEL_COLORS = {
    "CRITICAL": "#E24B4A",
    "HIGH":     "#EF9F27",
    "MEDIUM":   "#F9CB42",
    "LOW":      "#1D9E75",
}


def render_risk_gauge(score: float, level: str):
    """
    Render a circular gauge for the current risk score.

    Args:
        score: float in [0.0, 1.0]
        level: one of CRITICAL / HIGH / MEDIUM / LOW
    """
    color = LEVEL_COLORS.get(level, "#888")

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=round(score * 100, 1),
        number={"suffix": "%", "font": {"size": 32}},
        delta={"reference": 40, "increasing": {"color": "#E24B4A"}, "decreasing": {"color": "#1D9E75"}},
        gauge={
            "axis": {
                "range": [0, 100],
                "tickwidth": 1,
                "tickcolor": "#444",
                "tickvals": [0, 40, 65, 85, 100],
                "ticktext": ["0", "LOW", "HIGH", "CRIT", "100"],
            },
            "bar":  {"color": color, "thickness": 0.3},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0,  40], "color": "rgba(29,158,117,0.15)"},
                {"range": [40, 65], "color": "rgba(249,203,66,0.15)"},
                {"range": [65, 85], "color": "rgba(239,159,39,0.15)"},
                {"range": [85,100], "color": "rgba(226,75,74,0.15)"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.8,
                "value": round(score * 100, 1),
            },
        },
        title={"text": f"<b>{level}</b>", "font": {"size": 18, "color": color}},
    ))

    fig.update_layout(
        height=260,
        margin=dict(l=20, r=20, t=40, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": "#ccc"},
    )

    st.plotly_chart(fig, use_container_width=True)
