import pandas as pd
import streamlit as st


LEVEL_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

ACTION_ICONS = {
    "BLOCK_IP":   "🚫",
    "SEND_ALERT": "📧",
    "MONITOR":    "👁️",
    "LOG_ONLY":   "📝",
}


def render_alert_table(events: list):
    """
    Render a table of recent threat decisions.

    Args:
        events: list of event dicts (newest first)
    """
    if not events:
        st.info("No decisions recorded yet.")
        return

    rows = []
    for e in reversed(events):   # newest first
        level  = e.get("level", "LOW")
        action = e.get("action", "LOG_ONLY")
        rows.append({
            "Time":     e.get("time", ""),
            "Scenario": e.get("scenario", "—"),
            "Level":    f"{LEVEL_ICONS.get(level, '')} {level}",
            "Score":    f"{e.get('score', 0):.3f}",
            "IDS":      f"{e.get('ids', 0):.3f}",
            "Anomaly":  f"{e.get('anomaly', 0):.3f}",
            "Log":      f"{e.get('log', 0):.3f}",
            "Action":   f"{ACTION_ICONS.get(action, '')} {action}",
            "Rule":     e.get("rule", "none") if e.get("rule", "none") != "none" else "—",
        })

    df = pd.DataFrame(rows)

    # Style: highlight rows by risk level
    def highlight_row(row):
        level_raw = row["Level"]
        if "CRITICAL" in level_raw: bg = "rgba(226,75,74,0.15)"
        elif "HIGH"   in level_raw: bg = "rgba(239,159,39,0.12)"
        elif "MEDIUM" in level_raw: bg = "rgba(249,203,66,0.10)"
        else:                        bg = "rgba(29,158,117,0.08)"
        return [f"background-color: {bg}"] * len(row)

    styled = df.style.apply(highlight_row, axis=1)

    st.dataframe(
        styled,
        use_container_width=True,
        hide_index=True,
        height=min(400, 40 + len(rows) * 36),
    )
